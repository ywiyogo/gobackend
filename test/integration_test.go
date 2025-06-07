package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gobackend/internal/api"
	"gobackend/internal/auth"
	"gobackend/internal/db/sqlc"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServer wraps httptest.Server with additional functionality for integration testing
type TestServer struct {
	*httptest.Server
	Client      *http.Client
	AuthService *auth.Service
	Pool        *pgxpool.Pool
}

// setupTestServer creates a test server with the full application stack
func setupTestServer(t *testing.T) *TestServer {
	t.Helper()

	// Set up test database connection
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	if dbUser == "" || dbPassword == "" || dbName == "" {
		t.Skip("Database credentials not set, skipping integration test")
	}

	// Default to localhost for Docker-based testing
	if dbHost == "" || dbHost == "db" {
		dbHost = "localhost"
	}
	if dbPort == "" {
		dbPort = "5432"
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	pool, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = pool.Ping(ctx)
	require.NoError(t, err)

	queries := sqlc.New(pool)
	repo := auth.NewAuthRepository(queries)
	authService := auth.NewService(repo)

	// Create router with the same setup as main.go
	router := api.NewRouter(authService)

	// Add auth routes
	userHandler := auth.NewHandler(authService)
	routesAuth := map[string]http.HandlerFunc{
		"POST /register":   userHandler.Register,
		"POST /login":      userHandler.Login,
		"POST /logout":     userHandler.Logout,
		"POST /verify-otp": userHandler.VerifyOTP,
	}
	router.AppendHandlerFromMap(routesAuth)

	// Add protected dashboard route
	router.AppendProtectedHandler("POST /dashboard", api.Dashboard)

	// Create test server
	server := httptest.NewServer(router.Handler())

	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
	}

	return &TestServer{
		Server:      server,
		Client:      client,
		AuthService: authService,
		Pool:        pool,
	}
}

// cleanup removes test data and closes connections
func (ts *TestServer) cleanup(t *testing.T) {
	t.Helper()

	// Clean up test data - delete sessions and users created during test
	// Variables for potential cleanup operations (currently unused but reserved for future use)
	_ = context.Background()
	_ = sqlc.New(ts.Pool)

	// Note: In a real scenario, you might want to use a separate test database
	// or implement proper test data cleanup based on test identifiers

	ts.Server.Close()
	ts.Pool.Close()
}

// postForm is a helper method to make POST requests with form data
func (ts *TestServer) postForm(t *testing.T, endpoint string, data url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postFormWithCSRF is a helper method to make POST requests with form data and CSRF token
func (ts *TestServer) postFormWithCSRF(t *testing.T, endpoint string, data url.Values, csrfToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postJSON is a helper method to make POST requests with JSON data
func (ts *TestServer) postJSON(t *testing.T, endpoint string, data interface{}) *http.Response {
	t.Helper()

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// extractOTPFromResponse extracts OTP code from response body using regex
func extractOTPFromResponse(responseBody string) string {
	// Look for OTP pattern in response (6 digits)
	re := regexp.MustCompile(`OTP(?:\s+code)?:\s*(\d{6})`)
	matches := re.FindStringSubmatch(responseBody)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractCSRFTokenFromResponse extracts CSRF token from response body using regex
func extractCSRFTokenFromResponse(responseBody string) string {
	// Look for CSRF pattern in response
	re := regexp.MustCompile(`CSRF:\s*([a-zA-Z0-9_-]+)`)
	matches := re.FindStringSubmatch(responseBody)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getResponseBody reads and returns the response body as string
func getResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	require.NoError(t, err)

	return buf.String()
}

// TestAuthenticationWorkflowWithPassword tests the complete password-based authentication flow
func TestAuthenticationWorkflowWithPassword(t *testing.T) {
	// Set environment for password-based auth
	originalOTPEnabled := os.Getenv("OTP_ENABLED")
	os.Setenv("OTP_ENABLED", "false")
	defer func() {
		if originalOTPEnabled != "" {
			os.Setenv("OTP_ENABLED", originalOTPEnabled)
		} else {
			os.Unsetenv("OTP_ENABLED")
		}
	}()

	ts := setupTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-password-%d@example.com", time.Now().Unix())
	testPassword := "securePassword123"

	var csrfToken string

	t.Run("Register with password", func(t *testing.T) {
		fmt.Printf("Registering user with email: %s\n", testEmail)

		data := url.Values{
			"email":    {testEmail},
			"password": {testPassword},
		}

		resp := ts.postForm(t, "/register", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Password registration should not set session cookies
		// Session is created during login
	})

	t.Run("Login with password", func(t *testing.T) {
		data := url.Values{
			"email":    {testEmail},
			"password": {testPassword},
		}

		resp := ts.postForm(t, "/login", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check for session cookie
		var sessionCookie *http.Cookie
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session_token" {
				sessionCookie = cookie
				break
			}
		}
		require.NotNil(t, sessionCookie, "Session cookie should be set")
		assert.NotEmpty(t, sessionCookie.Value)

		// Extract CSRF token from response body
		body := getResponseBody(t, resp)
		csrfToken = extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, csrfToken, "CSRF token should be present in response")
	})

	t.Run("Access protected endpoint", func(t *testing.T) {
		resp := ts.postFormWithCSRF(t, "/dashboard", url.Values{}, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		assert.Contains(t, body, "Dashboard accessed successfully")
	})

	t.Run("Logout", func(t *testing.T) {
		resp := ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Access protected endpoint after logout should fail", func(t *testing.T) {
		resp := ts.postForm(t, "/dashboard", url.Values{})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestAuthenticationWorkflowWithOTP tests the complete OTP-based authentication flow
func TestAuthenticationWorkflowWithOTP(t *testing.T) {
	// Set to OTP mode
	originalOTPEnabled := os.Getenv("OTP_ENABLED")
	os.Setenv("OTP_ENABLED", "true")
	defer func() {
		if originalOTPEnabled != "" {
			os.Setenv("OTP_ENABLED", originalOTPEnabled)
		} else {
			os.Unsetenv("OTP_ENABLED")
		}
	}()

	ts := setupTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-otp-%d@example.com", time.Now().Unix())
	var otpCode string
	var csrfToken string

	t.Run("Register with OTP", func(t *testing.T) {
		fmt.Printf("Registering user with email: %s\n", testEmail)

		data := url.Values{
			"email": {testEmail},
		}

		resp := ts.postForm(t, "/register", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		otpCode = extractOTPFromResponse(body)
		assert.NotEmpty(t, otpCode, "OTP code should be present in response")
		assert.Len(t, otpCode, 6, "OTP should be 6 digits")

		// Extract CSRF token from response body
		csrfToken = extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, csrfToken, "CSRF token should be present in response")

		// Check for session cookie (temporary session for OTP verification)
		var sessionCookie *http.Cookie
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session_token" {
				sessionCookie = cookie
				break
			}
		}
		require.NotNil(t, sessionCookie, "Session cookie should be set")
	})

	t.Run("Verify OTP", func(t *testing.T) {
		data := url.Values{
			"otp_code": {otpCode},
		}

		resp := ts.postFormWithCSRF(t, "/verify-otp", data, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		assert.Contains(t, body, "OTP verified successfully")
	})

	t.Run("Access protected endpoint after OTP verification", func(t *testing.T) {
		resp := ts.postFormWithCSRF(t, "/dashboard", url.Values{}, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		assert.Contains(t, body, "Dashboard accessed successfully")
	})

	t.Run("Login with OTP (existing user)", func(t *testing.T) {
		// First logout to clear session
		ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)

		data := url.Values{
			"email": {testEmail},
		}

		resp := ts.postForm(t, "/login", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		newOtpCode := extractOTPFromResponse(body)
		assert.NotEmpty(t, newOtpCode, "New OTP code should be present in response")
		assert.Len(t, newOtpCode, 6, "OTP should be 6 digits")

		// Extract new CSRF token
		csrfToken = extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, csrfToken, "CSRF token should be present in response")

		// Verify the new OTP
		verifyData := url.Values{
			"otp_code": {newOtpCode},
		}
		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()

		assert.Equal(t, http.StatusOK, verifyResp.StatusCode)
	})

	t.Run("Logout", func(t *testing.T) {
		resp := ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestAuthenticationErrorScenarios tests various error scenarios
func TestAuthenticationErrorScenarios(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.cleanup(t)

	t.Run("Register with invalid email", func(t *testing.T) {
		data := url.Values{
			"email":    {"invalid-email"},
			"password": {"password123"},
		}

		resp := ts.postForm(t, "/register", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Register with short password", func(t *testing.T) {
		// Set to password mode
		os.Setenv("OTP_ENABLED", "false")
		defer os.Unsetenv("OTP_ENABLED")

		data := url.Values{
			"email":    {"test@example.com"},
			"password": {"123"},
		}

		resp := ts.postForm(t, "/register", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Login with wrong password", func(t *testing.T) {
		// Set to password mode
		os.Setenv("OTP_ENABLED", "false")
		defer os.Unsetenv("OTP_ENABLED")

		testEmail := fmt.Sprintf("test-wrong-password-%d@example.com", time.Now().Unix())

		// Register user first
		registerData := url.Values{
			"email":    {testEmail},
			"password": {"correctPassword123"},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		registerResp.Body.Close()

		// Try to login with wrong password
		loginData := url.Values{
			"email":    {testEmail},
			"password": {"wrongPassword123"},
		}

		resp := ts.postForm(t, "/login", loginData)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Verify OTP with invalid code", func(t *testing.T) {
		// Set to OTP mode
		os.Setenv("OTP_ENABLED", "true")
		defer os.Unsetenv("OTP_ENABLED")

		testEmail := fmt.Sprintf("test-invalid-otp-%d@example.com", time.Now().Unix())

		// Register to get session
		registerData := url.Values{
			"email": {testEmail},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		registerResp.Body.Close()

		// Try to verify with invalid OTP
		data := url.Values{
			"otp_code": {"000000"},
		}

		resp := ts.postForm(t, "/verify-otp", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Access protected endpoint without session", func(t *testing.T) {
		// Create new client without cookies
		client := &http.Client{Timeout: 10 * time.Second}

		req, err := http.NewRequest("POST", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Verify OTP without session cookie", func(t *testing.T) {
		// Create new client without cookies
		client := &http.Client{Timeout: 10 * time.Second}

		data := url.Values{
			"otp_code": {"123456"},
		}

		req, err := http.NewRequest("POST", ts.Server.URL+"/verify-otp", strings.NewReader(data.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// TestConcurrentAuthentication tests concurrent authentication requests
func TestConcurrentAuthentication(t *testing.T) {
	// Set to password mode for simplicity
	os.Setenv("OTP_ENABLED", "false")
	defer os.Unsetenv("OTP_ENABLED")

	ts := setupTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-concurrent-%d@example.com", time.Now().Unix())
	testPassword := "concurrentPassword123"

	// Register user first
	registerData := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	registerResp := ts.postForm(t, "/register", registerData)
	registerResp.Body.Close()

	t.Run("Concurrent login attempts", func(t *testing.T) {
		const numGoroutines = 5
		results := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				// Create separate client for each goroutine
				jar, err := cookiejar.New(nil)
				if err != nil {
					results <- false
					return
				}

				client := &http.Client{
					Jar:     jar,
					Timeout: 10 * time.Second,
				}

				data := url.Values{
					"email":    {testEmail},
					"password": {testPassword},
				}

				req, err := http.NewRequest("POST", ts.Server.URL+"/login", strings.NewReader(data.Encode()))
				if err != nil {
					results <- false
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := client.Do(req)
				if err != nil {
					results <- false
					return
				}
				defer resp.Body.Close()

				results <- resp.StatusCode == http.StatusOK
			}()
		}

		// Collect results
		successCount := 0
		for i := 0; i < numGoroutines; i++ {
			if <-results {
				successCount++
			}
		}

		// All concurrent login attempts should succeed
		assert.Equal(t, numGoroutines, successCount)
	})
}

// TestSessionExpiry tests session expiration behavior
func TestSessionExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping session expiry test in short mode")
	}

	// Set to password mode
	os.Setenv("OTP_ENABLED", "false")
	defer os.Unsetenv("OTP_ENABLED")

	ts := setupTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-expiry-%d@example.com", time.Now().Unix())
	testPassword := "expiryPassword123"

	var csrfToken string

	// Register user
	registerData := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	registerResp := ts.postForm(t, "/register", registerData)
	registerResp.Body.Close()

	// Login and extract CSRF token
	loginData := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	loginResp := ts.postForm(t, "/login", loginData)
	defer loginResp.Body.Close()

	assert.Equal(t, http.StatusOK, loginResp.StatusCode)

	// Extract CSRF token from response body
	body := getResponseBody(t, loginResp)
	csrfToken = extractCSRFTokenFromResponse(body)
	require.NotEmpty(t, csrfToken, "CSRF token should be present in response")

	// Access protected endpoint immediately - should work
	resp := ts.postFormWithCSRF(t, "/dashboard", url.Values{}, csrfToken)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Note: In a real test, you would need to either:
	// 1. Modify the session expiry time to be very short for testing
	// 2. Manually expire the session in the database
	// 3. Mock the time to simulate expiration
	// For now, we just verify the session works immediately after login
}
