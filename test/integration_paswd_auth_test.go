package test

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

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
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		assert.Contains(t, body, "Dashboard data retrieved successfully")
	})

	t.Run("Logout", func(t *testing.T) {
		resp := ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Access protected endpoint after logout should fail", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestAuthenticationErrorScenarios tests various error scenarios in authentication
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
		data := url.Values{
			"email":    {"test@example.com"},
			"password": {"123"},
		}

		resp := ts.postForm(t, "/register", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Login with wrong password", func(t *testing.T) {
		// First register a user
		email := fmt.Sprintf("test-wrong-password-%d@example.com", time.Now().Unix())
		registerData := url.Values{
			"email":    {email},
			"password": {"correctPassword123"},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		defer registerResp.Body.Close()

		// Try to login with wrong password
		loginData := url.Values{
			"email":    {email},
			"password": {"wrongPassword"},
		}
		loginResp := ts.postForm(t, "/login", loginData)
		defer loginResp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, loginResp.StatusCode)
	})

	t.Run("Login with non-existent user", func(t *testing.T) {
		// Try to login with user that doesn't exist
		data := url.Values{
			"email":    {"nonexistent@example.com"},
			"password": {"password123"},
		}
		resp := ts.postForm(t, "/login", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Access protected endpoint without session", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Verify OTP without session cookie", func(t *testing.T) {
		// Create a new client without cookies
		newClient := &http.Client{}

		req, err := http.NewRequest("POST", ts.Server.URL+"/verify-otp", nil)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

		resp, err := newClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestConcurrentAuthentication tests concurrent login attempts
func TestConcurrentAuthentication(t *testing.T) {
	// Set to password mode for simplicity
	os.Setenv("OTP_ENABLED", "false")
	defer os.Unsetenv("OTP_ENABLED")

	ts := setupTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-concurrent-%d@example.com", time.Now().Unix())
	testPassword := "concurrentPassword123"

	// Register the user first
	data := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	registerResp := ts.postForm(t, "/register", data)
	defer registerResp.Body.Close()
	assert.Equal(t, http.StatusCreated, registerResp.StatusCode)

	t.Run("Concurrent login attempts", func(t *testing.T) {
		const numGoroutines = 5
		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				loginData := url.Values{
					"email":    {testEmail},
					"password": {testPassword},
				}

				resp := ts.postForm(t, "/login", loginData)
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		// All attempts should succeed (each gets their own session)
		assert.Equal(t, numGoroutines, successCount)
	})
}

// TestSessionExpiry tests session expiration functionality
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

	// Register user
	registerData := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	registerResp := ts.postForm(t, "/register", registerData)
	defer registerResp.Body.Close()

	// Login
	loginData := url.Values{
		"email":    {testEmail},
		"password": {testPassword},
	}
	loginResp := ts.postForm(t, "/login", loginData)
	defer loginResp.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp.StatusCode)

	// Extract CSRF token from response body
	body := getResponseBody(t, loginResp)
	csrfToken := extractCSRFTokenFromResponse(body)
	require.NotEmpty(t, csrfToken, "CSRF token should be present in response")

	// Test immediate access works
	req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))
	req.Header.Set("X-CSRF-Token", csrfToken)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// For a full session expiry test, you would need to either:
	// 1. Wait for the actual session timeout (not practical in tests)
	// 2. Mock the time or session expiry logic
	// 3. Create a session with a very short expiry time
	// For now, we just verify that the session works immediately after creation
}
