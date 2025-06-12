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
	"strings"
	"testing"
	"time"

	"gobackend/internal/api"
	"gobackend/internal/auth"
	"gobackend/internal/db/sqlc"
	"gobackend/internal/tenant"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestServer wraps httptest.Server with additional functionality for integration testing
type TestServer struct {
	*httptest.Server
	Client        *http.Client
	AuthService   *auth.Service
	TenantService *tenant.Service
	Pool          *pgxpool.Pool
	DefaultTenant *sqlc.Tenant
}

// setupTestServer creates a test server with the full application stack
func setupTestServer(t *testing.T) *TestServer {
	return setupTestServerWithOTP(t, false)
}

// setupTestServerWithOTP creates a test server with OTP enabled/disabled
func setupTestServerWithOTP(t *testing.T, otpEnabled bool) *TestServer {
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

	// Initialize tenant service
	tenantService := tenant.NewService(queries)

	// Create router with the same setup as main.go
	router := api.NewRouter(authService)

	// Add auth routes with tenant middleware
	userHandler := auth.NewHandler(authService, tenantService)

	// Create tenant middleware
	tenantMiddleware := tenant.TenantMiddleware(tenantService)

	// Wrap handlers with tenant middleware
	routesAuth := map[string]http.HandlerFunc{
		"POST /register": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Register)).ServeHTTP(w, r)
		},
		"POST /login": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Login)).ServeHTTP(w, r)
		},
		"POST /logout": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Logout)).ServeHTTP(w, r)
		},
		"POST /verify-otp": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.VerifyOTP)).ServeHTTP(w, r)
		},
	}
	router.AppendHandlerFromMap(routesAuth)

	// Add protected dashboard route with tenant middleware
	dashboardWithTenant := func(w http.ResponseWriter, r *http.Request) {
		tenantMiddleware(http.HandlerFunc(userHandler.Dashboard)).ServeHTTP(w, r)
	}
	router.AppendProtectedHandler("GET /dashboard", dashboardWithTenant)

	// Create test server
	server := httptest.NewServer(router.Handler())

	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
	}

	// Create a default test tenant for basic operations
	defaultTenant := &TestServer{
		Server:        server,
		Client:        client,
		AuthService:   authService,
		TenantService: tenantService,
		Pool:          pool,
	}

	// Setup default tenant for tests that don't specify one
	// Use nanoseconds and random number to ensure unique domain per test
	defaultDomain := fmt.Sprintf("default-%d-%d.test.com", time.Now().UnixNano(), time.Now().Nanosecond()%1000)

	settings := &tenant.TenantSettings{
		OTPEnabled:               otpEnabled,
		SessionTimeoutMinutes:    1440, // 24 hours
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       100,
		RequireEmailVerification: false,
		CustomBranding:           make(map[string]string),
	}

	req := &tenant.CreateTenantRequest{
		Name:     "Default Test Tenant",
		Domain:   defaultDomain,
		Settings: settings,
	}

	testTenant, err := tenantService.CreateTenantAdmin(context.Background(), req)
	require.NoError(t, err)

	defaultTenant.DefaultTenant = testTenant

	return defaultTenant
}

// setupOTPTestServer creates a test server with OTP enabled
func setupOTPTestServer(t *testing.T) *TestServer {
	return setupTestServerWithOTP(t, true)
}

// setupPasswordTestServer creates a test server with OTP disabled
func setupPasswordTestServer(t *testing.T) *TestServer {
	return setupTestServerWithOTP(t, false)
}

// cleanup removes test data and closes connections
func (ts *TestServer) cleanup(t *testing.T) {
	t.Helper()
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.Pool != nil {
		ts.Pool.Close()
	}
}

// setupTestTenant creates a test tenant with the given domain using the server's default OTP setting
func (ts *TestServer) setupTestTenant(t *testing.T, domain string) *sqlc.Tenant {
	// Get the default tenant's settings
	settings, err := ts.TenantService.GetTenantSettings(ts.DefaultTenant)
	require.NoError(t, err)
	return ts.setupTestTenantWithOTP(t, domain, settings.OTPEnabled)
}

// setupTestTenantWithOTP creates a test tenant with the given domain and OTP setting
func (ts *TestServer) setupTestTenantWithOTP(t *testing.T, domain string, otpEnabled bool) *sqlc.Tenant {
	t.Helper()

	settings := &tenant.TenantSettings{
		OTPEnabled:               otpEnabled,
		SessionTimeoutMinutes:    1440, // 24 hours
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       100,
		RequireEmailVerification: false,
		CustomBranding:           make(map[string]string),
	}

	req := &tenant.CreateTenantRequest{
		Name:     fmt.Sprintf("Test App %s", domain),
		Domain:   domain,
		Settings: settings,
	}

	testTenant, err := ts.TenantService.CreateTenantAdmin(context.Background(), req)
	require.NoError(t, err)

	return testTenant
}

// postForm makes a POST request with form data using the default tenant
func (ts *TestServer) postForm(t *testing.T, endpoint string, data url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postFormWithCSRF makes a POST request with form data and CSRF token using the default tenant
func (ts *TestServer) postFormWithCSRF(t *testing.T, endpoint string, data url.Values, csrfToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postJSON makes a POST request with JSON data using the default tenant
func (ts *TestServer) postJSON(t *testing.T, endpoint string, data interface{}) *http.Response {
	t.Helper()

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", ts.Server.URL+endpoint, bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postFormWithOrigin makes a POST request with a specific Origin header
func (ts *TestServer) postFormWithOrigin(t *testing.T, path string, data url.Values, origin string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+path, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// getFormWithOrigin makes a GET request with a specific Origin header
func (ts *TestServer) getFormWithOrigin(t *testing.T, path string, origin string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("GET", ts.Server.URL+path, nil)
	require.NoError(t, err)

	req.Header.Set("Origin", origin)

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// getFormWithOriginAndCSRF makes a GET request with a specific Origin header and CSRF token
func (ts *TestServer) getFormWithOriginAndCSRF(t *testing.T, path string, origin string, csrfToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("GET", ts.Server.URL+path, nil)
	require.NoError(t, err)

	req.Header.Set("Origin", origin)
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// postFormWithOriginAndCSRF makes a POST request with a specific Origin header and CSRF token
func (ts *TestServer) postFormWithOriginAndCSRF(t *testing.T, path string, data url.Values, origin string, csrfToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest("POST", ts.Server.URL+path, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// extractOTPFromResponse extracts OTP code from response body
func extractOTPFromResponse(responseBody string) string {
	// Parse JSON response to extract OTP if present
	var response struct {
		OTP         string `json:"otp"`
		RequiresOTP bool   `json:"requires_otp"`
	}
	
	if err := json.Unmarshal([]byte(responseBody), &response); err == nil {
		// If OTP is explicitly in response, return it
		if response.OTP != "" {
			return response.OTP
		}
		
		// For testing purposes, return a predictable OTP only when requires_otp is true
		if response.RequiresOTP && (os.Getenv("ENV") == "test" || os.Getenv("ENV") == "development") {
			return "123456"
		}
	}
	
	return ""
}

// extractCSRFTokenFromResponse extracts CSRF token from JSON response body
func extractCSRFTokenFromResponse(responseBody string) string {
	var response struct {
		CSRFToken string `json:"csrf_token"`
	}

	// First try with lowercase csrf_token
	if err := json.Unmarshal([]byte(responseBody), &response); err == nil && response.CSRFToken != "" {
		return response.CSRFToken
	}

	// Try with capitalized CSRFToken
	var response2 struct {
		CSRFToken string `json:"CSRFToken"`
	}
	
	if err := json.Unmarshal([]byte(responseBody), &response2); err == nil && response2.CSRFToken != "" {
		return response2.CSRFToken
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