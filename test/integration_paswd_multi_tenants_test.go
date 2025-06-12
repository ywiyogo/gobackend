package test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"gobackend/internal/tenant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordTenantSettings tests that tenant-specific settings are respected for password-based authentication
func TestPasswordTenantSettings(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Create tenant with OTP disabled (password-based)
	passwordSettings := &tenant.TenantSettings{
		OTPEnabled:               false,
		SessionTimeoutMinutes:    1440,
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       100,
		RequireEmailVerification: false,
		CustomBranding:           make(map[string]string),
	}

	passwordTenantReq := &tenant.CreateTenantRequest{
		Name:     "Password Test App",
		Domain:   "password.test.com",
		Settings: passwordSettings,
	}

	passwordTenant, err := ts.TenantService.CreateTenantAdmin(context.Background(), passwordTenantReq)
	require.NoError(t, err)

	email := "settings@example.com"

	// Test password tenant - should require password
	t.Run("Password tenant requires password", func(t *testing.T) {
		data := url.Values{
			"email":    {email},
			"password": {"password123"},
		}

		resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", passwordTenant.Domain))
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Should not require OTP verification
		body := getResponseBody(t, resp)
		otpCode := extractOTPFromResponse(body)
		assert.Empty(t, otpCode, "OTP should not be generated for password-only tenant")
	})
}

// TestMultiTenantAuthentication tests that users can register with the same email on different tenants
func TestMultiTenantAuthentication(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup two test tenants
	tenant1 := ts.setupTestTenant(t, "app1.test.com")
	tenant2 := ts.setupTestTenant(t, "app2.test.com")

	email := "john@example.com"
	password := "password123"

	// Register same email on both tenants

	// Tenant 1 registration
	data1 := url.Values{
		"email":    {email},
		"password": {password},
	}
	resp1 := ts.postFormWithOrigin(t, "/register", data1, fmt.Sprintf("https://%s", tenant1.Domain))
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)

	// Tenant 2 registration (should succeed with same email)
	data2 := url.Values{
		"email":    {email},
		"password": {password},
	}
	resp2 := ts.postFormWithOrigin(t, "/register", data2, fmt.Sprintf("https://%s", tenant2.Domain))
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)

	// Login to tenant 1
	loginResp1 := ts.postFormWithOrigin(t, "/login", data1, fmt.Sprintf("https://%s", tenant1.Domain))
	defer loginResp1.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp1.StatusCode)

	// Try to access tenant 2 dashboard with tenant 1 session (should fail)
	dashboardResp := ts.getFormWithOrigin(t, "/dashboard", fmt.Sprintf("https://%s", tenant2.Domain))
	defer dashboardResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, dashboardResp.StatusCode)
}

// TestTenantIsolation tests that users and data are properly isolated between tenants
func TestTenantIsolation(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup two test tenants
	tenant1 := ts.setupTestTenant(t, "isolation1.test.com")
	tenant2 := ts.setupTestTenant(t, "isolation2.test.com")

	email := "isolation@example.com"
	password := "password123"

	// Register user on tenant 1
	data := url.Values{
		"email":    {email},
		"password": {password},
	}
	registerResp1 := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer registerResp1.Body.Close()
	assert.Equal(t, http.StatusCreated, registerResp1.StatusCode)

	// Try to login with same credentials on tenant 2 (should fail - user doesn't exist there)
	loginResp2 := ts.postFormWithOrigin(t, "/login", data, fmt.Sprintf("https://%s", tenant2.Domain))
	defer loginResp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, loginResp2.StatusCode)

	// Login on tenant 1 should work
	loginResp1 := ts.postFormWithOrigin(t, "/login", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer loginResp1.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp1.StatusCode)
}

// TestCrossTenantSessionSecurity tests that sessions are properly isolated between tenants
func TestCrossTenantSessionSecurity(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup two test tenants
	tenant1 := ts.setupTestTenant(t, "secure1.test.com")
	tenant2 := ts.setupTestTenant(t, "secure2.test.com")

	email := "security@example.com"
	password := "password123"

	// Register and login on tenant 1
	data := url.Values{
		"email":    {email},
		"password": {password},
	}

	// Register on tenant 1
	registerResp1 := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer registerResp1.Body.Close()
	assert.Equal(t, http.StatusCreated, registerResp1.StatusCode)

	// Login on tenant 1
	loginResp1 := ts.postFormWithOrigin(t, "/login", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer loginResp1.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp1.StatusCode)

	// Extract CSRF token from login response
	body1 := getResponseBody(t, loginResp1)
	csrfToken1 := extractCSRFTokenFromResponse(body1)
	require.NotEmpty(t, csrfToken1, "CSRF token should be present in login response")

	// Verify access to tenant 1 dashboard works with CSRF token
	dashboardResp1 := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer dashboardResp1.Body.Close()
	assert.Equal(t, http.StatusOK, dashboardResp1.StatusCode)

	// Register user with same email on tenant 2
	registerResp2 := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant2.Domain))
	defer registerResp2.Body.Close()
	assert.Equal(t, http.StatusCreated, registerResp2.StatusCode)

	// Try to access tenant 2 dashboard with tenant 1 session (should fail)
	dashboardResp2 := ts.getFormWithOrigin(t, "/dashboard", fmt.Sprintf("https://%s", tenant2.Domain))
	defer dashboardResp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, dashboardResp2.StatusCode)

	// Logout from tenant 1 with CSRF token
	logoutResp1 := ts.postFormWithOriginAndCSRF(t, "/logout", url.Values{}, fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer logoutResp1.Body.Close()
	assert.Equal(t, http.StatusOK, logoutResp1.StatusCode)

	// Verify tenant 1 dashboard access is now denied
	dashboardResp1After := ts.getFormWithOrigin(t, "/dashboard", fmt.Sprintf("https://%s", tenant1.Domain))
	defer dashboardResp1After.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, dashboardResp1After.StatusCode)
}

// TestMultiTenantDomainResolution tests that the correct tenant is resolved based on domain
func TestMultiTenantDomainResolution(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup tenants with different domains
	tenant1 := ts.setupTestTenant(t, "company1.example.com")
	tenant2 := ts.setupTestTenant(t, "company2.example.com")
	tenant3 := ts.setupTestTenant(t, "subdomain.company1.example.com")

	email := "user@test.com"
	password := "password123"

	testCases := []struct {
		name     string
		domain   string
		tenant   string
		expected int
	}{
		{
			name:     "Company 1 domain",
			domain:   tenant1.Domain,
			tenant:   tenant1.Name,
			expected: http.StatusCreated,
		},
		{
			name:     "Company 2 domain",
			domain:   tenant2.Domain,
			tenant:   tenant2.Name,
			expected: http.StatusCreated,
		},
		{
			name:     "Subdomain resolution",
			domain:   tenant3.Domain,
			tenant:   tenant3.Name,
			expected: http.StatusCreated,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := url.Values{
				"email":    {fmt.Sprintf("%s-%s", email, tc.domain)},
				"password": {password},
			}

			resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tc.domain))
			defer resp.Body.Close()
			assert.Equal(t, tc.expected, resp.StatusCode)
		})
	}
}

// TestMultiTenantConcurrentAccess tests concurrent access across multiple tenants
func TestMultiTenantConcurrentAccess(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup multiple tenants
	tenant1 := ts.setupTestTenant(t, "concurrent1.test.com")
	tenant2 := ts.setupTestTenant(t, "concurrent2.test.com")

	// Test that multiple users can access different tenants simultaneously
	t.Run("Concurrent registration on different tenants", func(t *testing.T) {
		done := make(chan bool, 2)

		// Register user on tenant 1
		go func() {
			defer func() { done <- true }()
			data := url.Values{
				"email":    {"user1@concurrent.com"},
				"password": {"password123"},
			}
			resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant1.Domain))
			defer resp.Body.Close()
			assert.Equal(t, http.StatusCreated, resp.StatusCode)
		}()

		// Register user on tenant 2
		go func() {
			defer func() { done <- true }()
			data := url.Values{
				"email":    {"user2@concurrent.com"},
				"password": {"password123"},
			}
			resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant2.Domain))
			defer resp.Body.Close()
			assert.Equal(t, http.StatusCreated, resp.StatusCode)
		}()

		// Wait for both operations to complete
		<-done
		<-done
	})
}

// TestMultiTenantPasswordComplexity tests password requirements per tenant
func TestMultiTenantPasswordComplexity(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	tenant := ts.setupTestTenant(t, "password-rules.test.com")

	testCases := []struct {
		name     string
		email    string
		password string
		expected int
	}{
		{
			name:     "Valid strong password",
			email:    "strong@test.com",
			password: "StrongP@ssw0rd123",
			expected: http.StatusCreated,
		},
		{
			name:     "Too short password",
			email:    "short@test.com",
			password: "123",
			expected: http.StatusBadRequest,
		},
		{
			name:     "Empty password",
			email:    "empty@test.com",
			password: "",
			expected: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := url.Values{
				"email":    {tc.email},
				"password": {tc.password},
			}

			resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant.Domain))
			defer resp.Body.Close()
			assert.Equal(t, tc.expected, resp.StatusCode)
		})
	}
}

// TestMultiTenantDataIsolation tests that user data is completely isolated between tenants
func TestMultiTenantDataIsolation(t *testing.T) {
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Setup two tenants
	tenant1 := ts.setupTestTenant(t, "data1.test.com")
	tenant2 := ts.setupTestTenant(t, "data2.test.com")

	email := "datatest@example.com"
	password := "password123"

	// Register same user on both tenants
	data := url.Values{
		"email":    {email},
		"password": {password},
	}

	// Register on tenant 1
	resp1 := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)

	// Register on tenant 2
	resp2 := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", tenant2.Domain))
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)

	// Login to tenant 1
	loginResp1 := ts.postFormWithOrigin(t, "/login", data, fmt.Sprintf("https://%s", tenant1.Domain))
	defer loginResp1.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp1.StatusCode)

	// Extract CSRF token for tenant 1
	body1 := getResponseBody(t, loginResp1)
	csrfToken1 := extractCSRFTokenFromResponse(body1)

	// Access tenant 1 dashboard - should work
	dashboardResp1 := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer dashboardResp1.Body.Close()
	assert.Equal(t, http.StatusOK, dashboardResp1.StatusCode)

	// Login to tenant 2
	loginResp2 := ts.postFormWithOrigin(t, "/login", data, fmt.Sprintf("https://%s", tenant2.Domain))
	defer loginResp2.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp2.StatusCode)

	// Extract CSRF token for tenant 2
	body2 := getResponseBody(t, loginResp2)
	csrfToken2 := extractCSRFTokenFromResponse(body2)

	// Access tenant 2 dashboard - should work
	dashboardResp2 := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant2.Domain), csrfToken2)
	defer dashboardResp2.Body.Close()
	assert.Equal(t, http.StatusOK, dashboardResp2.StatusCode)

	// Verify that tenant 1 session cannot access tenant 2 data
	crossTenantResp := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant2.Domain), csrfToken1)
	defer crossTenantResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, crossTenantResp.StatusCode)
}