package test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"gobackend/internal/tenant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantSettings tests that tenant-specific settings are respected
func TestTenantSettings(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.cleanup(t)

	// Create tenant with OTP enabled
	otpSettings := &tenant.TenantSettings{
		OTPEnabled:               true,
		SessionTimeoutMinutes:    1440,
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       100,
		RequireEmailVerification: false,
		CustomBranding:           make(map[string]string),
	}

	otpTenantReq := &tenant.CreateTenantRequest{
		Name:     "OTP Test App",
		Domain:   "otp.test.com",
		Settings: otpSettings,
	}

	otpTenant, err := ts.TenantService.CreateTenant(otpTenantReq)
	require.NoError(t, err)



	email := "settings@example.com"

	// Test OTP tenant - should require OTP
	t.Run("OTP tenant requires OTP", func(t *testing.T) {
		data := url.Values{
			"email": {email},
		}

		resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", otpTenant.Domain))
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Should return OTP in response
		body := getResponseBody(t, resp)
		otpCode := extractOTPFromResponse(body)
		assert.NotEmpty(t, otpCode, "OTP should be generated for OTP-enabled tenant")
	})


}

// TestMultiTenantOTPIsolation tests that OTP codes are isolated between tenants
func TestMultiTenantOTPIsolation(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	// Setup two tenants with OTP enabled
	tenant1 := ts.setupTestTenant(t, "otp1.test.com")
	tenant2 := ts.setupTestTenant(t, "otp2.test.com")

	email := "otp-isolation@example.com"

	// Register user on tenant 1
	data1 := url.Values{
		"email": {email},
	}
	resp1 := ts.postFormWithOrigin(t, "/register", data1, fmt.Sprintf("https://%s", tenant1.Domain))
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Extract OTP and CSRF token for tenant 1
	body1 := getResponseBody(t, resp1)
	otpCode1 := extractOTPFromResponse(body1)
	csrfToken1 := extractCSRFTokenFromResponse(body1)

	// Verify correct OTP on tenant 1 first (should work)
	verifyData1 := url.Values{
		"otp_code": {otpCode1},
	}
	verifyResp1 := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData1, fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer verifyResp1.Body.Close()
	assert.Equal(t, http.StatusOK, verifyResp1.StatusCode)

	// Register user on tenant 2
	data2 := url.Values{
		"email": {email},
	}
	resp2 := ts.postFormWithOrigin(t, "/register", data2, fmt.Sprintf("https://%s", tenant2.Domain))
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Extract OTP and CSRF token for tenant 2
	body2 := getResponseBody(t, resp2)
	otpCode2 := extractOTPFromResponse(body2)
	csrfToken2 := extractCSRFTokenFromResponse(body2)

	// Try to verify tenant 1's OTP on tenant 2 (should fail)
	verifyData := url.Values{
		"otp_code": {otpCode1}, // Use tenant 1's OTP
	}
	verifyResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", tenant2.Domain), csrfToken2)
	defer verifyResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)

	// Verify correct OTP on tenant 2 (should work)
	verifyData2 := url.Values{
		"otp_code": {otpCode2},
	}
	verifyResp2 := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData2, fmt.Sprintf("https://%s", tenant2.Domain), csrfToken2)
	defer verifyResp2.Body.Close()
	assert.Equal(t, http.StatusOK, verifyResp2.StatusCode)
}

// TestMultiTenantOTPSessionSecurity tests OTP session security across tenants
func TestMultiTenantOTPSessionSecurity(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	// Setup two tenants
	tenant1 := ts.setupTestTenant(t, "otpsec1.test.com")
	tenant2 := ts.setupTestTenant(t, "otpsec2.test.com")

	email := "otpsecurity@example.com"

	// Register and verify OTP on tenant 1
	registerData := url.Values{
		"email": {email},
	}
	registerResp1 := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant1.Domain))
	defer registerResp1.Body.Close()
	assert.Equal(t, http.StatusOK, registerResp1.StatusCode)

	// Extract OTP and CSRF token
	body1 := getResponseBody(t, registerResp1)
	otpCode1 := extractOTPFromResponse(body1)
	csrfToken1 := extractCSRFTokenFromResponse(body1)

	// Verify OTP on tenant 1
	verifyData := url.Values{
		"otp_code": {otpCode1},
	}
	verifyResp1 := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer verifyResp1.Body.Close()
	assert.Equal(t, http.StatusOK, verifyResp1.StatusCode)

	// Access tenant 1 dashboard (should work)
	dashboardResp1 := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant1.Domain), csrfToken1)
	defer dashboardResp1.Body.Close()
	assert.Equal(t, http.StatusOK, dashboardResp1.StatusCode)

	// Register user with same email on tenant 2
	registerResp2 := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant2.Domain))
	defer registerResp2.Body.Close()
	assert.Equal(t, http.StatusOK, registerResp2.StatusCode)

	// Try to access tenant 2 dashboard with tenant 1 session (should fail)
	dashboardResp2 := ts.getFormWithOrigin(t, "/dashboard", fmt.Sprintf("https://%s", tenant2.Domain))
	defer dashboardResp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, dashboardResp2.StatusCode)
}

// TestMultiTenantOTPWorkflow tests the complete OTP workflow across multiple tenants
func TestMultiTenantOTPWorkflow(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	// Setup tenant with custom OTP settings
	customSettings := &tenant.TenantSettings{
		OTPEnabled:               true,
		SessionTimeoutMinutes:    60, // Shorter session timeout
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       50, // Lower rate limit
		RequireEmailVerification: true,
		CustomBranding:           map[string]string{"theme": "dark"},
	}

	customTenantReq := &tenant.CreateTenantRequest{
		Name:     "Custom OTP Tenant",
		Domain:   "custom-otp.test.com",
		Settings: customSettings,
	}

	customTenant, err := ts.TenantService.CreateTenant(customTenantReq)
	require.NoError(t, err)

	email := "workflow@example.com"

	t.Run("Complete OTP workflow on custom tenant", func(t *testing.T) {
		// Register
		registerData := url.Values{
			"email": {email},
		}
		registerResp := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", customTenant.Domain))
		defer registerResp.Body.Close()
		assert.Equal(t, http.StatusOK, registerResp.StatusCode)

		// Extract OTP and CSRF token
		body := getResponseBody(t, registerResp)
		otpCode := extractOTPFromResponse(body)
		csrfToken := extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, otpCode, "OTP should be generated")
		require.NotEmpty(t, csrfToken, "CSRF token should be generated")

		// Verify OTP
		verifyData := url.Values{
			"otp_code": {otpCode},
		}
		verifyResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", customTenant.Domain), csrfToken)
		defer verifyResp.Body.Close()
		assert.Equal(t, http.StatusOK, verifyResp.StatusCode)

		// Access protected resource
		dashboardResp := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", customTenant.Domain), csrfToken)
		defer dashboardResp.Body.Close()
		assert.Equal(t, http.StatusOK, dashboardResp.StatusCode)

		// Logout
		logoutResp := ts.postFormWithOriginAndCSRF(t, "/logout", url.Values{}, fmt.Sprintf("https://%s", customTenant.Domain), csrfToken)
		defer logoutResp.Body.Close()
		assert.Equal(t, http.StatusOK, logoutResp.StatusCode)

		// Verify access is denied after logout
		dashboardAfterLogout := ts.getFormWithOrigin(t, "/dashboard", fmt.Sprintf("https://%s", customTenant.Domain))
		defer dashboardAfterLogout.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, dashboardAfterLogout.StatusCode)
	})
}

// TestMultiTenantOTPErrors tests error scenarios in multi-tenant OTP authentication
func TestMultiTenantOTPErrors(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	tenant := ts.setupTestTenant(t, "otp-errors.test.com")
	email := "errors@example.com"

	t.Run("Invalid OTP verification", func(t *testing.T) {
		// Register user
		registerData := url.Values{
			"email": {email},
		}
		registerResp := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant.Domain))
		defer registerResp.Body.Close()

		// Extract CSRF token
		body := getResponseBody(t, registerResp)
		csrfToken := extractCSRFTokenFromResponse(body)

		// Try invalid OTP
		verifyData := url.Values{
			"otp_code": {"000000"}, // Invalid OTP
		}
		verifyResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", tenant.Domain), csrfToken)
		defer verifyResp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)
	})

	t.Run("Cross-tenant OTP verification attempt", func(t *testing.T) {
		// Setup another tenant
		tenant2 := ts.setupTestTenant(t, "otp-errors2.test.com")

		// Register on tenant 1
		registerData := url.Values{
			"email": {email + "2"},
		}
		registerResp1 := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant.Domain))
		defer registerResp1.Body.Close()

		// Extract OTP and CSRF token from tenant 1
		body1 := getResponseBody(t, registerResp1)
		otpCode1 := extractOTPFromResponse(body1)

		// Register on tenant 2
		registerResp2 := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant2.Domain))
		defer registerResp2.Body.Close()

		// Extract CSRF token from tenant 2
		body2 := getResponseBody(t, registerResp2)
		csrfToken2 := extractCSRFTokenFromResponse(body2)

		// Try to use tenant 1's OTP on tenant 2
		verifyData := url.Values{
			"otp_code": {otpCode1},
		}
		verifyResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", tenant2.Domain), csrfToken2)
		defer verifyResp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)
	})

	t.Run("Missing session for OTP verification", func(t *testing.T) {
		// Try to verify OTP without a session (new client)
		newClient := &http.Client{}

		req, err := http.NewRequest("POST", ts.Server.URL+"/verify-otp", nil)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", fmt.Sprintf("https://%s", tenant.Domain))

		resp, err := newClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// TestMultiTenantOTPLogin tests OTP login functionality across tenants
func TestMultiTenantOTPLogin(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	tenant := ts.setupTestTenant(t, "otp-login.test.com")
	email := "login@example.com"

	// Register user first
	registerData := url.Values{
		"email": {email},
	}
	registerResp := ts.postFormWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", tenant.Domain))
	defer registerResp.Body.Close()
	assert.Equal(t, http.StatusOK, registerResp.StatusCode)

	// Extract and verify initial OTP
	body := getResponseBody(t, registerResp)
	initialOTP := extractOTPFromResponse(body)
	initialCSRF := extractCSRFTokenFromResponse(body)

	verifyData := url.Values{
		"otp_code": {initialOTP},
	}
	verifyResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyData, fmt.Sprintf("https://%s", tenant.Domain), initialCSRF)
	defer verifyResp.Body.Close()
	assert.Equal(t, http.StatusOK, verifyResp.StatusCode)

	// Logout
	logoutResp := ts.postFormWithOriginAndCSRF(t, "/logout", url.Values{}, fmt.Sprintf("https://%s", tenant.Domain), initialCSRF)
	defer logoutResp.Body.Close()
	assert.Equal(t, http.StatusOK, logoutResp.StatusCode)

	t.Run("Login with OTP for existing user", func(t *testing.T) {
		// Login (should generate new OTP)
		loginData := url.Values{
			"email": {email},
		}
		loginResp := ts.postFormWithOrigin(t, "/login", loginData, fmt.Sprintf("https://%s", tenant.Domain))
		defer loginResp.Body.Close()
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)

		// Extract new OTP and CSRF token
		loginBody := getResponseBody(t, loginResp)
		loginOTP := extractOTPFromResponse(loginBody)
		loginCSRF := extractCSRFTokenFromResponse(loginBody)
		require.NotEmpty(t, loginOTP, "Login should generate new OTP")
		require.NotEmpty(t, loginCSRF, "Login should generate CSRF token")

		// Verify new OTP
		verifyLoginData := url.Values{
			"otp_code": {loginOTP},
		}
		verifyLoginResp := ts.postFormWithOriginAndCSRF(t, "/verify-otp", verifyLoginData, fmt.Sprintf("https://%s", tenant.Domain), loginCSRF)
		defer verifyLoginResp.Body.Close()
		assert.Equal(t, http.StatusOK, verifyLoginResp.StatusCode)

		// Access protected resource
		dashboardResp := ts.getFormWithOriginAndCSRF(t, "/dashboard", fmt.Sprintf("https://%s", tenant.Domain), loginCSRF)
		defer dashboardResp.Body.Close()
		assert.Equal(t, http.StatusOK, dashboardResp.StatusCode)
	})
}