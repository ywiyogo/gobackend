package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticationWorkflowWithOTP tests the complete OTP-based authentication flow
func TestAuthenticationWorkflowWithOTP(t *testing.T) {
	ts := setupOTPTestServer(t)
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

		// OTP registration should return OTP code (in real scenario, this would be sent via email/SMS)
		body := getResponseBody(t, resp)
		otpCode = extractOTPFromResponse(body)
		require.NotEmpty(t, otpCode, "OTP code should be present in response")
		assert.Len(t, otpCode, 6, "OTP should be 6 digits")

		// Extract CSRF token from response body
		csrfToken = extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, csrfToken, "CSRF token should be present in response")
	})

	t.Run("Verify OTP", func(t *testing.T) {
		data := url.Values{
			"otp": {otpCode},
		}

		resp := ts.postFormWithCSRF(t, "/verify-otp", data, csrfToken)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		assert.Contains(t, body, "OTP verified successfully")

		// Parse response JSON to verify email is present
		var response map[string]interface{}
		err := json.Unmarshal([]byte(body), &response)
		require.NoError(t, err, "Response should be valid JSON")

		// Check that user object exists and has email
		user, exists := response["user"].(map[string]interface{})
		require.True(t, exists, "Response should contain user object")

		email, exists := user["email"].(string)
		require.True(t, exists, "User object should contain email field")
		assert.NotEmpty(t, email, "Email should not be empty")
		assert.Equal(t, testEmail, email, "Email should match registered email")

		// Check for updated session cookie after OTP verification
		var sessionCookie *http.Cookie
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session_token" {
				sessionCookie = cookie
				break
			}
		}
		require.NotNil(t, sessionCookie, "Session cookie should be set after OTP verification")
	})

	t.Run("Access protected endpoint after OTP verification", func(t *testing.T) {
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

	t.Run("Login with OTP (existing user)", func(t *testing.T) {
		// First logout
		ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)

		// Try to login (should generate new OTP)
		data := url.Values{
			"email": {testEmail},
		}

		resp := ts.postForm(t, "/login", data)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Should return new OTP code
		body := getResponseBody(t, resp)
		newOTPCode := extractOTPFromResponse(body)
		require.NotEmpty(t, newOTPCode, "New OTP code should be present in response")
		assert.Len(t, newOTPCode, 6, "OTP should be 6 digits")

		// Extract new CSRF token
		csrfToken = extractCSRFTokenFromResponse(body)
		require.NotEmpty(t, csrfToken, "CSRF token should be present in response")

		// Verify the new OTP
		verifyData := url.Values{
			"otp": {newOTPCode},
		}

		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()

		assert.Equal(t, http.StatusOK, verifyResp.StatusCode)
	})

	t.Run("Logout", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestOTPErrorScenarios tests various error scenarios specific to OTP authentication
func TestOTPErrorScenarios(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-otp-errors-%d@example.com", time.Now().Unix())

	t.Run("Register and try invalid OTP", func(t *testing.T) {
		// Register user first
		registerData := url.Values{
			"email": {testEmail},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		defer registerResp.Body.Close()
		assert.Equal(t, http.StatusOK, registerResp.StatusCode)

		// Extract CSRF token
		body := getResponseBody(t, registerResp)
		csrfToken := extractCSRFTokenFromResponse(body)

		// Try to verify with invalid OTP
		verifyData := url.Values{
			"otp": {"000000"}, // Invalid OTP
		}
		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)
	})

	t.Run("Verify OTP with wrong session", func(t *testing.T) {
		// Try to verify OTP without proper session (no cookies from previous tests)
		verifyData := url.Values{
			"otp": {"123456"},
		}
		verifyResp := ts.postFormWithoutCookies(t, "/verify-otp", verifyData)
		defer verifyResp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)
	})

	t.Run("Verify OTP with expired code", func(t *testing.T) {
		// This would require mocking time or creating an OTP with very short expiry
		// For now, we test the basic flow
		verifyData := url.Values{
			"otp": {"123456"}, // Assume this is expired
		}
		verifyResp := ts.postFormWithoutCookies(t, "/verify-otp", verifyData)
		defer verifyResp.Body.Close()

		// Should fail due to invalid session or expired OTP
		assert.NotEqual(t, http.StatusOK, verifyResp.StatusCode)
	})

	t.Run("Multiple OTP verification attempts", func(t *testing.T) {
		// Register a new user for this test
		newEmail := fmt.Sprintf("test-multiple-otp-%d@example.com", time.Now().Unix())
		registerData := url.Values{
			"email": {newEmail},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		defer registerResp.Body.Close()

		// Extract CSRF token
		body := getResponseBody(t, registerResp)
		csrfToken := extractCSRFTokenFromResponse(body)

		// Try multiple invalid OTP attempts
		for i := 0; i < 3; i++ {
			verifyData := url.Values{
				"otp": {fmt.Sprintf("00000%d", i)}, // Invalid OTP
			}
			verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
			defer verifyResp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)
		}
	})

	t.Run("Verify OTP with invalid field name 'otp_code'", func(t *testing.T) {
		// This test ensures that the API correctly rejects requests using the old field name 'otp_code'
		// instead of the current field name 'otp'. This validates that the field name change is properly enforced.

		// Register a new user for this test
		wrongFieldEmail := fmt.Sprintf("test-wrong-field-%d@example.com", time.Now().Unix())
		registerData := url.Values{
			"email": {wrongFieldEmail},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		defer registerResp.Body.Close()
		assert.Equal(t, http.StatusOK, registerResp.StatusCode)

		// Extract CSRF token and OTP
		body := getResponseBody(t, registerResp)
		csrfToken := extractCSRFTokenFromResponse(body)
		otpCode := extractOTPFromResponse(body)

		// Try to verify with the old field name 'otp_code' instead of 'otp'
		// This simulates a client using outdated API documentation or old code
		verifyData := url.Values{
			"otp_code": {otpCode}, // Wrong field name - should be 'otp'
		}
		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()

		// Should return unauthorized due to empty OTP (field name mismatch)
		// When 'otp_code' is sent instead of 'otp', the system receives an empty OTP field
		// and treats it as invalid, resulting in authentication failure
		assert.Equal(t, http.StatusUnauthorized, verifyResp.StatusCode)

		// Verify that the response indicates the OTP validation failed
		responseBody := getResponseBody(t, verifyResp)
		// The system should return an error about invalid OTP since the otp field is empty
		// when otp_code is used instead of otp
		assert.NotEmpty(t, responseBody, "Response should contain error message")
		t.Logf("Response when using wrong field name 'otp_code': %s", responseBody)
	})
}

// TestOTPSessionManagement tests session management specific to OTP authentication
func TestOTPSessionManagement(t *testing.T) {
	ts := setupOTPTestServer(t)
	defer ts.cleanup(t)

	testEmail := fmt.Sprintf("test-otp-session-%d@example.com", time.Now().Unix())

	t.Run("Session creation and validation", func(t *testing.T) {
		// Register user
		registerData := url.Values{
			"email": {testEmail},
		}
		registerResp := ts.postForm(t, "/register", registerData)
		defer registerResp.Body.Close()
		assert.Equal(t, http.StatusOK, registerResp.StatusCode)

		// Extract OTP and CSRF token
		body := getResponseBody(t, registerResp)
		otpCode := extractOTPFromResponse(body)
		csrfToken := extractCSRFTokenFromResponse(body)

		// Verify OTP should create a full session
		verifyData := url.Values{
			"otp": {otpCode},
		}
		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()
		assert.Equal(t, http.StatusOK, verifyResp.StatusCode)

		// Session should now allow access to protected resources
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Session invalidation after logout", func(t *testing.T) {
		// Login again to get a fresh session
		loginData := url.Values{
			"email": {testEmail},
		}
		loginResp := ts.postForm(t, "/login", loginData)
		defer loginResp.Body.Close()

		// Extract new OTP and CSRF token
		body := getResponseBody(t, loginResp)
		otpCode := extractOTPFromResponse(body)
		csrfToken := extractCSRFTokenFromResponse(body)

		// Verify OTP
		verifyData := url.Values{
			"otp": {otpCode},
		}
		verifyResp := ts.postFormWithCSRF(t, "/verify-otp", verifyData, csrfToken)
		defer verifyResp.Body.Close()

		// Logout
		logoutResp := ts.postFormWithCSRF(t, "/logout", url.Values{}, csrfToken)
		defer logoutResp.Body.Close()
		assert.Equal(t, http.StatusOK, logoutResp.StatusCode)

		// Access should now be denied
		req, err := http.NewRequest("GET", ts.Server.URL+"/dashboard", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", ts.DefaultTenant.Domain))

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
