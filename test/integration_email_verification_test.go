package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"gobackend/internal/db/sqlc"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailVerificationWorkflow(t *testing.T) {
	// Setup test server with password-based auth (OTP disabled for email verification)
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Create a specific test tenant for email verification
	testTenant := ts.setupTestTenant(t, "emailtest.com")

	t.Run("Registration sends verification email with OTP", func(t *testing.T) {
		// Register user with password (should send verification email)
		data := url.Values{
			"email":    {"test@example.com"},
			"password": {"TestPassword123!"},
		}

		resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()

		// Check response
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		body := getResponseBody(t, resp)
		var response map[string]interface{}
		err := json.Unmarshal([]byte(body), &response)
		require.NoError(t, err)

		assert.Contains(t, response["message"], "check your email to verify")

		// For password registration, requires_otp should be false
		if requiresOTP, exists := response["requires_otp"]; exists {
			assert.False(t, requiresOTP.(bool))
		}
	})

	t.Run("Email verification with OTP via GET request", func(t *testing.T) {
		// For testing, we need to get the OTP from the database since we can't intercept emails
		// Get the user and their OTP
		user, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "test@example.com", testTenant.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.True(t, user.Otp.Valid)

		otpCode := user.Otp.String
		require.Len(t, otpCode, 6, "OTP should be 6 digits")

		// Verify OTP is numeric
		for _, char := range otpCode {
			assert.True(t, char >= '0' && char <= '9', "OTP should contain only digits")
		}

		// Verify email using GET request (simulating link click)
		url := fmt.Sprintf("/verify-email-otp?otp=%s&email=test@example.com", otpCode)
		resp := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()

		// Check response
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := getResponseBody(t, resp)
		var response map[string]interface{}
		err = json.Unmarshal([]byte(body), &response)
		require.NoError(t, err)

		assert.Contains(t, response["message"], "Email verified successfully")

		// Verify user data
		user_resp := response["user"].(map[string]interface{})
		assert.Equal(t, "test@example.com", user_resp["email"])
	})

	t.Run("Email verification with OTP via POST request", func(t *testing.T) {
		// Register another user
		data := url.Values{
			"email":    {"test2@example.com"},
			"password": {"TestPassword123!"},
		}

		resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Get OTP from database
		user, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "test2@example.com", testTenant.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.True(t, user.Otp.Valid)

		otpCode := user.Otp.String

		// Verify email using POST request
		verifyData := url.Values{
			"otp":   {otpCode},
			"email": {"test2@example.com"},
		}

		resp2 := ts.postFormWithOrigin(t, "/verify-email-otp", verifyData, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp2.Body.Close()

		// Check response
		assert.Equal(t, http.StatusOK, resp2.StatusCode)

		body := getResponseBody(t, resp2)
		var response map[string]interface{}
		err = json.Unmarshal([]byte(body), &response)
		require.NoError(t, err)

		assert.Contains(t, response["message"], "Email verified successfully")
	})

	t.Run("Invalid OTP returns error", func(t *testing.T) {
		// Try to verify with invalid OTP
		url := "/verify-email-otp?otp=999999&email=test@example.com"
		resp := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()

		// Should return error
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Expired OTP returns error", func(t *testing.T) {
		// Register a user
		data := url.Values{
			"email":    {"expired@example.com"},
			"password": {"TestPassword123!"},
		}

		resp := ts.postFormWithOrigin(t, "/register", data, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Get the user and manually expire the OTP
		user, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "expired@example.com", testTenant.ID)
		require.NoError(t, err)
		require.NotNil(t, user)

		// Get queries to manually update OTP expiry
		queries := sqlc.New(ts.Pool)

		// Manually update the user's OTP expiry to past
		expiredTime := time.Now().Add(-1 * time.Hour)
		err = queries.SetUserOTPInTenant(context.Background(), sqlc.SetUserOTPInTenantParams{
			TenantID:     pgtype.UUID{Bytes: testTenant.ID, Valid: true},
			ID:           user.ID,
			Otp:          user.Otp,
			OtpExpiresAt: pgtype.Timestamptz{Time: expiredTime, Valid: true},
		})
		require.NoError(t, err)

		// Try to verify with expired OTP
		otpCode := user.Otp.String
		url := fmt.Sprintf("/verify-email-otp?otp=%s&email=expired@example.com", otpCode)
		resp2 := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp2.Body.Close()

		// Should return error for expired OTP
		assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	})

	t.Run("Already verified email returns error", func(t *testing.T) {
		// Get the first user's OTP (should be cleared after verification)
		user, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "test@example.com", testTenant.ID)
		require.NoError(t, err)
		require.NotNil(t, user)

		// Since the email was already verified, OTP should be cleared
		// Try to verify again with any OTP
		url := "/verify-email-otp?otp=123456&email=test@example.com"
		resp := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()

		// Should return error since email is already verified or OTP is cleared
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Missing OTP parameter returns error", func(t *testing.T) {
		// Try to verify without OTP parameter
		url := "/verify-email-otp?email=test@example.com"
		resp := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()

		// Should return bad request
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Method not allowed for unsupported HTTP methods", func(t *testing.T) {
		// Try with PUT method
		req, err := http.NewRequest("PUT", ts.Server.URL+"/verify-email-otp", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", fmt.Sprintf("https://%s", testTenant.Domain))

		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should return method not allowed
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})
}

func TestEmailVerificationWithMultipleTenants(t *testing.T) {
	// Setup test server
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	// Create two test tenants
	tenant1 := ts.setupTestTenant(t, "company1.com")
	tenant2 := ts.setupTestTenant(t, "company2.com")

	t.Run("Different tenants create separate users with OTPs", func(t *testing.T) {
		// Register user for tenant 1
		data1 := url.Values{
			"email":    {"user1@example.com"},
			"password": {"TestPassword123!"},
		}

		resp1 := ts.postFormWithOrigin(t, "/register", data1, fmt.Sprintf("https://%s", tenant1.Domain))
		defer resp1.Body.Close()
		assert.Equal(t, http.StatusCreated, resp1.StatusCode)

		// Register user for tenant 2
		data2 := url.Values{
			"email":    {"user2@example.com"},
			"password": {"TestPassword123!"},
		}

		resp2 := ts.postFormWithOrigin(t, "/register", data2, fmt.Sprintf("https://%s", tenant2.Domain))
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusCreated, resp2.StatusCode)

		// Verify both users exist in their respective tenants
		user1, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "user1@example.com", tenant1.ID)
		require.NoError(t, err)
		require.NotNil(t, user1)

		user2, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "user2@example.com", tenant2.ID)
		require.NoError(t, err)
		require.NotNil(t, user2)

		// Verify they have different OTPs
		assert.True(t, user1.Otp.Valid)
		assert.True(t, user2.Otp.Valid)
		assert.NotEqual(t, user1.Otp.String, user2.Otp.String)
	})

	t.Run("OTP from one tenant cannot verify email in another tenant", func(t *testing.T) {
		// Get OTP from tenant1 user
		user1, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "user1@example.com", tenant1.ID)
		require.NoError(t, err)
		require.NotNil(t, user1)
		require.True(t, user1.Otp.Valid)

		tenant1OTP := user1.Otp.String

		// Try to use tenant1 OTP with tenant2 context
		url := fmt.Sprintf("/verify-email-otp?otp=%s&email=user2@example.com", tenant1OTP)
		resp := ts.getFormWithOrigin(t, url, fmt.Sprintf("https://%s", tenant2.Domain))
		defer resp.Body.Close()

		// Should fail - wrong tenant
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Verify emails work correctly within their own tenants", func(t *testing.T) {
		// Get OTPs for both users
		user1, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "user1@example.com", tenant1.ID)
		require.NoError(t, err)
		tenant1OTP := user1.Otp.String

		user2, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "user2@example.com", tenant2.ID)
		require.NoError(t, err)
		tenant2OTP := user2.Otp.String

		// Verify user1 with tenant1 context
		url1 := fmt.Sprintf("/verify-email-otp?otp=%s&email=user1@example.com", tenant1OTP)
		resp1 := ts.getFormWithOrigin(t, url1, fmt.Sprintf("https://%s", tenant1.Domain))
		defer resp1.Body.Close()
		assert.Equal(t, http.StatusOK, resp1.StatusCode)

		// Verify user2 with tenant2 context
		url2 := fmt.Sprintf("/verify-email-otp?otp=%s&email=user2@example.com", tenant2OTP)
		resp2 := ts.getFormWithOrigin(t, url2, fmt.Sprintf("https://%s", tenant2.Domain))
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
	})
}

func TestEmailVerificationJSONSupport(t *testing.T) {
	// Setup test server
	ts := setupPasswordTestServer(t)
	defer ts.cleanup(t)

	testTenant := ts.setupTestTenant(t, "jsontest.com")

	t.Run("Register user and verify with JSON POST", func(t *testing.T) {
		// Register user using JSON
		registerData := map[string]string{
			"email":    "jsonuser@example.com",
			"password": "TestPassword123!",
		}

		resp := ts.postJSONWithOrigin(t, "/register", registerData, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Get the OTP from database
		user, err := ts.AuthService.GetUserByEmailAndTenant(context.Background(), "jsonuser@example.com", testTenant.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.True(t, user.Otp.Valid)

		otpCode := user.Otp.String

		// Verify using JSON POST
		verifyData := map[string]string{
			"otp":   otpCode,
			"email": "jsonuser@example.com",
		}

		resp2 := ts.postJSONWithOrigin(t, "/verify-email-otp", verifyData, fmt.Sprintf("https://%s", testTenant.Domain))
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusOK, resp2.StatusCode)

		body := getResponseBody(t, resp2)
		var response map[string]interface{}
		err = json.Unmarshal([]byte(body), &response)
		require.NoError(t, err)

		assert.Contains(t, response["message"], "Email verified successfully")
	})
}
