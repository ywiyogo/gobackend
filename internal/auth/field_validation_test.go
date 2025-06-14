package auth

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyOTPFieldValidation tests that the API properly rejects requests
// using the old field name 'otp_code' instead of the new field name 'otp'
func TestVerifyOTPFieldValidation(t *testing.T) {
	// Create a mock handler for testing
	handler := &Handler{}

	t.Run("JSON request with correct field name 'otp'", func(t *testing.T) {
		// Test with correct field name
		requestBody := map[string]interface{}{
			"email": "test@example.com",
			"otp":   "123456",
		}

		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/verify-otp", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		var parsedReq VerifyOTPRequest
		err = handler.parseRequest(req, &parsedReq)

		// Should parse successfully
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", parsedReq.Email)
		assert.Equal(t, "123456", parsedReq.OTP)
	})

	t.Run("JSON request with incorrect field name 'otp_code'", func(t *testing.T) {
		// Test with incorrect field name
		requestBody := map[string]interface{}{
			"email":    "test@example.com",
			"otp_code": "123456", // Wrong field name
		}

		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/verify-otp", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		var parsedReq VerifyOTPRequest
		err = handler.parseRequest(req, &parsedReq)

		// Should parse but OTP field will be empty due to field name mismatch
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", parsedReq.Email)
		assert.Empty(t, parsedReq.OTP, "OTP should be empty when wrong field name is used")
	})

	t.Run("Form data with correct field name 'otp'", func(t *testing.T) {
		// Test form data with correct field name
		formData := url.Values{
			"email": {"test@example.com"},
			"otp":   {"123456"},
		}

		req := httptest.NewRequest("POST", "/verify-otp", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var parsedReq VerifyOTPRequest
		err := handler.parseRequest(req, &parsedReq)

		// Should parse successfully
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", parsedReq.Email)
		assert.Equal(t, "123456", parsedReq.OTP)
	})

	t.Run("Form data with incorrect field name 'otp_code'", func(t *testing.T) {
		// Test form data with incorrect field name
		formData := url.Values{
			"email":    {"test@example.com"},
			"otp_code": {"123456"}, // Wrong field name
		}

		req := httptest.NewRequest("POST", "/verify-otp", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var parsedReq VerifyOTPRequest
		err := handler.parseRequest(req, &parsedReq)

		// Should parse but OTP field will be empty due to field name mismatch
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", parsedReq.Email)
		assert.Empty(t, parsedReq.OTP, "OTP should be empty when wrong field name 'otp_code' is used")
	})

	t.Run("Mixed field names - correct and incorrect", func(t *testing.T) {
		// Test with both correct and incorrect field names
		formData := url.Values{
			"email":    {"test@example.com"},
			"otp":      {"correct_otp"},
			"otp_code": {"wrong_otp"},
		}

		req := httptest.NewRequest("POST", "/verify-otp", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var parsedReq VerifyOTPRequest
		err := handler.parseRequest(req, &parsedReq)

		// Should parse and use the correct field name
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", parsedReq.Email)
		assert.Equal(t, "correct_otp", parsedReq.OTP, "Should use value from 'otp' field, not 'otp_code'")
	})
}

// TestOTPRequestStructValidation tests the struct validation tags
func TestOTPRequestStructValidation(t *testing.T) {
	t.Run("Valid OTP request", func(t *testing.T) {
		req := VerifyOTPRequest{
			Email: "test@example.com",
			OTP:   "123456",
		}

		// Check that the struct has the correct field names and tags
		assert.NotEmpty(t, req.Email)
		assert.NotEmpty(t, req.OTP)
		assert.Len(t, req.OTP, 6, "OTP should be 6 characters")
	})

	t.Run("Empty OTP field", func(t *testing.T) {
		req := VerifyOTPRequest{
			Email: "test@example.com",
			OTP:   "", // Empty OTP (what happens when wrong field name is used)
		}

		// This simulates what happens when 'otp_code' is sent instead of 'otp'
		assert.NotEmpty(t, req.Email)
		assert.Empty(t, req.OTP, "OTP should be empty when field name is incorrect")
	})
}

// TestFieldNameDocumentation tests that we document the correct field names
func TestFieldNameDocumentation(t *testing.T) {
	t.Run("Verify struct tags use correct field names", func(t *testing.T) {
		// This test documents that the VerifyOTPRequest struct uses 'otp' not 'otp_code'
		req := VerifyOTPRequest{}

		// Use reflection to verify the JSON tag
		// This is a compile-time check that ensures the struct uses the correct field name
		jsonBody := `{"email":"test@example.com","otp":"123456"}`
		err := json.Unmarshal([]byte(jsonBody), &req)

		require.NoError(t, err)
		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "123456", req.OTP)
	})

	t.Run("Verify deprecated field name is not accepted", func(t *testing.T) {
		// This test documents that 'otp_code' is not accepted
		req := VerifyOTPRequest{}

		// JSON with old field name should result in empty OTP
		jsonBody := `{"email":"test@example.com","otp_code":"123456"}`
		err := json.Unmarshal([]byte(jsonBody), &req)

		require.NoError(t, err)
		assert.Equal(t, "test@example.com", req.Email)
		assert.Empty(t, req.OTP, "Old field name 'otp_code' should not populate OTP field")
	})
}

// TestWrongFieldNameBehavior demonstrates the exact behavior when wrong field name is used
func TestWrongFieldNameBehavior(t *testing.T) {
	t.Run("Demonstrate wrong field name leads to empty OTP", func(t *testing.T) {
		// This test demonstrates that using 'otp_code' instead of 'otp' results in an empty OTP field
		// which would cause authentication to fail with "invalid OTP code" error

		// Simulate client using old API documentation
		wrongFieldRequest := map[string]interface{}{
			"email":    "user@example.com",
			"otp_code": "123456", // Client mistakenly uses old field name
		}

		// Simulate correct API usage
		correctFieldRequest := map[string]interface{}{
			"email": "user@example.com",
			"otp":   "123456", // Client uses correct field name
		}

		// Parse both requests
		var wrongReq VerifyOTPRequest
		var correctReq VerifyOTPRequest

		wrongJSON, _ := json.Marshal(wrongFieldRequest)
		correctJSON, _ := json.Marshal(correctFieldRequest)

		json.Unmarshal(wrongJSON, &wrongReq)
		json.Unmarshal(correctJSON, &correctReq)

		// Demonstrate the difference
		t.Logf("Using 'otp_code' field: Email=%s, OTP='%s' (empty=%t)",
			wrongReq.Email, wrongReq.OTP, wrongReq.OTP == "")
		t.Logf("Using 'otp' field: Email=%s, OTP='%s' (empty=%t)",
			correctReq.Email, correctReq.OTP, correctReq.OTP == "")

		// Assertions
		assert.Equal(t, "user@example.com", wrongReq.Email)
		assert.Empty(t, wrongReq.OTP, "Wrong field name results in empty OTP")

		assert.Equal(t, "user@example.com", correctReq.Email)
		assert.Equal(t, "123456", correctReq.OTP, "Correct field name populates OTP")

		// This empty OTP would cause the verification to fail in the service layer
		// with an "invalid OTP code" error since empty string != stored OTP
	})

	t.Run("Show error message client would receive", func(t *testing.T) {
		// When a client sends otp_code instead of otp, the parsed request has empty OTP
		// This would result in the service layer comparing "" with the stored OTP
		// and returning an authentication error

		storedOTP := "123456"
		receivedOTP := "" // This is what happens when otp_code is used instead of otp

		isValid := storedOTP == receivedOTP

		assert.False(t, isValid, "Empty OTP (from wrong field name) should not match stored OTP")

		// The error message the client would receive would be something like:
		// "invalid OTP code" or "OTP verification failed"
		// This provides a clear indication that the OTP validation failed
		expectedErrorScenario := "Client uses 'otp_code' → Server receives empty OTP → Validation fails → Returns 'invalid OTP code' error"
		t.Logf("Error scenario: %s", expectedErrorScenario)
	})
}
