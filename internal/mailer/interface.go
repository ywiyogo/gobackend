package mailer

import "time"

// Mailer defines the interface for email sending services
type Mailer interface {
	// SendOTP sends an OTP verification email to the specified recipient
	SendOTP(toEmail, toName, otpCode string, expiryTime time.Time, tenantName string) error

	// SendVerificationEmail sends a verification email with OTP code, tenant name, and expiry
	SendVerificationEmail(toEmail, toName, otpCode, tenantName string, expiryTime time.Time) error

	// TestConnection tests the connection to the email service
	TestConnection() error

	// GetConfig returns the current configuration (without sensitive data)
	GetConfig() map[string]interface{}
}

// Ensure our implementations satisfy the interface
var _ Mailer = (*Service)(nil)
var _ Mailer = (*MockService)(nil)
