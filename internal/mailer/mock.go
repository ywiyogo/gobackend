package mailer

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// MockService is a mock implementation of the mailer service for testing and development
type MockService struct {
	enabled bool
	emails  []MockEmail
}

// MockEmail represents an email that was "sent" by the mock service
type MockEmail struct {
	ToEmail     string
	ToName      string
	Subject     string
	OTPCode     string
	TenantName  string
	ExpiryTime  time.Time
	SentAt      time.Time
}

// NewMockService creates a new mock mailer service
func NewMockService() *MockService {
	return &MockService{
		enabled: true,
		emails:  make([]MockEmail, 0),
	}
}

// SendOTP simulates sending an OTP email by logging it and storing it in memory
func (m *MockService) SendOTP(toEmail, toName, otpCode string, expiryTime time.Time, tenantName string) error {
	if !m.enabled {
		return fmt.Errorf("mock mailer service is disabled")
	}

	mockEmail := MockEmail{
		ToEmail:    toEmail,
		ToName:     toName,
		Subject:    fmt.Sprintf("Email Verification Code: %s", otpCode),
		OTPCode:    otpCode,
		TenantName: tenantName,
		ExpiryTime: expiryTime,
		SentAt:     time.Now(),
	}

	m.emails = append(m.emails, mockEmail)

	log.Info().
		Str("pkg", pkgName).
		Str("service", "mock").
		Str("to_email", toEmail).
		Str("to_name", toName).
		Str("otp_code", otpCode).
		Str("tenant_name", tenantName).
		Time("expires_at", expiryTime).
		Msg("Mock email sent - OTP verification code")

	// Print to console for easy development testing
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("📧 MOCK EMAIL SENT\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	fmt.Printf("To: %s <%s>\n", toName, toEmail)
	fmt.Printf("Subject: %s\n", mockEmail.Subject)
	fmt.Printf("Tenant: %s\n", tenantName)
	fmt.Printf("OTP Code: %s\n", otpCode)
	fmt.Printf("Expires: %s\n", expiryTime.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf(strings.Repeat("=", 60) + "\n\n")

	return nil
}

// TestConnection simulates testing the connection (always succeeds for mock)
func (m *MockService) TestConnection() error {
	if !m.enabled {
		return fmt.Errorf("mock mailer service is disabled")
	}

	log.Info().
		Str("pkg", pkgName).
		Str("service", "mock").
		Msg("Mock SMTP connection test successful")

	return nil
}

// GetConfig returns mock configuration
func (m *MockService) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"service":    "mock",
		"enabled":    m.enabled,
		"host":       "mock.smtp.local",
		"port":       587,
		"username":   "mock@example.com",
		"from_email": "mock@example.com",
		"from_name":  "Mock Mailer Service",
		"use_tls":    true,
		"password":   "[MOCK]",
	}
}

// GetSentEmails returns all emails sent by the mock service (for testing)
func (m *MockService) GetSentEmails() []MockEmail {
	return m.emails
}

// GetLastEmail returns the most recently sent email (for testing)
func (m *MockService) GetLastEmail() *MockEmail {
	if len(m.emails) == 0 {
		return nil
	}
	return &m.emails[len(m.emails)-1]
}

// GetEmailCount returns the number of emails sent
func (m *MockService) GetEmailCount() int {
	return len(m.emails)
}

// ClearEmails clears all sent emails from memory (for testing)
func (m *MockService) ClearEmails() {
	m.emails = make([]MockEmail, 0)
	log.Debug().
		Str("pkg", pkgName).
		Str("service", "mock").
		Msg("Cleared all mock emails")
}

// SetEnabled enables or disables the mock service
func (m *MockService) SetEnabled(enabled bool) {
	m.enabled = enabled
	log.Info().
		Str("pkg", pkgName).
		Str("service", "mock").
		Bool("enabled", enabled).
		Msg("Mock mailer service enabled status changed")
}

// IsEnabled returns whether the mock service is enabled
func (m *MockService) IsEnabled() bool {
	return m.enabled
}

// FindEmailByCode finds an email by OTP code (for testing)
func (m *MockService) FindEmailByCode(otpCode string) *MockEmail {
	for i := len(m.emails) - 1; i >= 0; i-- {
		if m.emails[i].OTPCode == otpCode {
			return &m.emails[i]
		}
	}
	return nil
}

// FindEmailsByRecipient finds all emails sent to a specific recipient
func (m *MockService) FindEmailsByRecipient(email string) []MockEmail {
	var result []MockEmail
	for _, mockEmail := range m.emails {
		if mockEmail.ToEmail == email {
			result = append(result, mockEmail)
		}
	}
	return result
}