package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

const pkgName = "mailer"

// SMTPConfig holds SMTP server configuration
type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromEmail string
	FromName  string
	UseTLS    bool
}

// Service provides email sending functionality
type Service struct {
	config    *SMTPConfig
	templates map[string]*template.Template
}

// EmailData represents data for email templates
type EmailData struct {
	ToEmail     string
	ToName      string
	Subject     string
	OTPCode     string
	AppName     string
	ExpiryTime  time.Time
	TenantName  string
	CompanyName string
}

// NewService creates a new mailer service instance
func NewService() (*Service, error) {
	config, err := loadSMTPConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load SMTP config: %w", err)
	}

	service := &Service{
		config:    config,
		templates: make(map[string]*template.Template),
	}

	// Load email templates
	if err := service.loadTemplates(); err != nil {
		log.Warn().
			Str("pkg", pkgName).
			Err(err).
			Msg("Failed to load email templates, using default templates")
	}

	return service, nil
}

// loadSMTPConfig reads SMTP configuration from environment variables
func loadSMTPConfig() (*SMTPConfig, error) {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return nil, fmt.Errorf("SMTP_HOST is required")
	}

	portStr := os.Getenv("SMTP_PORT")
	if portStr == "" {
		portStr = "587" // Default SMTP port
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	username := os.Getenv("SMTP_USERNAME")
	if username == "" {
		return nil, fmt.Errorf("SMTP_USERNAME is required")
	}

	password := os.Getenv("SMTP_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("SMTP_PASSWORD is required")
	}

	fromEmail := os.Getenv("SMTP_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = username // Default to username if not specified
	}

	fromName := os.Getenv("SMTP_FROM_NAME")
	if fromName == "" {
		fromName = "Authentication Service" // Default name
	}

	useTLSStr := os.Getenv("SMTP_USE_TLS")
	useTLS := useTLSStr == "true" || useTLSStr == "1"

	return &SMTPConfig{
		Host:      host,
		Port:      port,
		Username:  username,
		Password:  password,
		FromEmail: fromEmail,
		FromName:  fromName,
		UseTLS:    useTLS,
	}, nil
}

// loadTemplates loads email templates from embedded strings
func (s *Service) loadTemplates() error {
	// OTP verification template
	otpTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Subject}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .otp-code { background-color: #e9ecef; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; margin: 20px 0; border-radius: 5px; letter-spacing: 3px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
            <h2>Email Verification Required</h2>
        </div>
        
        <div class="content">
            <p>Hello,</p>
            
            <p>You have requested to verify your email address for <strong>{{.TenantName}}</strong>. Please use the verification code below to complete your registration:</p>
            
            <div class="otp-code">{{.OTPCode}}</div>
            
            <div class="warning">
                <strong>Important:</strong> This verification code will expire at <strong>{{.ExpiryTime.Format "Jan 2, 2006 at 3:04 PM MST"}}</strong>. 
                If you did not request this verification, please ignore this email.
            </div>
            
            <p>For your security:</p>
            <ul>
                <li>Never share this code with anyone</li>
                <li>Our team will never ask for this code</li>
                <li>If you didn't request this, please ignore this email</li>
            </ul>
            
            <p>If you have any questions, please contact our support team.</p>
            
            <p>Best regards,<br>
            The {{.CompanyName}} Team</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© {{.CompanyName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("otp").Parse(otpTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse OTP template: %w", err)
	}
	s.templates["otp"] = tmpl

	// Plain text template for fallback
	plainTemplate := `
{{.AppName}} - Email Verification

Hello,

You have requested to verify your email address for {{.TenantName}}.

Your verification code is: {{.OTPCode}}

This code will expire at {{.ExpiryTime.Format "Jan 2, 2006 at 3:04 PM MST"}}.

For your security:
- Never share this code with anyone
- Our team will never ask for this code
- If you didn't request this, please ignore this email

Best regards,
The {{.CompanyName}} Team

---
This is an automated message. Please do not reply to this email.
`

	plainTmpl, err := template.New("otp_plain").Parse(plainTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse plain text template: %w", err)
	}
	s.templates["otp_plain"] = plainTmpl

	return nil
}

// SendOTP sends an OTP verification email
func (s *Service) SendOTP(toEmail, toName, otpCode string, expiryTime time.Time, tenantName string) error {
	subject := fmt.Sprintf("Email Verification Code: %s", otpCode)

	emailData := EmailData{
		ToEmail:     toEmail,
		ToName:      toName,
		Subject:     subject,
		OTPCode:     otpCode,
		AppName:     s.config.FromName,
		ExpiryTime:  expiryTime,
		TenantName:  tenantName,
		CompanyName: s.config.FromName,
	}

	// Generate HTML content
	htmlContent, err := s.renderTemplate("otp", emailData)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("template", "otp").
			Err(err).
			Msg("Failed to render HTML template")

		// Fallback to plain text
		return s.sendPlainTextOTP(emailData)
	}

	// Generate plain text content for multipart
	plainContent, err := s.renderTemplate("otp_plain", emailData)
	if err != nil {
		log.Warn().
			Str("pkg", pkgName).
			Str("template", "otp_plain").
			Err(err).
			Msg("Failed to render plain text template, using HTML only")
		plainContent = fmt.Sprintf("Your verification code is: %s", otpCode)
	}

	// Send multipart email
	return s.sendEmail(toEmail, toName, subject, plainContent, htmlContent)
}

// sendPlainTextOTP sends a plain text OTP email as fallback
func (s *Service) sendPlainTextOTP(emailData EmailData) error {
	plainContent, err := s.renderTemplate("otp_plain", emailData)
	if err != nil {
		// Ultimate fallback - simple text
		plainContent = fmt.Sprintf(`
Email Verification Code

Your verification code is: %s

This code will expire at %s.

If you didn't request this, please ignore this email.

Best regards,
%s Team
`, emailData.OTPCode, emailData.ExpiryTime.Format("Jan 2, 2006 at 3:04 PM"), emailData.CompanyName)
	}

	return s.sendEmail(emailData.ToEmail, emailData.ToName, emailData.Subject, plainContent, "")
}

// renderTemplate renders an email template with the provided data
func (s *Service) renderTemplate(templateName string, data EmailData) (string, error) {
	tmpl, exists := s.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// sendEmail sends an email with both plain text and HTML content
func (s *Service) sendEmail(toEmail, toName, subject, plainContent, htmlContent string) error {
	// Build message
	message := s.buildMessage(toEmail, toName, subject, plainContent, htmlContent)

	// Setup authentication
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

	// Determine the server address
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Send email
	err := smtp.SendMail(addr, auth, s.config.FromEmail, []string{toEmail}, []byte(message))
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("to_email", toEmail).
			Str("smtp_host", s.config.Host).
			Int("smtp_port", s.config.Port).
			Err(err).
			Msg("Failed to send email")
		return fmt.Errorf("failed to send email to %s: %w", toEmail, err)
	}

	log.Info().
		Str("pkg", pkgName).
		Str("to_email", toEmail).
		Str("subject", subject).
		Msg("Email sent successfully")

	return nil
}

// buildMessage constructs the email message with proper headers
func (s *Service) buildMessage(toEmail, toName, subject, plainContent, htmlContent string) string {
	var message bytes.Buffer

	// Headers
	message.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.FromEmail))

	if toName != "" {
		message.WriteString(fmt.Sprintf("To: %s <%s>\r\n", toName, toEmail))
	} else {
		message.WriteString(fmt.Sprintf("To: %s\r\n", toEmail))
	}

	message.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	message.WriteString("MIME-Version: 1.0\r\n")

	if htmlContent != "" {
		// Multipart message with both plain text and HTML
		boundary := "boundary-" + fmt.Sprintf("%d", time.Now().Unix())
		message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n\r\n", boundary))

		// Plain text part
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		message.WriteString(plainContent)
		message.WriteString("\r\n\r\n")

		// HTML part
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		message.WriteString(htmlContent)
		message.WriteString("\r\n\r\n")

		// End boundary
		message.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text only
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		message.WriteString(plainContent)
	}

	return message.String()
}

// SendVerificationEmail sends a verification email with a token
func (s *Service) SendVerificationEmail(toEmail, toName, token, appName string) error {
	subject := "Verify Your Email Address"

	emailData := EmailData{
		ToEmail:     toEmail,
		ToName:      toName,
		Subject:     subject,
		OTPCode:     token, // Reusing OTPCode field for the token
		AppName:     appName,
		TenantName:  appName,
		CompanyName: appName,
	}

	// Generate HTML content
	htmlContent, err := s.renderTemplate("otp", emailData) // Reusing OTP template for now
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("template", "otp").
			Err(err).
			Msg("Failed to render HTML template for verification email")

		// Fallback to plain text
		return s.sendPlainTextVerificationEmail(emailData)
	}

	// Generate plain text content for multipart
	plainContent, err := s.renderTemplate("otp_plain", emailData) // Reusing OTP plain template
	if err != nil {
		log.Warn().
			Str("pkg", pkgName).
			Str("template", "otp_plain").
			Err(err).
			Msg("Failed to render plain text template for verification email, using HTML only")
		plainContent = fmt.Sprintf("Your verification token is: %s", token)
	}

	// Send multipart email
	return s.sendEmail(toEmail, toName, subject, plainContent, htmlContent)
}

// sendPlainTextVerificationEmail sends a plain text verification email as fallback
func (s *Service) sendPlainTextVerificationEmail(emailData EmailData) error {
	plainContent, err := s.renderTemplate("otp_plain", emailData) // Reusing OTP plain template
	if err != nil {
		// Ultimate fallback - simple text
		plainContent = fmt.Sprintf(`
Email Verification Token

Your verification token is: %s

If you didn't request this, please ignore this email.

Best regards,
%s Team
`, emailData.OTPCode, emailData.CompanyName)
	}

	return s.sendEmail(emailData.ToEmail, emailData.ToName, emailData.Subject, plainContent, "")
}

// TestConnection tests the SMTP connection
func (s *Service) TestConnection() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

	// Try to connect and authenticate
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()

	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %w", err)
	}

	log.Info().
		Str("pkg", pkgName).
		Str("smtp_host", s.config.Host).
		Int("smtp_port", s.config.Port).
		Msg("SMTP connection test successful")

	return nil
}

// GetConfig returns the current SMTP configuration (without sensitive data)
func (s *Service) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"host":       s.config.Host,
		"port":       s.config.Port,
		"username":   s.config.Username,
		"from_email": s.config.FromEmail,
		"from_name":  s.config.FromName,
		"use_tls":    s.config.UseTLS,
		"password":   "[REDACTED]",
	}
}
