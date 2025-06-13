package mailer

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// NewMailer creates a new mailer service based on environment configuration
func NewMailer() (Mailer, error) {
	env := strings.ToLower(os.Getenv("ENV"))
	smtpHost := os.Getenv("SMTP_HOST")

	// Use mock service in development/test environments or when SMTP is not configured
	if env == "development" || env == "test" || smtpHost == "" {
		log.Info().
			Str("pkg", pkgName).
			Str("environment", env).
			Str("smtp_host", smtpHost).
			Msg("Using mock mailer service")

		return NewMockService(), nil
	}

	// Use real SMTP service in production or when explicitly configured
	log.Info().
		Str("pkg", pkgName).
		Str("environment", env).
		Str("smtp_host", smtpHost).
		Msg("Using real SMTP mailer service")

	service, err := NewService()
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Err(err).
			Msg("Failed to create SMTP mailer service, falling back to mock")

		return NewMockService(), nil
	}

	// Test the connection in production
	if env == "production" {
		if err := service.TestConnection(); err != nil {
			log.Error().
				Str("pkg", pkgName).
				Err(err).
				Msg("SMTP connection test failed in production")
			return nil, fmt.Errorf("SMTP connection test failed in production: %w", err)
		}
	}

	return service, nil
}

// NewRealMailer creates a real SMTP mailer service (for testing or explicit usage)
func NewRealMailer() (Mailer, error) {
	return NewService()
}

// NewMockMailer creates a mock mailer service (for testing or explicit usage)
func NewMockMailer() Mailer {
	return NewMockService()
}
