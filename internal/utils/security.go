package utils

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const pkgName = "utils"

// HashPassword hashes the given password using bcrypt and returns the hashed password as a string.
// It uses the default cost of 10 for bcrypt.
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares a plaintext password with a hashed password.
// It returns true if the password matches the hash, otherwise false.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSecureToken generates a secure random token of length n.
// It uses crypto/rand to ensure the token is cryptographically secure.
// The token is returned as a base64 URL-encoded string without padding.
func GenerateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GenerateSecureToken").
			Err(err).Msg("Failed to generate random token")

		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// ExtractIPFromRemoteAddr extracts the IP address from a RemoteAddr string
// which may include a port (e.g., "192.168.1.1:12345" -> "192.168.1.1")
func ExtractIPFromRemoteAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	// Fallback for cases where SplitHostPort fails (e.g., no port present)
	return strings.Split(remoteAddr, ":")[0]
}

// IsValidEmail performs basic email format validation
func IsValidEmail(email string) bool {
	// Simple regex for basic email validation
	if len(email) > 254 || len(email) < 3 {
		return false
	}
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return false
	}
	return true
}
