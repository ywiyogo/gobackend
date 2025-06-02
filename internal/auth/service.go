package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/rs/zerolog/log"
)

var ErrAuth = errors.New("unauthorized access")

type Service struct {
	repo AuthRepository
}

func NewService(repo AuthRepository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Register(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email are required", http.StatusBadRequest)
		return fmt.Errorf("email is required")
	}
	password := r.FormValue("password")

	if password == "" || len(password) < 6 {
		http.Error(w, "Password (min 6 chars) are required", http.StatusBadRequest)
		return fmt.Errorf("password is required and must be at least 6 characters long")
	}

	// Check if email already exists
	existingUser, err := s.repo.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "Database server internal error", http.StatusInternalServerError)
		return fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return fmt.Errorf("email already exists: %s", email)
	}
	log.Debug().
		Str("pkg", pkgName).
		Str("method", "Register").
		Str("email", email).
		Msg("Hashing password and creating user")
	// Hash the password
	hashPassword, err := utils.HashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return fmt.Errorf("error hashing password: %w", err)
	}

	// Create new user
	newUser := &sqlc.User{
		Email:        email,
		PasswordHash: hashPassword,
	}

	err = s.repo.CreateUser(newUser)
	if err != nil {
		http.Error(w, "Error registering user", http.StatusInternalServerError)
		return fmt.Errorf("error registering user: %w", err)
	}

	fmt.Fprintf(w, "User with email %s registered successfully!", email)

	return nil
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	password := r.FormValue("password")
	userAgent := r.UserAgent()
	ipAddress := r.RemoteAddr
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("error retrieving user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid email: %s", email)
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return fmt.Errorf("invalid password for email: %s", email)
	}
	// Delete existing sessions for this user, user agent, and IP address
	err = s.repo.DeleteSessionsByDevice(r.Context(), user.ID, userAgent, ipAddress)
	if err != nil {
		return fmt.Errorf("error removing old session: %w", err)
	}

	// Create session
	// Generate a session token and store it in the sessions table
	sessionToken, err := utils.GenerateSecureToken(32) // 32 bytes token
	if err != nil {
		http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate session token: %w", err)
	}

	// Generate CSRF token
	csrfToken, err := utils.GenerateSecureToken(32) // 32 bytes CSRF token
	if err != nil {
		http.Error(w, "Failed to generate CSRF session token", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate CSRF session token: %w", err)
	}

	expiration := time.Now().Add(24 * time.Hour)
	sessionRow, err := s.repo.CreateSession(context.Background(), user.ID, sessionToken, csrfToken, userAgent, ipAddress, expiration)
	if err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return fmt.Errorf("error creating session: %w", err)
	}
	log.Debug().
		Str("pkg", pkgName).
		Str("method", "Login").
		Str("email", email).
		Str("sessionID", fmt.Sprintf("%v", sessionRow)).
		Msg("Session created successfully")

	// Set session cookie with session ID
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	// Return CSRF token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": csrfToken,
	})
	return nil
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) error {
	userID, err := s.repo.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return fmt.Errorf("unauthorized access: %w", err)
	}

	userAgent := r.UserAgent()
	ip := r.RemoteAddr

	err = s.repo.DeleteSessionsByDevice(r.Context(), userID, userAgent, ip)
	if err != nil {
		http.Error(w, "error logging out", http.StatusInternalServerError)
		return fmt.Errorf("error logging out: %w", err)
	}

	// Clear the session token for the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)

	return nil
}

// SendOTPEmail sends an OTP to the specified email address
// This is a placeholder implementation. In a real application,
// you would use an SMTP library like "github.com/jordan-wright/email"
// to send actual emails.
func SendOTPEmail(emailAddr, otp string) error {
	// In a real implementation, you would configure SMTP settings
	// from environment variables or a configuration file.
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		fmt.Printf("SMTP configuration incomplete. Logging OTP email instead.\n")
		fmt.Printf("Sending OTP %s to %s\n", otp, emailAddr)
		return nil
	}

	// Placeholder for actual email sending logic
	fmt.Printf("Sending OTP %s to %s via SMTP (placeholder)\n", otp, emailAddr)
	return nil
}
