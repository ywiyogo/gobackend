package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrAuth = errors.New("unauthorized access")

type Service struct {
	repo AuthRepository
}

type OTPSession struct {
	Email     string
	OTPCode   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewService(repo AuthRepository) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) VerifyOTP(ctx context.Context, sessionToken string, otpCode string) (string, error) {
	session, err := s.repo.GetSessionRowByToken(ctx, sessionToken)
	if err != nil {
		return "", fmt.Errorf("invalid session")
	}
	if time.Now().After(session.ExpiresAt) {
		// Delete all sessions for this user
		err = s.repo.DeleteSessionByUserID(ctx, session.UserID)
		if err != nil {
			return "", fmt.Errorf("error deleting sessions: %w", err)
		}
		return "", fmt.Errorf("session expired")
	}
	dbOtpCode, _, err := s.repo.GetUserOTP(ctx, session.UserID)
	if err != nil {
		return "", fmt.Errorf("error retrieving OTP code: %w", err)
	}
	if dbOtpCode != otpCode {
		return "", fmt.Errorf("invalid OTP code")
	}

	// Generate auth token
	authToken := uuid.New().String()

	return authToken, nil
}

func (s *Service) Register(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email are required", http.StatusBadRequest)
		return fmt.Errorf("email is required")
	}
	fmt.Println("Registering user with email:", email)
	if !utils.IsValidEmail(email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return fmt.Errorf("invalid email format: %s", email)
	}

	// Check if email already exists
	existingUser, err := s.repo.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "Database server internal error", http.StatusInternalServerError)
		return fmt.Errorf("error checking existing user: %w", err)
	}

	if os.Getenv("OTP_ENABLED") == "true" {
		// If OTP is enabled, create user without password, but OTP
		otpCode := s.GenerateAndStoreOTP(r)

		if otpCode == "" {
			http.Error(w, "Error generating OTP", http.StatusInternalServerError)
			return fmt.Errorf("error generating OTP: %w", err)
		}

		// If user doesn't exist, create a new user with OTP
		// fmt.Fprintf(w, "OTP sent to %s: %s\n", email, otpCode)
		sessionToken, csrfToken, err := s.GenerateSessionTokens(r)
		if sessionToken == "" || csrfToken == "" || err != nil {
			http.Error(w, "Error generating session tokens", http.StatusInternalServerError)
			return fmt.Errorf("error generating session tokens: %w. sessionToken:%s, csrfToken:%s", err, sessionToken, csrfToken)
		}
		// Do not call fmt.Fprintf with http.ResponseWriter, otherwise SetCookie won't work
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			HttpOnly: true,
			Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
			Expires:  time.Now().Add(24 * time.Hour),
		})

		fmt.Fprintf(w, "Setting cookie with session token: %s, CSRF: %s.\n OTP: %s", sessionToken, csrfToken, otpCode)
		return nil
	} else {
		if existingUser != nil {
			http.Error(w, "Email already exists", http.StatusConflict)
			return fmt.Errorf("email already exists: %s", email)
		}
		password := r.FormValue("password")
		if password == "" || len(password) < 6 {
			http.Error(w, "Password (min 6 chars) are required", http.StatusBadRequest)
			return fmt.Errorf("invalid password format")
		}
		// Hash the password
		hashPassword, err := utils.HashPassword(password)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return fmt.Errorf("error hashing password: %w", err)
		}
		// Convert to pgtype.Text
		passwordHash := pgtype.Text{}
		if err := passwordHash.Scan(hashPassword); err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return fmt.Errorf("error processing password: %w", err)
		}

		// Create new user
		existingUser := &sqlc.User{
			Email:        email,
			PasswordHash: passwordHash,
		}
		err = s.repo.CreateUserWithPassword(existingUser)
		if err != nil {
			http.Error(w, "Error registering user", http.StatusInternalServerError)
			return fmt.Errorf("error registering user: %w", err)
		}
		// registration with password doesn't need session tokens, since it's handled by the login flow
	}

	return nil
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")

	userAgent := r.UserAgent()
	ipAddress := utils.ExtractIPFromRemoteAddr(r.RemoteAddr)

	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("error retrieving user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid email: %s", email)
	}
	otpCode := ""
	// Handle OTP flow if enabled
	if os.Getenv("OTP_ENABLED") == "true" {
		otp := r.FormValue("otp")
		if otp == "" {
			otpCode = s.GenerateAndStoreOTP(r)
			if otpCode == "" {
				http.Error(w, "Error generating OTP", http.StatusInternalServerError)
				return fmt.Errorf("error generating OTP: %w", err)
			}
		}
	} else {
		// Standard password flow
		password := r.FormValue("password")
		if err := s.validatePassword(user, password); err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return fmt.Errorf("invalid password for email: %s", email)
		}
	}

	// Delete existing sessions for this user, user agent, and IP address
	err = s.repo.DeleteSessionsByDevice(r.Context(), user.ID, userAgent, ipAddress)
	if err != nil {
		return fmt.Errorf("error removing old session: %w", err)
	}

	// Create session and CSRF tokens
	sessionToken, csrfToken, err := s.GenerateSessionTokens(r)
	if sessionToken == "" || csrfToken == "" || err != nil {
		http.Error(w, "Error generating session tokens", http.StatusInternalServerError)
		return fmt.Errorf("error generating session tokens")
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})
	fmt.Fprintf(w, "User with email %s logged in successfully! \nsessionToken: %s, CSRF: %s.\n", email, sessionToken, csrfToken)
	fmt.Fprintf(w, "OTP code: %s", otpCode)
	return nil
}

func (s *Service) RequestOTP(ctx context.Context, userID uuid.UUID) (string, error) {
	otpCode := utils.GenerateOTP(6)
	expiresAt := time.Now().Add(5 * time.Minute)

	err := s.repo.SetUserOTP(ctx, userID, otpCode, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to set OTP: %w", err)
	}

	return otpCode, nil
}

// validatePassword checks if the provided password matches the user's stored hash
func (s *Service) validatePassword(user *sqlc.User, password string) error {
	if !user.PasswordHash.Valid {
		return fmt.Errorf("no password set for user")
	}
	if !utils.CheckPasswordHash(password, user.PasswordHash.String) {
		return fmt.Errorf("password mismatch")
	}
	return nil
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) error {
	// Get session token from cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return fmt.Errorf("no session token found: %w", err)
	}

	// Get user ID from session token
	userID, err := s.repo.GetUserIDByToken(r.Context(), cookie.Value)
	if err != nil {
		fmt.Fprintf(w, "error getting user ID from session: %v", err)
		email := r.FormValue("email")
		if email != "" {
			user, err := s.repo.GetUserByEmail(email)
			if err != nil {
				return fmt.Errorf("error retrieving user by email: %w", err)
			}
			userID = user.ID
		}
	}

	// Delete all sessions for this user
	err = s.repo.DeleteSessionByUserID(r.Context(), userID)
	if err != nil {
		return fmt.Errorf("error deleting sessions: %w", err)
	}
	s.ClearOTP(r.Context(), userID)
	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

func (s *Service) ClearOTP(ctx context.Context, userID uuid.UUID) error {
	return s.repo.ClearUserOTP(ctx, userID)
}

func (s *Service) GenerateAndStoreOTP(r *http.Request) string {
	email := r.FormValue("email")
	otpCode := utils.GenerateOTP(6)
	otpExpiresAt := time.Now().Add(5 * time.Minute)
	// Check if email already exists
	existingUser, err := s.repo.GetUserByEmail(email)
	if err != nil {
		fmt.Println("Error checking existing user:", err)
		return ""
	}
	// Check if email doesn't exist yet
	if existingUser == nil {
		existingUser := &sqlc.User{
			Email: email,
			OtpCode: pgtype.Text{
				String: otpCode,
				Valid:  true,
			},
			OtpExpiresAt: pgtype.Timestamptz{
				Time:  otpExpiresAt,
				Valid: true,
			},
		}
		err = s.repo.CreateUserWithOtp(existingUser)
		if err != nil {
			fmt.Println("Error creating user with OTP:", err)
			return ""
		}

		if err != nil {
			fmt.Println("Error retrieving newly created user:", err)
			return ""
		}

	} else {
		// If user already exists, update OTP code and expiration
		err = s.repo.SetUserOTP(r.Context(), existingUser.ID, otpCode, otpExpiresAt)
		if err != nil {
			return ""
		}
	}

	return otpCode

}

func (s *Service) GenerateSessionTokens(r *http.Request) (string, string, error) {
	sessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return "", "", fmt.Errorf("error generating session token: %w", err)
	}
	csrfToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return "", "", fmt.Errorf("error generating CSRF token: %w", err)
	}
	userAgent := r.UserAgent()
	ipAddress := utils.ExtractIPFromRemoteAddr(r.RemoteAddr)

	expiresAt := time.Now().Add(24 * time.Hour)
	email := r.FormValue("email")
	if email == "" {
		return "", "", fmt.Errorf("email is required for session creation")
	}
	user, err := s.repo.GetUserByEmail(email)
	if err != nil || user == nil {
		return "", "", fmt.Errorf("error retrieving user by email: %w", err)
	}

	_, err = s.repo.CreateSession(r.Context(), user.ID, sessionToken, csrfToken, userAgent, ipAddress, expiresAt)
	if err != nil {
		return "", "", fmt.Errorf("error creating session: %w", err)
	}

	return sessionToken, csrfToken, nil
}
