package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/mailer"
	"gobackend/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
)

var ErrAuth = errors.New("unauthorized access")

type Service struct {
	repo   AuthRepository
	mailer mailer.Mailer
}

type OTPSession struct {
	Email     string
	OTPCode   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewService(repo AuthRepository) *Service {
	// Initialize mailer service
	mailerService, err := mailer.NewMailer()
	if err != nil {
		// Log error but don't fail - fallback to mock mailer
		mailerService = mailer.NewMockMailer()
	}

	return &Service{
		repo:   repo,
		mailer: mailerService,
	}
}

// NewServiceWithMailer creates a new auth service with a specific mailer instance
func NewServiceWithMailer(repo AuthRepository, mailerService mailer.Mailer) *Service {
	return &Service{
		repo:   repo,
		mailer: mailerService,
	}
}

// Multi-tenant authentication methods

// RegisterWithPasswordInTenant registers a new user with password in a specific tenant
func (s *Service) RegisterWithPasswordInTenant(ctx context.Context, email, password string, tenantID uuid.UUID) (*sqlc.User, error) {
	// Check if user exists in this tenant
	existingUser, err := s.repo.GetUserByEmailAndTenant(ctx, email, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		return nil, fmt.Errorf("user already exists in this application")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	// Create user
	user := &sqlc.User{
		ID:           uuid.New(),
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		Email:        email,
		PasswordHash: pgtype.Text{String: hashedPassword, Valid: true},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.CreateUserInTenant(ctx, user); err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return user, nil
}

// RegisterWithOTPInTenant registers a new user with OTP in a specific tenant and sends OTP email
func (s *Service) RegisterWithOTPInTenant(ctx context.Context, email string, tenantID uuid.UUID, tenantName string) (*sqlc.User, string, error) {
	// Check if user exists in this tenant
	existingUser, err := s.repo.GetUserByEmailAndTenant(ctx, email, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		return nil, "", fmt.Errorf("user already exists in this application")
	}

	// Generate OTP
	otpCode := utils.GenerateOTP(6)
	otpExpiry := time.Now().Add(15 * time.Minute)

	// Create user with OTP
	user := &sqlc.User{
		ID:           uuid.New(),
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		Email:        email,
		Otp:          pgtype.Text{String: otpCode, Valid: true},
		OtpExpiresAt: pgtype.Timestamptz{Time: otpExpiry, Valid: true},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.CreateUserInTenant(ctx, user); err != nil {
		return nil, "", fmt.Errorf("error creating user: %w", err)
	}

	// Send OTP email
	if err := s.mailer.SendOTP(email, "", otpCode, otpExpiry, tenantName); err != nil {
		// Log error but don't fail the registration - user can still verify manually
		fmt.Printf("Warning: Failed to send OTP email to %s: %v\n", email, err)
	}

	return user, otpCode, nil
}

// LoginWithPasswordInTenant authenticates a user with password in a specific tenant
func (s *Service) LoginWithPasswordInTenant(ctx context.Context, email, password string, tenantID uuid.UUID) (*sqlc.User, error) {
	user, err := s.repo.GetUserByEmailAndTenant(ctx, email, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !HasPassword(user) {
		return nil, fmt.Errorf("password login not available for this user")
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash.String) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// LoginWithOTPInTenant generates OTP for an existing user in a specific tenant and sends OTP email
func (s *Service) LoginWithOTPInTenant(ctx context.Context, email string, tenantID uuid.UUID, tenantName string) (*sqlc.User, string, error) {
	// Get user by email in this tenant
	user, err := s.repo.GetUserByEmailAndTenant(ctx, email, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("error getting user: %w", err)
	}
	if user == nil {
		return nil, "", fmt.Errorf("user not found in this application")
	}

	// Generate new OTP
	otpCode := utils.GenerateOTP(6)
	otpExpiry := time.Now().Add(15 * time.Minute)

	// Set OTP for user
	if err := s.repo.SetUserOTPInTenant(ctx, user.ID, uuid.UUID(user.TenantID.Bytes), otpCode, otpExpiry); err != nil {
		return nil, "", fmt.Errorf("error setting OTP: %w", err)
	}

	// Update user model
	user.Otp = pgtype.Text{String: otpCode, Valid: true}
	user.OtpExpiresAt = pgtype.Timestamptz{Time: otpExpiry, Valid: true}

	// Send OTP email
	if err := s.mailer.SendOTP(email, "", otpCode, otpExpiry, tenantName); err != nil {
		// Log error but don't fail the login - user can still verify manually
		fmt.Printf("Warning: Failed to send OTP email to %s: %v\n", email, err)
	}

	return user, otpCode, nil
}

// CreateSessionInTenant creates a new session for a user in a specific tenant
func (s *Service) CreateSessionInTenant(ctx context.Context, userID, tenantID uuid.UUID, userAgent, ip string) (*sqlc.Session, error) {
	sessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("error generating session token: %w", err)
	}

	csrfToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("error generating CSRF token: %w", err)
	}

	session := &sqlc.Session{
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		UserID:       userID,
		SessionToken: sessionToken,
		CsrfToken:    csrfToken,
		UserAgent:    userAgent,
		Ip:           ip,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.CreateSessionInTenant(ctx, session); err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	return session, nil
}

// ValidateSessionInTenant validates a session token within a specific tenant
func (s *Service) ValidateSessionInTenant(ctx context.Context, sessionToken string, tenantID uuid.UUID) (*sqlc.Session, error) {
	session, err := s.repo.GetSessionByTokenAndTenant(ctx, sessionToken, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error getting session: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("invalid session")
	}

	if IsSessionExpired(session) {
		// Clean up expired session
		_ = s.repo.DeleteSessionByIDAndTenant(ctx, session.ID, tenantID)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// VerifyOTPInTenant verifies OTP and updates session in a specific tenant
func (s *Service) VerifyOTPInTenant(ctx context.Context, sessionToken, otpCode string, tenantID uuid.UUID) (*sqlc.Session, error) {

	// Get current session
	session, err := s.ValidateSessionInTenant(ctx, sessionToken, tenantID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTPInTenant").
			Str("session_token", sessionToken[:8]+"...").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Session validation failed")
		return nil, err
	}

	// Validate OTP
	isValid, err := s.repo.ValidateOTPInTenant(ctx, session.UserID, tenantID, otpCode)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTPInTenant").
			Str("user_id", session.UserID.String()).
			Str("tenant_id", tenantID.String()).
			Str("otp", otpCode).
			Err(err).
			Msg("OTP validation error")
		return nil, fmt.Errorf("error validating OTP: %w", err)
	}
	if !isValid {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTPInTenant").
			Str("user_id", session.UserID.String()).
			Str("tenant_id", tenantID.String()).
			Str("otp", otpCode).
			Msg("OTP validation failed - codes do not match")
		return nil, fmt.Errorf("invalid OTP code")
	}

	log.Info().
		Str("pkg", pkgName).
		Str("method", "VerifyOTPInTenant").
		Str("user_id", session.UserID.String()).
		Str("tenant_id", tenantID.String()).
		Msg("OTP verification successful")

	// Clear OTP after successful verification
	_ = s.repo.ClearUserOTPInTenant(ctx, session.UserID, tenantID)

	// Generate new session token for security
	newSessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("error generating new session token: %w", err)
	}

	// Delete old session and create new one
	_ = s.repo.DeleteSessionByIDAndTenant(ctx, session.ID, tenantID)

	newSession := &sqlc.Session{
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		UserID:       session.UserID,
		SessionToken: newSessionToken,
		CsrfToken:    session.CsrfToken,
		UserAgent:    session.UserAgent,
		Ip:           session.Ip,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.CreateSessionInTenant(ctx, newSession); err != nil {
		return nil, fmt.Errorf("error creating new session: %w", err)
	}

	return newSession, nil
}

// LogoutInTenant logs out a user from a specific tenant
func (s *Service) LogoutInTenant(ctx context.Context, sessionToken string, tenantID uuid.UUID, allDevices bool) error {
	session, err := s.repo.GetSessionByTokenAndTenant(ctx, sessionToken, tenantID)
	if err != nil {
		return fmt.Errorf("error getting session: %w", err)
	}
	if session == nil {
		return fmt.Errorf("session not found")
	}

	if allDevices {
		// Delete all sessions for the user in this tenant
		return s.repo.DeleteSessionByUserIDAndTenant(ctx, session.UserID, tenantID)
	} else {
		// Delete only current session
		return s.repo.DeleteSessionByIDAndTenant(ctx, session.ID, tenantID)
	}
}

// GetUserSessionsInTenant retrieves all sessions for a user in a specific tenant
func (s *Service) GetUserSessionsInTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*sqlc.Session, error) {
	return s.repo.GetSessionsByUserIDAndTenant(ctx, userID, tenantID)
}

// RequestOTPInTenant generates and sets OTP for a user in a specific tenant
func (s *Service) RequestOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) (string, error) {
	otpCode := utils.GenerateOTP(6)
	expiresAt := time.Now().Add(15 * time.Minute)

	err := s.repo.SetUserOTPInTenant(ctx, userID, tenantID, otpCode, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to set OTP: %w", err)
	}

	return otpCode, nil
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

	// Generate new session token after successful OTP verification
	newSessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("error generating new session token: %w", err)
	}

	// Update the session with the new token and extend expiration
	newExpiresAt := time.Now().Add(24 * time.Hour)
	err = s.repo.UpdateSessionToken(ctx, session.ID, newSessionToken, newExpiresAt)
	if err != nil {
		return "", fmt.Errorf("error updating session: %w", err)
	}

	return newSessionToken, nil
}

func (s *Service) Register(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return fmt.Errorf("email is required")
	}
	if !utils.IsValidEmail(email) {
		http.Error(w, "invalid email format", http.StatusBadRequest)
		return fmt.Errorf("invalid email format: %s", email)
	}

	// Check if email already exists
	userExists, err := s.repo.UserExistsByEmail(r.Context(), email)
	if err != nil {
		return fmt.Errorf("error checking existing user: %w", err)
	}

	if os.Getenv("OTP_ENABLED") == "true" {
		// OTP flow - create user with OTP and temporary session
		otpCode := s.GenerateAndStoreOTP(r)
		if otpCode == "" {
			return fmt.Errorf("error generating OTP: %w", err)
		}

		// Generate session tokens for OTP verification
		sessionToken, csrfToken, err := s.GenerateSessionTokens(r)
		if sessionToken == "" || csrfToken == "" || err != nil {
			return fmt.Errorf("error generating session tokens: %w. sessionToken:%s, csrfToken:%s", err, sessionToken, csrfToken)
		}

		// Set temporary session cookie for OTP verification
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			HttpOnly: true,
			Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
			Expires:  time.Now().Add(24 * time.Hour),
		})

		return nil
	} else {
		// Password flow - check if user already exists
		if userExists {
			http.Error(w, "email already exists", http.StatusConflict)
			return fmt.Errorf("email already exists: %s", email)
		}

		password := r.FormValue("password")
		if password == "" || len(password) < 6 {
			http.Error(w, "invalid password format", http.StatusBadRequest)
			return fmt.Errorf("invalid password format")
		}

		// Hash the password
		hashPassword, err := utils.HashPassword(password)
		if err != nil {
			return fmt.Errorf("error hashing password: %w", err)
		}

		// Convert to pgtype.Text
		passwordHash := pgtype.Text{}
		if err := passwordHash.Scan(hashPassword); err != nil {
			return fmt.Errorf("error processing password: %w", err)
		}

		// Create new user with password
		newUser := &sqlc.User{
			Email:        email,
			PasswordHash: passwordHash,
		}
		err = s.repo.CreateUserWithPassword(newUser)
		if err != nil {
			return fmt.Errorf("error registering user: %w", err)
		}

		// Password registration doesn't create session - user must login separately
		return nil
	}
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
	otpExpiresAt := time.Now().Add(15 * time.Minute)
	// Check if email already exists
	existingUser, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return ""
	}
	// Check if email doesn't exist yet
	if existingUser == nil {
		existingUser := &sqlc.User{
			Email: email,
			Otp: pgtype.Text{
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

func (s *Service) GetCSRFTokenBySessionToken(ctx context.Context, sessionToken string) (string, error) {
	return s.repo.GetCsrfTokenBySessionToken(ctx, sessionToken)
}
