// Package repository provides the implementation of user data operations
// implementing the Repository pattern on top of SQLC, that’s a clean abstraction for decoupling business logic from database access.

package auth

import (
	"context"
	"errors"
	"fmt"
	"gobackend/internal/db/sqlc"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const pkgName = "auth"

// AuthRepository defines the interface for user data operations
type AuthRepository interface {
	// Legacy methods (keep for backward compatibility)
	CreateUserWithPassword(user *sqlc.User) error
	GetUserByEmail(email string) (*sqlc.User, error)
	CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ip string, expiresAt time.Time) (sqlc.Session, error)
	GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error)
	Authorize(r *http.Request) (uuid.UUID, error)
	GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error)
	GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error)
	DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error
	UpdateSessionToken(ctx context.Context, sessionID int64, sessionToken string, expiresAt time.Time) error
	UserExistsByEmail(ctx context.Context, email string) (bool, error)
	// OTP methods
	CreateUserWithOtp(user *sqlc.User) error
	SetUserOTP(ctx context.Context, userID uuid.UUID, otpCode string, expiresAt time.Time) error
	GetUserOTP(ctx context.Context, userID uuid.UUID) (string, time.Time, error)
	ClearUserOTP(ctx context.Context, userID uuid.UUID) error
	ValidateOTP(ctx context.Context, userID uuid.UUID, otp string) (bool, error)

	// Multi-tenant methods
	GetUserByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (*sqlc.User, error)
	GetUserByIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*sqlc.User, error)
	CreateUserInTenant(ctx context.Context, user *sqlc.User) error
	CreateSessionInTenant(ctx context.Context, session *sqlc.Session) error
	GetSessionByTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.Session, error)
	UserExistsByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (bool, error)
	SetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otpCode string, expiresAt time.Time) error
	GetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) (string, time.Time, error)
	ClearUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) error
	ValidateOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otp string) (bool, error)
	DeleteSessionByIDAndTenant(ctx context.Context, sessionID int64, tenantID uuid.UUID) error
	DeleteSessionByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) error
	DeleteSessionsByDeviceAndTenant(ctx context.Context, tenantID, userID uuid.UUID, userAgent, ip string) error
	GetSessionsByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*sqlc.Session, error)
	GetUserByVerificationTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.User, error)
	UpdateUserEmailVerified(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, verified bool) error
	ClearVerificationToken(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error
}

// UserRepo implements AuthRepository
type UserRepo struct {
	queries *sqlc.Queries
}

// NewUserRepository creates a new instance of UserRepo
func NewAuthRepository(queries *sqlc.Queries) AuthRepository {
	return &UserRepo{queries: queries}
}

// CreateUser adds a new user to the database
func (r *UserRepo) CreateUserWithPassword(user *sqlc.User) error {
	_, err := r.queries.CreateUserWithPassword(context.Background(), sqlc.CreateUserWithPasswordParams{
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateUser").
			Str("email", user.Email).
			Err(err).
			Msg("DB operation failed")
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// ValidateOTP checks if the provided OTP matches the stored one and is not expired
func (r *UserRepo) ValidateOTP(ctx context.Context, userID uuid.UUID, otp string) (bool, error) {

	otpRecord, err := r.queries.GetUserOTP(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get user OTP: %w", err)
	}

	// Convert pgtype.Text to string
	var storedOTP string
	if err := otpRecord.Otp.Scan(&storedOTP); err != nil {
		return false, fmt.Errorf("failed to read OTP code: %w", err)
	}

	// Check if OTP is valid and not expired
	if storedOTP == "" || !otpRecord.OtpExpiresAt.Valid || time.Now().After(otpRecord.OtpExpiresAt.Time) {
		return false, nil
	}

	return storedOTP == otp, nil
}

// Multi-tenant repository methods

// GetUserByEmailAndTenant retrieves a user by email within a specific tenant
func (r *UserRepo) GetUserByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (*sqlc.User, error) {
	userRow, err := r.queries.GetUserByEmailAndTenant(ctx, sqlc.GetUserByEmailAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Email:    email,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetUserByEmailAndTenant").
			Str("email", email).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get user by email and tenant: %w", err)
	}

	user := &sqlc.User{
		ID:           userRow.ID,
		TenantID:     userRow.TenantID,
		Email:        userRow.Email,
		PasswordHash: userRow.PasswordHash,
		Otp:          userRow.Otp,
		OtpExpiresAt: userRow.OtpExpiresAt,
		CreatedAt:    userRow.CreatedAt,
		UpdatedAt:    userRow.UpdatedAt,
	}

	return user, nil
}

// GetUserByIDAndTenant retrieves a user by ID within a specific tenant
func (r *UserRepo) GetUserByIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*sqlc.User, error) {
	userRow, err := r.queries.GetUserByIDAndTenant(ctx, sqlc.GetUserByIDAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetUserByIDAndTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get user by ID and tenant: %w", err)
	}

	user := &sqlc.User{
		ID:           userRow.ID,
		TenantID:     userRow.TenantID,
		Email:        userRow.Email,
		PasswordHash: userRow.PasswordHash,
		Otp:          userRow.Otp,
		OtpExpiresAt: userRow.OtpExpiresAt,
		CreatedAt:    userRow.CreatedAt,
		UpdatedAt:    userRow.UpdatedAt,
	}

	return user, nil
}

// CreateUserInTenant creates a new user within a specific tenant
func (r *UserRepo) CreateUserInTenant(ctx context.Context, user *sqlc.User) error {
	if user.PasswordHash.Valid && user.PasswordHash.String != "" {
		createdUser, err := r.queries.CreateUserWithPasswordInTenant(ctx, sqlc.CreateUserWithPasswordInTenantParams{
			TenantID:     user.TenantID,
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
		})
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "CreateUserInTenant").
				Str("email", user.Email).
				Str("tenant_id", uuid.UUID(user.TenantID.Bytes).String()).
				Err(err).
				Msg("Failed to create user with password")
			return fmt.Errorf("failed to create user with password in tenant: %w", err)
		}
		// Update the user object with the database-generated values
		*user = createdUser
	} else {
		createdUser, err := r.queries.CreateUserWithOtpInTenant(ctx, sqlc.CreateUserWithOtpInTenantParams{
			TenantID:     user.TenantID,
			Email:        user.Email,
			Otp:          user.Otp,
			OtpExpiresAt: user.OtpExpiresAt,
		})
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "CreateUserInTenant").
				Str("email", user.Email).
				Str("tenant_id", uuid.UUID(user.TenantID.Bytes).String()).
				Err(err).
				Msg("Failed to create user with OTP")
			return fmt.Errorf("failed to create user with OTP in tenant: %w", err)
		}
		// Update the user object with the database-generated values
		*user = createdUser
	}

	return nil
}

// CreateSessionInTenant creates a new session within a specific tenant
func (r *UserRepo) CreateSessionInTenant(ctx context.Context, session *sqlc.Session) error {
	_, err := r.queries.CreateSessionInTenant(ctx, sqlc.CreateSessionInTenantParams{
		TenantID:     session.TenantID,
		UserID:       session.UserID,
		SessionToken: session.SessionToken,
		CsrfToken:    session.CsrfToken,
		UserAgent:    session.UserAgent,
		Ip:           session.Ip,
		ExpiresAt:    session.ExpiresAt,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateSessionInTenant").
			Str("user_id", session.UserID.String()).
			Str("tenant_id", uuid.UUID(session.TenantID.Bytes).String()).
			Err(err).
			Msg("Failed to create session")
		return fmt.Errorf("failed to create session in tenant: %w", err)
	}

	return nil
}

// GetSessionByTokenAndTenant retrieves a session by token within a specific tenant
func (r *UserRepo) GetSessionByTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.Session, error) {
	sessionRow, err := r.queries.GetSessionByTokenAndTenant(ctx, sqlc.GetSessionByTokenAndTenantParams{
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		SessionToken: token,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetSessionByTokenAndTenant").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get session by token and tenant: %w", err)
	}

	session := &sqlc.Session{
		ID:           sessionRow.ID,
		TenantID:     sessionRow.TenantID,
		UserID:       sessionRow.UserID,
		SessionToken: sessionRow.SessionToken,
		CsrfToken:    sessionRow.CsrfToken,
		UserAgent:    sessionRow.UserAgent,
		Ip:           sessionRow.Ip,
		ExpiresAt:    sessionRow.ExpiresAt,
		CreatedAt:    sessionRow.CreatedAt,
	}

	return session, nil
}

// UserExistsByEmailAndTenant checks if a user exists by email within a specific tenant
func (r *UserRepo) UserExistsByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (bool, error) {
	exists, err := r.queries.UserExistsByEmailAndTenant(ctx, sqlc.UserExistsByEmailAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Email:    email,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "UserExistsByEmailAndTenant").
			Str("email", email).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return false, fmt.Errorf("failed to check user existence by email and tenant: %w", err)
	}
	return exists, nil
}

// SetUserOTPInTenant sets OTP for a user within a specific tenant
func (r *UserRepo) SetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otpCode string, expiresAt time.Time) error {
	err := r.queries.SetUserOTPInTenant(ctx, sqlc.SetUserOTPInTenantParams{
		ID:           userID,
		TenantID:     pgtype.UUID{Bytes: tenantID, Valid: true},
		Otp:          pgtype.Text{String: otpCode, Valid: true},
		OtpExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "SetUserOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to set OTP")
		return fmt.Errorf("failed to set OTP in tenant: %w", err)
	}
	return nil
}

// GetUserOTPInTenant retrieves OTP for a user within a specific tenant
func (r *UserRepo) GetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) (string, time.Time, error) {
	otpRow, err := r.queries.GetUserOTPInTenant(ctx, sqlc.GetUserOTPInTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetUserOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to get OTP")
		return "", time.Time{}, fmt.Errorf("failed to get OTP in tenant: %w", err)
	}

	return otpRow.Otp.String, otpRow.OtpExpiresAt.Time, nil
}

// ClearUserOTPInTenant clears OTP for a user within a specific tenant
func (r *UserRepo) ClearUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	err := r.queries.ClearUserOTPInTenant(ctx, sqlc.ClearUserOTPInTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       userID,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "ClearUserOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to clear OTP")
		return fmt.Errorf("failed to clear OTP in tenant: %w", err)
	}
	return nil
}

// ValidateOTPInTenant validates OTP for a user within a specific tenant
func (r *UserRepo) ValidateOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otp string) (bool, error) {

	otpCode, expiresAt, err := r.GetUserOTPInTenant(ctx, userID, tenantID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "ValidateOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to get OTP from database")
		return false, err
	}

	if otpCode == "" {
		log.Warn().
			Str("pkg", pkgName).
			Str("method", "ValidateOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Msg("No OTP found for user in tenant")
		return false, nil
	}

	if time.Now().After(expiresAt) {
		log.Warn().
			Str("pkg", pkgName).
			Str("method", "ValidateOTPInTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Time("expires_at", expiresAt).
			Msg("OTP has expired")
		return false, nil
	}

	isMatch := otpCode == otp

	return isMatch, nil
}

// DeleteSessionByIDAndTenant deletes a session by ID within a specific tenant
func (r *UserRepo) DeleteSessionByIDAndTenant(ctx context.Context, sessionID int64, tenantID uuid.UUID) error {
	_, err := r.queries.DeleteSessionByIDAndTenant(ctx, sqlc.DeleteSessionByIDAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       sessionID,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "DeleteSessionByIDAndTenant").
			Int64("session_id", sessionID).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to delete session")
		return fmt.Errorf("failed to delete session by ID and tenant: %w", err)
	}

	return nil
}

// DeleteSessionByUserIDAndTenant deletes all sessions for a user within a specific tenant
func (r *UserRepo) DeleteSessionByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	_, err := r.queries.DeleteSessionByUserIDAndTenant(ctx, sqlc.DeleteSessionByUserIDAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "DeleteSessionByUserIDAndTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to delete user sessions")
		return fmt.Errorf("failed to delete sessions by user ID and tenant: %w", err)
	}
	log.Info().
		Str("pkg", pkgName).
		Str("method", "DeleteSessionByUserIDAndTenant").
		Str("user_id", userID.String()).
		Str("tenant_id", tenantID.String()).
		Msg("User sessions deleted successfully")

	return nil
}

// DeleteSessionsByDeviceAndTenant deletes sessions for a specific device within a tenant
func (r *UserRepo) DeleteSessionsByDeviceAndTenant(ctx context.Context, tenantID, userID uuid.UUID, userAgent, ip string) error {
	_, err := r.queries.DeleteSessionsByDeviceAndTenant(ctx, sqlc.DeleteSessionsByDeviceAndTenantParams{
		TenantID:  pgtype.UUID{Bytes: tenantID, Valid: true},
		UserID:    userID,
		UserAgent: userAgent,
		Ip:        ip,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "DeleteSessionsByDeviceAndTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to delete device sessions")
		return fmt.Errorf("failed to delete sessions by device and tenant: %w", err)
	}

	log.Info().
		Str("pkg", pkgName).
		Str("method", "DeleteSessionsByDeviceAndTenant").
		Str("user_id", userID.String()).
		Str("tenant_id", tenantID.String()).
		Msg("Device sessions deleted successfully")

	return nil
}

// GetSessionsByUserIDAndTenant retrieves all sessions for a user within a specific tenant
func (r *UserRepo) GetSessionsByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*sqlc.Session, error) {
	sessionRows, err := r.queries.GetSessionsByUserIDAndTenant(ctx, sqlc.GetSessionsByUserIDAndTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetSessionsByUserIDAndTenant").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get sessions by user ID and tenant: %w", err)
	}

	sessions := make([]*sqlc.Session, len(sessionRows))
	for i, row := range sessionRows {
		sessions[i] = &sqlc.Session{
			ID:           row.ID,
			TenantID:     row.TenantID,
			UserID:       row.UserID,
			SessionToken: row.SessionToken,
			CsrfToken:    row.CsrfToken,
			UserAgent:    row.UserAgent,
			Ip:           row.Ip,
			ExpiresAt:    row.ExpiresAt,
			CreatedAt:    row.CreatedAt,
		}
	}

	return sessions, nil
}

// GetUserByVerificationTokenAndTenant retrieves a user by verification token within a specific tenant
func (r *UserRepo) GetUserByVerificationTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.User, error) {
	userRow, err := r.queries.GetUserByVerificationTokenAndTenant(ctx, sqlc.GetUserByVerificationTokenAndTenantParams{
		TenantID:          pgtype.UUID{Bytes: tenantID, Valid: true},
		VerificationToken: pgtype.Text{String: token, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetUserByVerificationTokenAndTenant").
			Str("token", token).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get user by verification token and tenant: %w", err)
	}

	user := &sqlc.User{
		ID:                userRow.ID,
		TenantID:          userRow.TenantID,
		Email:             userRow.Email,
		PasswordHash:      userRow.PasswordHash,
		Otp:               userRow.Otp,
		OtpExpiresAt:      userRow.OtpExpiresAt,
		CreatedAt:         userRow.CreatedAt,
		UpdatedAt:         userRow.UpdatedAt,
		EmailVerified:     userRow.EmailVerified,
		VerificationToken: userRow.VerificationToken,
	}

	return user, nil
}

// UpdateUserEmailVerified updates the email verification status of a user within a specific tenant
func (r *UserRepo) UpdateUserEmailVerified(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, verified bool) error {
	err := r.queries.UpdateUserEmailVerified(ctx, sqlc.UpdateUserEmailVerifiedParams{
		ID:            userID,
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		EmailVerified: pgtype.Bool{Bool: verified, Valid: true},
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "UpdateUserEmailVerified").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Bool("verified", verified).
			Err(err).
			Msg("Failed to update email verification status")
		return fmt.Errorf("failed to update email verification status: %w", err)
	}
	return nil
}

// ClearVerificationToken clears the verification token for a user within a specific tenant
func (r *UserRepo) ClearVerificationToken(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	err := r.queries.ClearVerificationToken(ctx, sqlc.ClearVerificationTokenParams{
		ID:       userID,
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "ClearVerificationToken").
			Str("user_id", userID.String()).
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to clear verification token")
		return fmt.Errorf("failed to clear verification token: %w", err)
	}
	return nil
}

// GetUserByEmail retrieves a user by their email
func (r *UserRepo) GetUserByEmail(email string) (*sqlc.User, error) {

	dbUser, err := r.queries.GetUserByEmail(context.Background(), email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found is not an error condition for user existence checks
			return nil, nil
		}
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetUserByEmail").
			Str("email", email).
			Err(err).
			Msg("DB query failed")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &sqlc.User{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		Otp:          dbUser.Otp,
		OtpExpiresAt: dbUser.OtpExpiresAt,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
	}, nil
}

func (r *UserRepo) CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ip string, expiresAt time.Time) (sqlc.Session, error) {
	session, err := r.queries.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID:       userID,
		SessionToken: sessionToken,
		CsrfToken:    csrfToken,
		UserAgent:    userAgent,
		Ip:           ip,
		ExpiresAt:    expiresAt,
	})
	return session, err
}

func (r *UserRepo) GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error) {
	return r.queries.GetSessionRowBySessionToken(ctx, token)
}

func (r *UserRepo) Authorize(req *http.Request) (uuid.UUID, error) {
	// Get session token from cookie
	sessionToken, err := req.Cookie("session_token")
	if err != nil || sessionToken.Value == "" {

		return uuid.UUID{}, fmt.Errorf("unauthorized access: missing session cookie")
	}

	// Validate session from database
	dbSession, err := r.queries.GetSessionRowBySessionToken(req.Context(), sessionToken.Value)
	if err != nil {

		return uuid.UUID{}, fmt.Errorf("unauthorized access: %w", err)
	}

	if time.Now().After(dbSession.ExpiresAt) {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Authorize").
			Time("expiredAt", dbSession.ExpiresAt).
			Msg("Session expired")
		return uuid.UUID{}, fmt.Errorf("unauthorized access: session expired")
	}

	// Stateless Token: Validate CSRF token from header only and check it against the CSRF token in cookie
	// CSRF token is expected to be in the header for security reasons
	csrfDB, err := r.queries.GetCsrfTokenBySessionToken(req.Context(), sessionToken.Value)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Authorize").
			Err(err).
			Msg("Error retrieving CSRF token")
		return uuid.UUID{}, fmt.Errorf("unauthorized access: %w", err)
	}
	csrfToken := req.Header.Get("X-CSRF-Token")
	if csrfToken != csrfDB {
		log.Error().
			Str("location", "Authorize").
			Msg("CSRF token not found")
		return uuid.UUID{}, fmt.Errorf("%w: invalid CSRF token", ErrAuth)
	}
	return dbSession.UserID, nil
}

func (r *UserRepo) GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error) {
	session, err := r.queries.GetSessionRowBySessionToken(ctx, token)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get user ID by token: %w", err)
	}
	return session.UserID, nil
}
func (r *UserRepo) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("user not found with email: %s", email)
		}
		return uuid.Nil, fmt.Errorf("failed to get user ID by email: %w", err)
	}
	return user.ID, nil
}
func (r *UserRepo) DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error {
	numRows, err := r.queries.DeleteSessionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete session by user ID: %w", err)
	}
	log.Info().
		Str("pkg", pkgName).
		Str("method", "DeleteSessionByUserID").
		Str("userID", userID.String()).
		Msgf("Session deleted successfully %d rows affected", numRows)

	return nil
}

func (r *UserRepo) DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error {

	numRows, err := r.queries.DeleteSessionsByDevice(ctx, sqlc.DeleteSessionsByDeviceParams{
		UserID:    userID,
		UserAgent: userAgent,
		Ip:        ip,
	})
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	log.Info().
		Str("pkg", pkgName).
		Str("method", "DeleteSession").
		Str("userID", userID.String()).
		Int64("rowsAffected", numRows).
		Msg("Session deleted successfully")
	return nil
}

func (r *UserRepo) GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error) {
	csrfToken, err := r.queries.GetCsrfTokenBySessionToken(ctx, sessionToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("CSRF token not found for session token: %s", sessionToken)
		}
		return "", fmt.Errorf("failed to get CSRF token by session token: %w", err)
	}
	return csrfToken, nil
}

func (r *UserRepo) UpdateSessionToken(ctx context.Context, sessionID int64, sessionToken string, expiresAt time.Time) error {
	err := r.queries.UpdateSessionToken(ctx, sqlc.UpdateSessionTokenParams{
		ID:           sessionID,
		SessionToken: sessionToken,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		return fmt.Errorf("failed to update session token: %w", err)
	}
	return nil
}

func (r *UserRepo) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.UserExistsByEmail(ctx, email)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "UserExistsByEmail").
			Str("email", email).
			Err(err).
			Msg("DB query failed")
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}
	return exists, nil
}

func (r *UserRepo) CreateUserWithOtp(user *sqlc.User) error {
	_, err := r.queries.CreateUserWithOtp(context.Background(), sqlc.CreateUserWithOtpParams{
		Email:        user.Email,
		Otp:          pgtype.Text{String: user.Otp.String, Valid: user.Otp.String != ""},
		OtpExpiresAt: pgtype.Timestamptz{Time: user.OtpExpiresAt.Time, Valid: !user.OtpExpiresAt.Time.IsZero()},
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateUserWithOtp").
			Str("email", user.Email).
			Err(err).
			Msg("DB operation failed")
		return fmt.Errorf("failed to create user with OTP: %w", err)
	}
	return nil
}

func (r *UserRepo) SetUserOTP(ctx context.Context, userID uuid.UUID, otpCode string, expiresAt time.Time) error {
	err := r.queries.SetUserOTP(ctx, sqlc.SetUserOTPParams{
		Otp: pgtype.Text{
			String: otpCode,
			Valid:  otpCode != "",
		},
		OtpExpiresAt: pgtype.Timestamptz{
			Time:  expiresAt,
			Valid: !expiresAt.IsZero(),
		},
		ID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to set OTP: %w", err)
	}
	return nil
}

func (r *UserRepo) GetUserOTP(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	otpData, err := r.queries.GetUserOTP(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, nil
		}
		return "", time.Time{}, fmt.Errorf("failed to get OTP: %w", err)
	}

	return otpData.Otp.String, otpData.OtpExpiresAt.Time, nil
}

func (r *UserRepo) ClearUserOTP(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.ClearUserOTP(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to clear OTP: %w", err)
	}
	return nil
}
