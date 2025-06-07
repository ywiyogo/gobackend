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
	if err := otpRecord.OtpCode.Scan(&storedOTP); err != nil {
		return false, fmt.Errorf("failed to read OTP code: %w", err)
	}

	// Check if OTP is valid and not expired
	if storedOTP == "" || !otpRecord.OtpExpiresAt.Valid || time.Now().After(otpRecord.OtpExpiresAt.Time) {
		return false, nil
	}

	return storedOTP == otp, nil
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
		OtpCode:      dbUser.OtpCode,
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
		OtpCode:      pgtype.Text{String: user.OtpCode.String, Valid: user.OtpCode.String != ""},
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
		OtpCode: pgtype.Text{
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

	return otpData.OtpCode.String, otpData.OtpExpiresAt.Time, nil
}

func (r *UserRepo) ClearUserOTP(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.ClearUserOTP(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to clear OTP: %w", err)
	}
	return nil
}
