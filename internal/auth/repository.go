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

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const pkgName = "auth"

// AuthRepository defines the interface for user data operations
type AuthRepository interface {
	CreateUser(user *sqlc.User) error
	GetUserByEmail(email string) (*sqlc.User, error)
	CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ip string, expiresAt time.Time) (sqlc.Session, error)
	GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error)
	Authorize(r *http.Request) (uuid.UUID, error)
	GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error)
	GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error)
	DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error
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
func (r *UserRepo) CreateUser(user *sqlc.User) error {
	log.Debug().
		Str("pkg", pkgName).
		Str("method", "CreateUser").
		Str("email", user.Email).
		Msg("DB operation started")

	_, err := r.queries.CreateUser(context.Background(), sqlc.CreateUserParams{
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
	})
	if err != nil {
		log.Debug().
			Str("pkg", pkgName).
			Str("method", "CreateUser").
			Str("email", user.Email).
			Err(err).
			Msg("DB operation failed")
		return fmt.Errorf("failed to create user: %w", err)
	}

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "CreateUser").
		Str("email", user.Email).
		Msg("DB operation successful")
	return nil
}

// GetUserByEmail retrieves a user by their email
func (r *UserRepo) GetUserByEmail(email string) (*sqlc.User, error) {
	log.Debug().
		Str("pkg", pkgName).
		Str("method", "GetUserByEmail").
		Str("email", email).
		Msg("DB query started")

	dbUser, err := r.queries.GetUserByEmail(context.Background(), email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug().
				Str("pkg", pkgName).
				Str("method", "GetUserByEmail").
				Str("email", email).
				Msg("User not found")
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

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "GetUserByEmail").
		Str("email", dbUser.Email).
		Str("userID", dbUser.ID.String()).
		Msg("DB query successful")
	return &sqlc.User{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
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
		log.Debug().
			Str("pkg", pkgName).
			Str("method", "Authorize").
			Msg("Session token not found")
		return uuid.UUID{}, fmt.Errorf("unauthorized access: missing session cookie")
	}

	// Validate session from database
	dbSession, err := r.queries.GetSessionRowBySessionToken(req.Context(), sessionToken.Value)
	if err != nil {
		log.Debug().
			Str("pkg", pkgName).
			Str("method", "Authorize").
			Err(err).
			Msg("Error retrieving session")
		return uuid.UUID{}, fmt.Errorf("unauthorized access: %w", err)
	}

	if time.Now().After(dbSession.ExpiresAt) {
		log.Debug().
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
		log.Debug().
			Str("pkg", pkgName).
			Str("method", "Authorize").
			Err(err).
			Msg("Error retrieving CSRF token")
		return uuid.UUID{}, fmt.Errorf("unauthorized access: %w", err)
	}
	csrfToken := req.Header.Get("X-CSRF-Token")
	if csrfToken != csrfDB {
		log.Debug().
			Str("location", "Authorize").
			Msg("CSRF token not found")
		return uuid.UUID{}, fmt.Errorf("%w: missing CSRF token", ErrAuth)
	}

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "Authorize").
		Str("session token", sessionToken.Value).
		Msg("Session authorized successfully")

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
