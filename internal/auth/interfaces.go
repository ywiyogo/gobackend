// Implement Interface Segregation Principle to ensure that each interface has a single responsibility
// Split the large `AuthRepository` interface into smaller focused interfaces
// Benefits:
// - Tests only mock what they actually use
// - Clear separation of concerns
// - Easy to add new functionality without breaking existing tests
// - Better code organization

package auth

import (
	"context"
	"net/http"
	"time"

	"gobackend/internal/db/sqlc"

	"github.com/google/uuid"
)

// UserRepository handles user-related database operations
type UserRepository interface {
	// User management
	CreateUserWithPassword(user *sqlc.User) error
	CreateUserWithOtp(user *sqlc.User) error
	GetUserByEmail(email string) (*sqlc.User, error)
	UserExistsByEmail(ctx context.Context, email string) (bool, error)
	GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error)

	// Multi-tenant user operations
	GetUserByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (*sqlc.User, error)
	GetUserByIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*sqlc.User, error)
	CreateUserInTenant(ctx context.Context, user *sqlc.User) error
	UserExistsByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (bool, error)
}

// SessionRepository handles session-related database operations
type SessionRepository interface {
	// Session management
	CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ip string, expiresAt time.Time) (sqlc.Session, error)
	GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error)
	GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error)
	GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error)
	DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error
	UpdateSessionToken(ctx context.Context, sessionID int64, sessionToken string, expiresAt time.Time) error

	// Multi-tenant session operations
	CreateSessionInTenant(ctx context.Context, session *sqlc.Session) error
	GetSessionByTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.Session, error)
	DeleteSessionByIDAndTenant(ctx context.Context, sessionID int64, tenantID uuid.UUID) error
	DeleteSessionByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) error
	DeleteSessionsByDeviceAndTenant(ctx context.Context, tenantID, userID uuid.UUID, userAgent, ip string) error
	GetSessionsByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*sqlc.Session, error)
}

// OTPRepository handles OTP-related database operations
type OTPRepository interface {
	// OTP operations
	SetUserOTP(ctx context.Context, userID uuid.UUID, otpCode string, expiresAt time.Time) error
	GetUserOTP(ctx context.Context, userID uuid.UUID) (string, time.Time, error)
	ClearUserOTP(ctx context.Context, userID uuid.UUID) error
	ValidateOTP(ctx context.Context, userID uuid.UUID, otp string) (bool, error)

	// Multi-tenant OTP operations
	SetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otpCode string, expiresAt time.Time) error
	GetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) (string, time.Time, error)
	ClearUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) error
	ValidateOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otp string) (bool, error)
}

// AuthRepositoryInterface combines all auth-related repository operations
// This maintains backward compatibility with existing code
type AuthRepositoryInterface interface {
	UserRepository
	SessionRepository
	OTPRepository

	// Legacy method for backward compatibility
	Authorize(r *http.Request) (uuid.UUID, error)
}

// ServiceDependencies represents the minimal dependencies needed by the auth service
// This is what we'll use in tests to avoid having to mock everything
type ServiceDependencies interface {
	UserRepository
	SessionRepository
	OTPRepository
}
