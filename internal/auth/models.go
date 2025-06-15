package auth

import (
	"time"

	"gobackend/internal/db/sqlc"
)

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email" form:"email" validate:"required,email"`
	Password string `json:"password,omitempty" form:"password" validate:"omitempty,min=8"`
	OTP      string `json:"otp,omitempty" form:"otp"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" form:"email" validate:"required,email"`
	Password string `json:"password,omitempty" form:"password"`
	OTP      string `json:"otp,omitempty" form:"otp"`
}

// VerifyOTPRequest represents an OTP verification request
type VerifyOTPRequest struct {
	Email        string `json:"email" form:"email" validate:"required,email"`
	OTP          string `json:"otp" form:"otp" validate:"required,len=6"`
	SessionToken string `json:"session_token" form:"session_token"`
}

// AuthResponse represents a successful authentication response
type AuthResponse struct {
	User         *UserResponse `json:"user"`
	SessionToken string        `json:"session_token,omitempty"`
	CSRFToken    string        `json:"csrf_token,omitempty"`
	ExpiresAt    time.Time     `json:"expires_at"`
	RequiresOTP  bool          `json:"requires_otp"`
	Message      string        `json:"message,omitempty"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string            `json:"error"`
	Code    string            `json:"code,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// SessionInfo represents session information for responses
type SessionInfo struct {
	ID        string    `json:"id"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IsCurrent bool      `json:"is_current"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	AllDevices bool `json:"all_devices,omitempty" form:"all_devices"`
}

// OTPRequest represents a request to generate OTP
type OTPRequest struct {
	Email string `json:"email" form:"email" validate:"required,email"`
}

// ToUserResponse converts a SQLC User model to UserResponse
func ToUserResponse(user *sqlc.User) *UserResponse {
	return &UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// ToSessionInfo converts a SQLC Session to SessionInfo
func ToSessionInfo(session *sqlc.Session, currentSessionToken string) *SessionInfo {
	return &SessionInfo{
		ID:        string(rune(session.ID)),
		UserAgent: session.UserAgent,
		IP:        session.Ip,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
		IsCurrent: session.SessionToken == currentSessionToken,
	}
}

// HasPassword checks if the user has a password set
func HasPassword(user *sqlc.User) bool {
	return user.PasswordHash.Valid && user.PasswordHash.String != ""
}

// HasValidOTP checks if the user has a valid OTP that hasn't expired
func HasValidOTP(user *sqlc.User) bool {
	if !user.Otp.Valid || !user.OtpExpiresAt.Valid {
		return false
	}
	return time.Now().Before(user.OtpExpiresAt.Time)
}

// IsSessionExpired checks if the session has expired
func IsSessionExpired(session *sqlc.Session) bool {
	return time.Now().After(session.ExpiresAt)
}
