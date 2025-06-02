// Implementation of OTP (One-Time Password) Management

package auth

import (
	"context"
	"fmt"
	"gobackend/internal/db/sqlc"
	"math/rand"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OTPRepository defines the interface for OTP data operations
type OTPRepository interface {
	CreateOTP(userID int, otpCode string, expiresAt time.Time) error
	GetOTPByUserID(userID int) (*OTP, error)
	MarkOTPAsUsed(otpID int) error
}

// OTPRepo implements OTPRepository
type OTPRepo struct {
	queries *sqlc.Queries
	pool    *pgxpool.Pool
}

// NewOTPRepository creates a new instance of OTPRepo
func NewOTPRepository(queries *sqlc.Queries, pool *pgxpool.Pool) OTPRepository {
	return &OTPRepo{queries: queries, pool: pool}
}

// OTP represents the OTP entity in the database
type OTP struct {
	ID        int
	UserID    int
	OTPCode   string
	ExpiresAt time.Time
	Used      bool
}

// GenerateOTP creates a 6-digit OTP code
func GenerateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// CreateOTP adds a new OTP to the database
func (r *OTPRepo) CreateOTP(userID int, otpCode string, expiresAt time.Time) error {
	query := `
		INSERT INTO otps (user_id, otp_code, expires_at)
		VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(context.Background(), query, userID, otpCode, expiresAt)
	return err
}

// GetOTPByUserID retrieves the latest unused OTP for a user
func (r *OTPRepo) GetOTPByUserID(userID int) (*OTP, error) {
	otp := &OTP{}
	query := `
		SELECT id, user_id, otp_code, expires_at, used
		FROM otps
		WHERE user_id = $1 AND used = false
		ORDER BY expires_at DESC
		LIMIT 1`
	err := r.pool.QueryRow(context.Background(), query, userID).Scan(
		&otp.ID, &otp.UserID, &otp.OTPCode, &otp.ExpiresAt, &otp.Used,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return otp, nil
}

// MarkOTPAsUsed marks an OTP as used
func (r *OTPRepo) MarkOTPAsUsed(otpID int) error {
	query := `
		UPDATE otps
		SET used = true
		WHERE id = $1`
	_, err := r.pool.Exec(context.Background(), query, otpID)
	return err
}
