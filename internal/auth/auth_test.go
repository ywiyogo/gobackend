package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthRepository struct {
	mock.Mock
}

func (m *MockAuthRepository) CreateUserWithPassword(user *sqlc.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockAuthRepository) CreateUserWithOtp(user *sqlc.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockAuthRepository) GetUserByEmail(email string) (*sqlc.User, error) {
	args := m.Called(email)
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockAuthRepository) Authorize(r *http.Request) (uuid.UUID, error) {
	args := m.Called(r)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAuthRepository) DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error {
	args := m.Called(ctx, userID, userAgent, ip)
	return args.Error(0)
}

func (m *MockAuthRepository) UpdateSessionToken(ctx context.Context, sessionID int64, sessionToken string, expiresAt time.Time) error {
	args := m.Called(ctx, sessionID, sessionToken, expiresAt)
	return args.Error(0)
}

func (m *MockAuthRepository) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthRepository) DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthRepository) CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ipAddress string, expiresAt time.Time) (sqlc.Session, error) {
	args := m.Called(ctx, userID, sessionToken, csrfToken, userAgent, ipAddress, expiresAt)
	return args.Get(0).(sqlc.Session), args.Error(1)
}

func (m *MockAuthRepository) GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.Session), args.Error(1)
}

func (m *MockAuthRepository) GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error) {
	args := m.Called(ctx, sessionToken)
	return args.String(0), args.Error(1)
}

func (m *MockAuthRepository) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAuthRepository) GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAuthRepository) SetUserOTP(ctx context.Context, userID uuid.UUID, otpCode string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, otpCode, expiresAt)
	return args.Error(0)
}

func (m *MockAuthRepository) GetUserOTP(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *MockAuthRepository) ClearUserOTP(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthRepository) ValidateOTP(ctx context.Context, userID uuid.UUID, otp string) (bool, error) {
	args := m.Called(ctx, userID, otp)
	return args.Bool(0), args.Error(1)
}

func TestService_Register(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		mockRepo := new(MockAuthRepository)
		svc := NewService(mockRepo)

		req := httptest.NewRequest("POST", "/register", nil)
		req.Form = map[string][]string{
			"email":    {"test@example.com"},
			"password": {"validpassword123"},
		}

		w := httptest.NewRecorder()

		mockRepo.On("GetUserByEmail", "test@example.com").Return((*sqlc.User)(nil), nil)
		mockRepo.On("CreateUserWithPassword", mock.Anything).Return(nil)

		err := svc.Register(w, req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("duplicate email", func(t *testing.T) {
		mockRepo := new(MockAuthRepository)
		svc := NewService(mockRepo)

		req := httptest.NewRequest("POST", "/register", nil)
		req.Form = map[string][]string{
			"email":    {"exists@example.com"},
			"password": {"validpassword123"},
		}

		w := httptest.NewRecorder()

		existingUser := &sqlc.User{Email: "exists@example.com"}
		mockRepo.On("GetUserByEmail", "exists@example.com").Return(existingUser, nil)

		err := svc.Register(w, req)
		assert.Error(t, err)
		assert.Equal(t, http.StatusConflict, w.Code)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_Register_InvalidInput(t *testing.T) {
	testCases := []struct {
		name     string
		email    string
		password string
		expected int
	}{
		{"empty email", "", "password123", http.StatusBadRequest},
		{"invalid email", "notanemail", "password123", http.StatusBadRequest},
		{"short password", "test@example.com", "short", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo := new(MockAuthRepository)
			svc := NewService(mockRepo)

			req := httptest.NewRequest("POST", "/register", nil)
			req.Form = map[string][]string{
				"email":    {tc.email},
				"password": {tc.password},
			}

			w := httptest.NewRecorder()

			// Mock GetUserByEmail to return nil user for invalid input cases
			if tc.email != "" && tc.email != "notanemail" {
				mockRepo.On("GetUserByEmail", tc.email).Return((*sqlc.User)(nil), nil)
			}

			err := svc.Register(w, req)
			assert.Error(t, err)
			assert.Equal(t, tc.expected, w.Code)
			mockRepo.AssertExpectations(t)
		})
	}
}

func BenchmarkLogin(b *testing.B) {
	mockRepo := new(MockAuthRepository)
	svc := NewService(mockRepo)

	userID := uuid.New()
	hashedPassword, _ := utils.HashPassword("correctpassword")
	user := &sqlc.User{
		ID:    userID,
		Email: "user@example.com",
		PasswordHash: pgtype.Text{
			String: hashedPassword,
			Valid:  hashedPassword != "",
		},
	}

	mockRepo.On("GetUserByEmail", "user@example.com").Return(user, nil)
	mockRepo.On("DeleteSessionsByDevice", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)
	mockRepo.On("CreateSession", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.Form = map[string][]string{
			"email":    {"user@example.com"},
			"password": {"correctpassword"},
		}
		req.RemoteAddr = "192.168.1.1:1234"

		w := httptest.NewRecorder()
		_ = svc.Login(w, req)
	}
}

func TestService_Login(t *testing.T) {
	t.Run("successful login", func(t *testing.T) {
		mockRepo := new(MockAuthRepository)
		svc := NewService(mockRepo)

		// Explicitly set OTP_ENABLED to false for standard login flow
		os.Setenv("OTP_ENABLED", "false")
		defer os.Unsetenv("OTP_ENABLED")

		req := httptest.NewRequest("POST", "/login", nil)
		req.Form = map[string][]string{
			"email":    {"user@example.com"},
			"password": {"correctpassword"},
		}
		req.RemoteAddr = "192.168.1.1:1234"

		w := httptest.NewRecorder()

		userID := uuid.New()
		hashedPassword, _ := utils.HashPassword("correctpassword")
		user := &sqlc.User{
			ID:    userID,
			Email: "user@example.com",
			PasswordHash: pgtype.Text{
				String: hashedPassword,
				Valid:  true,
			},
		}

		mockRepo.On("GetUserByEmail", "user@example.com").Return(user, nil)
		// Ensure OTP is disabled for password flow
		os.Setenv("OTP_ENABLED", "false")
		defer os.Unsetenv("OTP_ENABLED")
		mockRepo.On("DeleteSessionsByDevice", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)
		mockRepo.On("CreateSession", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{
			ID:           1,
			UserID:       userID,
			SessionToken: "session_token_value",
			CsrfToken:    "csrf_token_value",
			UserAgent:    "test-agent",
			Ip:           "192.168.1.1",
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}, nil)

		err := svc.Login(w, req)
		if err != nil {
			t.Logf("Login error: %v", err)
		}
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)

		cookies := w.Result().Cookies()
		assert.NotEmpty(t, cookies)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_Logout(t *testing.T) {
	t.Run("successful logout", func(t *testing.T) {
		mockRepo := new(MockAuthRepository)
		svc := NewService(mockRepo)

		req := httptest.NewRequest("POST", "/logout", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "validtoken", Path: "/"})
		req.RemoteAddr = "192.168.1.1:1234"
		req.Header.Set("User-Agent", "test-agent") // Add user agent
		w := httptest.NewRecorder()

		userID := uuid.New()
		mockRepo.On("GetUserIDByToken", mock.Anything, "validtoken").Return(userID, nil)

		mockRepo.On("DeleteSessionByUserID", mock.Anything, userID).Return(nil)
		mockRepo.On("ClearUserOTP", mock.Anything, userID).Return(nil)

		err := svc.Logout(w, req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)

		cookies := w.Result().Cookies()
		assert.NotEmpty(t, cookies)
		assert.Equal(t, "session_token", cookies[0].Name)
		assert.Equal(t, "", cookies[0].Value)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_OTPEnabled(t *testing.T) {
	t.Run("OTP enabled registration", func(t *testing.T) {
		mockRepo := new(MockAuthRepository)
		svc := NewService(mockRepo)
		testEmail := "otp@example.com"
		// Set OTP_ENABLED environment variable for this test
		os.Setenv("OTP_ENABLED", "true")
		defer os.Unsetenv("OTP_ENABLED")

		req := httptest.NewRequest("POST", "/register", nil)
		req.Form = map[string][]string{
			"email": {testEmail},
		}

		testUser := &sqlc.User{
			Email: "existing@example.com", // or use testEmail variable if defined
			// Include other required fields as needed by your User struct
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			// ... other fields
		}

		w := httptest.NewRecorder()
		// Mock GetUserByEmail to return nil user for new registration
		mockRepo.On("GetUserByEmail", testEmail).Return(testUser, nil)
		mockRepo.On("SetUserOTP", mock.Anything, testUser.ID, mock.Anything, mock.Anything).Return(nil)
		mockRepo.On("CreateSession", mock.Anything, testUser.ID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{}, nil)

		err := svc.Register(w, req)
		// simulating nil user will returns an error
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		mockRepo.AssertExpectations(t)
	})
}
