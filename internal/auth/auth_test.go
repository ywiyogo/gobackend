package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthRepository struct {
	mock.Mock
}

func (m *MockAuthRepository) CreateUser(user *sqlc.User) error {
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

func (m *MockAuthRepository) DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string) error {
	args := m.Called(ctx, userID, userAgent, ipAddress)
	return args.Error(0)
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
		mockRepo.On("CreateUser", mock.Anything).Return(nil)

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

			err := svc.Register(w, req)
			assert.Error(t, err)
			assert.Equal(t, tc.expected, w.Code)
		})
	}
}

func BenchmarkLogin(b *testing.B) {
	mockRepo := new(MockAuthRepository)
	svc := NewService(mockRepo)

	userID := uuid.New()
	hashedPassword, _ := utils.HashPassword("correctpassword")
	user := &sqlc.User{
		ID:           userID,
		Email:        "user@example.com",
		PasswordHash: hashedPassword,
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
			ID:           userID,
			Email:        "user@example.com",
			PasswordHash: hashedPassword,
		}

		mockRepo.On("GetUserByEmail", "user@example.com").Return(user, nil)
		mockRepo.On("DeleteSessionsByDevice", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)
		mockRepo.On("CreateSession", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{}, nil)

		err := svc.Login(w, req)
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
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "validtoken"})
		req.RemoteAddr = "192.168.1.1:1234"

		w := httptest.NewRecorder()

		userID := uuid.New()
		mockRepo.On("Authorize", req).Return(userID, nil)
		mockRepo.On("DeleteSessionsByDevice", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)

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
