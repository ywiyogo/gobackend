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
	"github.com/stretchr/testify/suite"
)

// MockRepository provides a clean mocking approach
// Only implements methods actually used by the auth service
type MockRepository struct {
	mock.Mock
}

// User-related methods
func (m *MockRepository) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) CreateUserWithPassword(user *sqlc.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockRepository) CreateUserWithOtp(user *sqlc.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockRepository) GetUserByEmail(email string) (*sqlc.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockRepository) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

// Session-related methods
func (m *MockRepository) CreateSession(ctx context.Context, userID uuid.UUID, sessionToken string, csrfToken string, userAgent string, ip string, expiresAt time.Time) (sqlc.Session, error) {
	args := m.Called(ctx, userID, sessionToken, csrfToken, userAgent, ip, expiresAt)
	return args.Get(0).(sqlc.Session), args.Error(1)
}

func (m *MockRepository) DeleteSessionsByDevice(ctx context.Context, userID uuid.UUID, userAgent string, ip string) error {
	args := m.Called(ctx, userID, userAgent, ip)
	return args.Error(0)
}

func (m *MockRepository) GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockRepository) DeleteSessionByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRepository) GetSessionRowByToken(ctx context.Context, token string) (sqlc.Session, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.Session), args.Error(1)
}

func (m *MockRepository) UpdateSessionToken(ctx context.Context, sessionID int64, sessionToken string, expiresAt time.Time) error {
	args := m.Called(ctx, sessionID, sessionToken, expiresAt)
	return args.Error(0)
}

func (m *MockRepository) GetCsrfTokenBySessionToken(ctx context.Context, sessionToken string) (string, error) {
	args := m.Called(ctx, sessionToken)
	return args.String(0), args.Error(1)
}

// OTP-related methods
func (m *MockRepository) SetUserOTP(ctx context.Context, userID uuid.UUID, otpCode string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, otpCode, expiresAt)
	return args.Error(0)
}

func (m *MockRepository) GetUserOTP(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *MockRepository) ClearUserOTP(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRepository) ValidateOTP(ctx context.Context, userID uuid.UUID, otp string) (bool, error) {
	args := m.Called(ctx, userID, otp)
	return args.Bool(0), args.Error(1)
}

// Legacy/unused methods - stub implementations to satisfy interface
func (m *MockRepository) Authorize(r *http.Request) (uuid.UUID, error) {
	return uuid.New(), nil
}

// Multi-tenant stubs - not actively tested but required for interface compliance
func (m *MockRepository) GetUserByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (*sqlc.User, error) {
	args := m.Called(ctx, email, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockRepository) GetUserByIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*sqlc.User, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockRepository) CreateUserInTenant(ctx context.Context, user *sqlc.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) CreateSessionInTenant(ctx context.Context, session *sqlc.Session) error {
	return nil
}

func (m *MockRepository) GetSessionByTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.Session, error) {
	return nil, nil
}

func (m *MockRepository) UserExistsByEmailAndTenant(ctx context.Context, email string, tenantID uuid.UUID) (bool, error) {
	return false, nil
}

func (m *MockRepository) SetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otpCode string, expiresAt time.Time) error {
	return nil
}

func (m *MockRepository) GetUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) (string, time.Time, error) {
	return "", time.Now(), nil
}

func (m *MockRepository) ClearUserOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	return nil
}

func (m *MockRepository) ValidateOTPInTenant(ctx context.Context, userID, tenantID uuid.UUID, otp string) (bool, error) {
	return false, nil
}

func (m *MockRepository) DeleteSessionByIDAndTenant(ctx context.Context, sessionID int64, tenantID uuid.UUID) error {
	return nil
}

func (m *MockRepository) DeleteSessionByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	return nil
}

func (m *MockRepository) DeleteSessionsByDeviceAndTenant(ctx context.Context, tenantID, userID uuid.UUID, userAgent, ip string) error {
	return nil
}

func (m *MockRepository) GetSessionsByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*sqlc.Session, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Get(0).([]*sqlc.Session), args.Error(1)
}

func (m *MockRepository) GetUserByVerificationTokenAndTenant(ctx context.Context, token string, tenantID uuid.UUID) (*sqlc.User, error) {
	args := m.Called(ctx, token, tenantID)
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockRepository) GetUserByOTPAndTenant(ctx context.Context, otp string, tenantID uuid.UUID) (*sqlc.User, error) {
	args := m.Called(ctx, otp, tenantID)
	return args.Get(0).(*sqlc.User), args.Error(1)
}

func (m *MockRepository) UpdateUserEmailVerified(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, verified bool) error {
	args := m.Called(ctx, userID, tenantID, verified)
	return args.Error(0)
}

func (m *MockRepository) ClearVerificationToken(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	args := m.Called(ctx, userID, tenantID)
	return args.Error(0)
}

// AuthTestSuite organizes all auth-related tests
type AuthTestSuite struct {
	suite.Suite
	mockRepo *MockRepository
	service  *Service
}

// SetupTest runs before each test
func (suite *AuthTestSuite) SetupTest() {
	suite.mockRepo = &MockRepository{}
	suite.service = NewService(suite.mockRepo)
}

// Registration Tests
func (suite *AuthTestSuite) TestRegister_Success() {
	email := "test@example.com"
	password := "validpassword123"

	// Only mock what this test actually uses
	suite.mockRepo.On("UserExistsByEmail", mock.Anything, email).Return(false, nil)
	suite.mockRepo.On("CreateUserWithPassword", mock.Anything).Return(nil)

	req := httptest.NewRequest("POST", "/register", nil)
	req.Form = map[string][]string{
		"email":    {email},
		"password": {password},
	}
	w := httptest.NewRecorder()

	err := suite.service.Register(w, req)

	suite.NoError(err)
	suite.Equal(http.StatusOK, w.Code)
	suite.mockRepo.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestRegister_DuplicateEmail() {
	email := "exists@example.com"
	password := "validpassword123"

	suite.mockRepo.On("UserExistsByEmail", mock.Anything, email).Return(true, nil)

	req := httptest.NewRequest("POST", "/register", nil)
	req.Form = map[string][]string{
		"email":    {email},
		"password": {password},
	}
	w := httptest.NewRecorder()

	err := suite.service.Register(w, req)

	suite.Error(err)
	suite.Equal(http.StatusConflict, w.Code)
	suite.mockRepo.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestRegister_InvalidInput() {
	testCases := []struct {
		name          string
		email         string
		password      string
		expectedCode  int
		needsUserMock bool
	}{
		{"empty email", "", "password123", http.StatusBadRequest, false},
		{"invalid email", "notanemail", "password123", http.StatusBadRequest, false},
		{"short password", "test@example.com", "short", http.StatusBadRequest, true},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Fresh mock for each subtest
			suite.SetupTest()

			// Only mock if we expect the test to reach user existence check
			if tc.needsUserMock {
				suite.mockRepo.On("UserExistsByEmail", mock.Anything, tc.email).Return(false, nil)
			}

			req := httptest.NewRequest("POST", "/register", nil)
			req.Form = map[string][]string{
				"email":    {tc.email},
				"password": {tc.password},
			}
			w := httptest.NewRecorder()

			err := suite.service.Register(w, req)

			suite.Error(err)
			suite.Equal(tc.expectedCode, w.Code)
			suite.mockRepo.AssertExpectations(suite.T())
		})
	}
}

func (suite *AuthTestSuite) TestRegister_OTPEnabled() {
	// Save original env and restore after test
	originalOTP := os.Getenv("OTP_ENABLED")
	os.Setenv("OTP_ENABLED", "true")
	defer func() {
		if originalOTP != "" {
			os.Setenv("OTP_ENABLED", originalOTP)
		} else {
			os.Unsetenv("OTP_ENABLED")
		}
	}()

	email := "otp@example.com"
	userID := uuid.New()
	testUser := &sqlc.User{
		ID:        userID,
		Email:     email,
		CreatedAt: time.Now(),
	}

	// Setup mocks for OTP registration flow
	suite.mockRepo.On("UserExistsByEmail", mock.Anything, email).Return(true, nil)
	suite.mockRepo.On("GetUserByEmail", email).Return(testUser, nil)
	suite.mockRepo.On("SetUserOTP", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)
	suite.mockRepo.On("CreateSession", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{}, nil)

	req := httptest.NewRequest("POST", "/register", nil)
	req.Form = map[string][]string{"email": {email}}
	w := httptest.NewRecorder()

	err := suite.service.Register(w, req)

	suite.NoError(err)
	suite.Equal(http.StatusOK, w.Code)
	suite.mockRepo.AssertExpectations(suite.T())
}

// Login Tests
func (suite *AuthTestSuite) TestLogin_Success() {
	// Ensure OTP is disabled for password login
	os.Setenv("OTP_ENABLED", "false")
	defer os.Unsetenv("OTP_ENABLED")

	email := "user@example.com"
	password := "correctpassword"
	userID := uuid.New()

	hashedPassword, _ := utils.HashPassword(password)
	user := &sqlc.User{
		ID:    userID,
		Email: email,
		PasswordHash: pgtype.Text{
			String: hashedPassword,
			Valid:  true,
		},
	}

	// Mock only what login actually uses
	suite.mockRepo.On("GetUserByEmail", email).Return(user, nil)
	suite.mockRepo.On("DeleteSessionsByDevice", mock.Anything, userID, mock.Anything, mock.Anything).Return(nil)
	suite.mockRepo.On("CreateSession", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sqlc.Session{
		ID:           1,
		UserID:       userID,
		SessionToken: "session_token_value",
		CsrfToken:    "csrf_token_value",
		UserAgent:    "test-agent",
		Ip:           "192.168.1.1",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}, nil)

	req := httptest.NewRequest("POST", "/login", nil)
	req.Form = map[string][]string{
		"email":    {email},
		"password": {password},
	}
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()

	err := suite.service.Login(w, req)

	suite.NoError(err)
	suite.Equal(http.StatusOK, w.Code)

	cookies := w.Result().Cookies()
	suite.NotEmpty(cookies)
	suite.mockRepo.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestLogin_InvalidCredentials() {
	email := "user@example.com"

	// User not found
	suite.mockRepo.On("GetUserByEmail", email).Return(nil, nil)

	req := httptest.NewRequest("POST", "/login", nil)
	req.Form = map[string][]string{
		"email":    {email},
		"password": {"wrongpassword"},
	}
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()

	err := suite.service.Login(w, req)

	suite.Error(err)
	suite.Contains(err.Error(), "invalid email")
	suite.mockRepo.AssertExpectations(suite.T())
}

// Logout Tests
func (suite *AuthTestSuite) TestLogout_Success() {
	userID := uuid.New()
	sessionToken := "validtoken"

	suite.mockRepo.On("GetUserIDByToken", mock.Anything, sessionToken).Return(userID, nil)
	suite.mockRepo.On("DeleteSessionByUserID", mock.Anything, userID).Return(nil)
	suite.mockRepo.On("ClearUserOTP", mock.Anything, userID).Return(nil)

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken, Path: "/"})
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	err := suite.service.Logout(w, req)

	suite.NoError(err)
	suite.Equal(http.StatusOK, w.Code)

	cookies := w.Result().Cookies()
	suite.NotEmpty(cookies)
	suite.Equal("session_token", cookies[0].Name)
	suite.Equal("", cookies[0].Value) // Cookie should be cleared
	suite.mockRepo.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestLogout_NoSession() {
	req := httptest.NewRequest("POST", "/logout", nil)
	// No session cookie provided
	w := httptest.NewRecorder()

	err := suite.service.Logout(w, req)

	suite.Error(err)
	suite.Contains(err.Error(), "no session token found")
}

// Multi-tenant Tests (example)
func (suite *AuthTestSuite) TestRegisterWithPasswordInTenant() {
	tenantID := uuid.New()
	email := "tenant-user@example.com"
	password := "validpassword123"

	// Only mock what this tenant operation uses
	suite.mockRepo.On("GetUserByEmailAndTenant", mock.Anything, email, tenantID).Return(nil, nil)
	suite.mockRepo.On("CreateUserInTenant", mock.Anything, mock.Anything).Return(nil)

	user, err := suite.service.RegisterWithPasswordInTenant(context.Background(), email, password, tenantID)

	suite.NoError(err)
	suite.NotNil(user)
	suite.Equal(email, user.Email)
	suite.mockRepo.AssertExpectations(suite.T())
}

// Run the test suite
func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}

// Individual benchmark for performance testing
func BenchmarkLogin(b *testing.B) {
	mockRepo := &MockRepository{}
	svc := NewService(mockRepo)

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

	// Setup mocks for benchmark
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

// Table-driven test example for multiple scenarios
func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		password     string
		userExists   bool
		expectedCode int
		expectError  bool
	}{
		{
			name:         "valid registration",
			email:        "test@example.com",
			password:     "validpass123",
			userExists:   false,
			expectedCode: http.StatusOK,
			expectError:  false,
		},
		{
			name:         "duplicate email",
			email:        "exists@example.com",
			password:     "validpass123",
			userExists:   true,
			expectedCode: http.StatusConflict,
			expectError:  true,
		},
		{
			name:         "short password",
			email:        "test@example.com",
			password:     "short",
			userExists:   false,
			expectedCode: http.StatusBadRequest,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := &MockRepository{}
			svc := NewService(mockRepo)

			// Setup mocks based on test case
			// Always mock UserExistsByEmail since it's called before password validation
			mockRepo.On("UserExistsByEmail", mock.Anything, tt.email).Return(tt.userExists, nil)
			if !tt.userExists && !tt.expectError {
				mockRepo.On("CreateUserWithPassword", mock.Anything).Return(nil)
			}

			req := httptest.NewRequest("POST", "/register", nil)
			req.Form = map[string][]string{
				"email":    {tt.email},
				"password": {tt.password},
			}
			w := httptest.NewRecorder()

			err := svc.Register(w, req)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedCode, w.Code)
			mockRepo.AssertExpectations(t)
		})
	}
}
