package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/tenant"
	"gobackend/internal/utils"

	"github.com/rs/zerolog/log"
)

type Handler struct {
	authService   *Service
	tenantService *tenant.Service
}

func NewHandler(authService *Service, tenantService *tenant.Service) *Handler {
	return &Handler{
		authService:   authService,
		tenantService: tenantService,
	}
}

// Register handles user registration with multi-tenant support
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context (set by tenant middleware)
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Get tenant settings
	settings, err := h.tenantService.GetTenantSettings(tenantObj)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Register").
			Err(err).
			Msg("Failed to get tenant settings")
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse request
	var req RegisterRequest
	if err := h.parseRequest(r, &req); err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Register").
			Err(err).
			Msg("Request parsing failed")
		h.writeError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate email
	if !utils.IsValidEmail(req.Email) {
		h.writeError(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Set CORS headers for tenant
	h.setCORSHeaders(w, tenantObj.Domain)

	var user *sqlc.User
	var otpCode string
	var sessionToken string
	var expiresAt time.Time

	if settings.OTPEnabled {
		// OTP-based registration
		user, otpCode, err = h.authService.RegisterWithOTPInTenant(r.Context(), req.Email, tenantObj.ID, tenantObj.Name)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Register").
				Str("tenant_id", tenantObj.ID.String()).
				Err(err).
				Msg("OTP registration failed")
			h.handleAuthError(w, err)
			return
		}

		// Create temporary session for OTP verification
		session, err := h.authService.CreateSessionInTenant(
			r.Context(),
			user.ID,
			tenantObj.ID,
			r.UserAgent(),
			utils.ExtractIPFromRemoteAddr(r.RemoteAddr),
		)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Register").
				Str("user_id", user.ID.String()).
				Err(err).
				Msg("Failed to create session")
			h.writeError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		sessionToken = session.SessionToken
		expiresAt = session.ExpiresAt

		// Set session cookie
		h.setSessionCookie(w, sessionToken, expiresAt)

		// TODO: Send OTP via email/SMS based on tenant configuration
		log.Info().
			Str("pkg", pkgName).
			Str("method", "Register").
			Str("email", req.Email).
			Str("tenant_id", tenantObj.ID.String()).
			Str("otp", otpCode).
			Msg("OTP generated for registration")

		response := &AuthResponse{
			User:        ToUserResponse(user),
			RequiresOTP: true,
			CSRFToken:   session.CsrfToken,
			Message:     "OTP sent to your email. Please verify to complete registration.",
			ExpiresAt:   expiresAt,
		}

		// For testing purposes, include OTP in development/test environment
		if os.Getenv("ENV") == "test" || os.Getenv("ENV") == "development" {
			// Create a map to include OTP for testing
			responseMap := map[string]interface{}{
				"user":         response.User,
				"requires_otp": response.RequiresOTP,
				"csrf_token":   response.CSRFToken,
				"message":      response.Message,
				"expires_at":   response.ExpiresAt,
				"otp":          otpCode,
			}
			h.writeJSON(w, responseMap, http.StatusOK)
		} else {
			h.writeJSON(w, response, http.StatusOK)
		}

	} else {
		// Password-based registration
		if req.Password == "" || len(req.Password) < 8 {
			h.writeError(w, "Password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		user, err = h.authService.RegisterWithPasswordInTenant(r.Context(), req.Email, req.Password, tenantObj.ID)
		if err != nil {
			if os.Getenv("ENV") == "test" || os.Getenv("ENV") == "development" {
				if strings.Contains(err.Error(), "password must be at least 8 characters") {
					h.writeError(w, "Password must be at least 8 characters", http.StatusBadRequest)
					return
				}
			}
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Register").
				Str("tenant_id", tenantObj.ID.String()).
				Err(err).
				Msg("Password registration failed")
			h.handleAuthError(w, err)
			return
		}

		log.Info().
			Str("pkg", pkgName).
			Str("method", "Register").
			Str("email", req.Email).
			Str("tenant_id", tenantObj.ID.String()).
			Msg("User registered successfully")

		response := &AuthResponse{
			User:        ToUserResponse(user),
			RequiresOTP: false,
			Message:     "User registered successfully. Please check your email to verify your account.",
		}
		h.writeJSON(w, response, http.StatusCreated)
	}
}

// Login handles user login with multi-tenant support
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Get tenant settings
	settings, err := h.tenantService.GetTenantSettings(tenantObj)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Login").
			Err(err).
			Msg("Failed to get tenant settings")
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse request
	var req LoginRequest
	if err := h.parseRequest(r, &req); err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Login").
			Err(err).
			Msg("Request parsing failed")
		h.writeError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate email
	if !utils.IsValidEmail(req.Email) {
		h.writeError(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Set CORS headers
	h.setCORSHeaders(w, tenantObj.Domain)

	var user *sqlc.User
	var otpCode string

	if settings.OTPEnabled {
		// OTP-based login
		user, otpCode, err = h.authService.LoginWithOTPInTenant(r.Context(), req.Email, tenantObj.ID, tenantObj.Name)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Login").
				Str("tenant_id", tenantObj.ID.String()).
				Err(err).
				Msg("OTP login failed")
			h.handleAuthError(w, err)
			return
		}

		// Create temporary session for OTP verification
		session, err := h.authService.CreateSessionInTenant(
			r.Context(),
			user.ID,
			tenantObj.ID,
			r.UserAgent(),
			utils.ExtractIPFromRemoteAddr(r.RemoteAddr),
		)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Login").
				Str("user_id", user.ID.String()).
				Err(err).
				Msg("Failed to create session")
			h.writeError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		h.setSessionCookie(w, session.SessionToken, session.ExpiresAt)

		// TODO: Send OTP via email/SMS
		log.Info().
			Str("pkg", pkgName).
			Str("method", "Login").
			Str("email", req.Email).
			Str("tenant_id", tenantObj.ID.String()).
			Str("otp", otpCode).
			Msg("OTP generated for login")

		response := &AuthResponse{
			User:        ToUserResponse(user),
			RequiresOTP: true,
			CSRFToken:   session.CsrfToken,
			Message:     "OTP sent to your email. Please verify to complete login.",
			ExpiresAt:   session.ExpiresAt,
		}

		// For testing purposes, include OTP in development/test environment
		if os.Getenv("ENV") == "test" || os.Getenv("ENV") == "development" {
			// Create a map to include OTP for testing
			responseMap := map[string]interface{}{
				"user":         response.User,
				"requires_otp": response.RequiresOTP,
				"csrf_token":   response.CSRFToken,
				"message":      response.Message,
				"expires_at":   response.ExpiresAt,
				"otp":          otpCode,
			}
			h.writeJSON(w, responseMap, http.StatusOK)
		} else {
			h.writeJSON(w, response, http.StatusOK)
		}

	} else {
		// Password-based login
		if req.Password == "" {
			h.writeError(w, "Password is required", http.StatusBadRequest)
			return
		}

		user, err = h.authService.LoginWithPasswordInTenant(r.Context(), req.Email, req.Password, tenantObj.ID)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Login").
				Str("tenant_id", tenantObj.ID.String()).
				Err(err).
				Msg("Password login failed")
			h.handleAuthError(w, err)
			return
		}

		// Delete existing sessions for this device
		userAgent := r.UserAgent()
		ipAddress := utils.ExtractIPFromRemoteAddr(r.RemoteAddr)
		_ = h.authService.repo.DeleteSessionsByDeviceAndTenant(r.Context(), tenantObj.ID, user.ID, userAgent, ipAddress)

		// Create new session
		session, err := h.authService.CreateSessionInTenant(
			r.Context(),
			user.ID,
			tenantObj.ID,
			userAgent,
			ipAddress,
		)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "Login").
				Str("user_id", user.ID.String()).
				Err(err).
				Msg("Failed to create session")
			h.writeError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		h.setSessionCookie(w, session.SessionToken, session.ExpiresAt)

		log.Info().
			Str("pkg", pkgName).
			Str("method", "Login").
			Str("email", req.Email).
			Str("tenant_id", tenantObj.ID.String()).
			Msg("User logged in successfully")

		response := &AuthResponse{
			User:         ToUserResponse(user),
			SessionToken: session.SessionToken,
			CSRFToken:    session.CsrfToken,
			ExpiresAt:    session.ExpiresAt,
			Message:      "Login successful",
		}
		h.writeJSON(w, response, http.StatusOK)
	}
}

// VerifyOTP handles OTP verification with multi-tenant support
func (h *Handler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Parse request
	var req VerifyOTPRequest
	if err := h.parseRequest(r, &req); err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTP").
			Err(err).
			Msg("Request parsing failed")
		h.writeError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Get session token from cookie if not provided in request
	sessionToken := req.SessionToken
	if sessionToken == "" {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			h.writeError(w, "Session token required", http.StatusUnauthorized)
			return
		}
		sessionToken = cookie.Value
	}

	// Verify OTP
	session, err := h.authService.VerifyOTPInTenant(r.Context(), sessionToken, req.OTP, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTP").
			Str("tenant_id", tenantObj.ID.String()).
			Err(err).
			Msg("OTP verification failed")
		h.handleAuthError(w, err)
		return
	}

	// Get user information from database
	user, err := h.authService.repo.GetUserByIDAndTenant(r.Context(), session.UserID, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTP").
			Str("user_id", session.UserID.String()).
			Err(err).
			Msg("Failed to get user information")
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyOTP").
			Str("user_id", session.UserID.String()).
			Msg("User not found")
		h.writeError(w, "User not found", http.StatusNotFound)
		return
	}

	// Set CORS headers
	h.setCORSHeaders(w, tenantObj.Domain)

	// Set new session cookie
	h.setSessionCookie(w, session.SessionToken, session.ExpiresAt)

	log.Info().
		Str("pkg", pkgName).
		Str("method", "VerifyOTP").
		Str("user_id", session.UserID.String()).
		Str("tenant_id", tenantObj.ID.String()).
		Msg("OTP verified successfully")

	response := &AuthResponse{
		User:         ToUserResponse(user),
		SessionToken: session.SessionToken,
		CSRFToken:    session.CsrfToken,
		ExpiresAt:    session.ExpiresAt,
		Message:      "OTP verified successfully",
	}
	h.writeJSON(w, response, http.StatusOK)
}

// VerifyEmail handles email verification with multi-tenant support (legacy token-based)
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Get token from query parameters
	token := r.URL.Query().Get("token")
	if token == "" {
		h.writeError(w, "Verification token required", http.StatusBadRequest)
		return
	}

	// Verify email using token
	user, err := h.authService.VerifyEmailInTenant(r.Context(), token, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyEmail").
			Str("tenant_id", tenantObj.ID.String()).
			Err(err).
			Msg("Email verification failed")
		h.handleAuthError(w, err)
		return
	}

	// Set CORS headers
	h.setCORSHeaders(w, tenantObj.Domain)

	log.Info().
		Str("pkg", pkgName).
		Str("method", "VerifyEmail").
		Str("user_id", user.ID.String()).
		Str("tenant_id", tenantObj.ID.String()).
		Msg("Email verified successfully")

	response := &AuthResponse{
		User:    ToUserResponse(user),
		Message: "Email verified successfully",
	}
	h.writeJSON(w, response, http.StatusOK)
}

// VerifyEmailWithOTP handles email verification using OTP with multi-tenant support
func (h *Handler) VerifyEmailWithOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Set CORS headers
	h.setCORSHeaders(w, tenantObj.Domain)

	var otp string
	var email string

	// Get OTP and email from request (support both GET and POST)
	if r.Method == http.MethodGet {
		otp = r.URL.Query().Get("otp")
		email = r.URL.Query().Get("email")
	} else {
		// Parse the request based on content type
		var req struct {
			OTP   string `json:"otp"`
			Email string `json:"email"`
		}

		if err := h.parseRequest(r, &req); err != nil {
			h.writeError(w, "Invalid request format", http.StatusBadRequest)
			return
		}
		otp = req.OTP
		email = req.Email
	}

	// Validate required fields
	if otp == "" {
		h.writeError(w, "OTP code is required", http.StatusBadRequest)
		return
	}

	// Verify email using OTP
	user, err := h.authService.VerifyEmailWithOTPInTenant(r.Context(), otp, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "VerifyEmailWithOTP").
			Str("tenant_id", tenantObj.ID.String()).
			Str("email", email).
			Err(err).
			Msg("Email verification with OTP failed")
		h.handleAuthError(w, err)
		return
	}

	log.Info().
		Str("pkg", pkgName).
		Str("method", "VerifyEmailWithOTP").
		Str("user_id", user.ID.String()).
		Str("tenant_id", tenantObj.ID.String()).
		Msg("Email verified successfully with OTP")

	response := &AuthResponse{
		User:    ToUserResponse(user),
		Message: "Email verified successfully",
	}
	h.writeJSON(w, response, http.StatusOK)
}

// Logout handles user logout with multi-tenant support
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Get session token from cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		h.writeError(w, "No active session", http.StatusBadRequest)
		return
	}

	// Parse request for logout options
	var req LogoutRequest
	_ = h.parseRequest(r, &req) // Ignore errors as request body is optional

	// Logout user
	err = h.authService.LogoutInTenant(r.Context(), cookie.Value, tenantObj.ID, req.AllDevices)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Logout").
			Str("tenant_id", tenantObj.ID.String()).
			Err(err).
			Msg("Logout failed")
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear session cookie
	h.clearSessionCookie(w)

	log.Info().
		Str("pkg", pkgName).
		Str("method", "Logout").
		Str("tenant_id", tenantObj.ID.String()).
		Bool("all_devices", req.AllDevices).
		Msg("User logged out successfully")

	response := map[string]string{
		"message": "Logout successful",
	}
	h.writeJSON(w, response, http.StatusOK)
}

// Dashboard handles user dashboard access with multi-tenant support
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get tenant from context
	tenantObj, ok := tenant.GetTenantFromContext(r.Context())
	if !ok {
		h.writeError(w, "Tenant not found", http.StatusBadRequest)
		return
	}

	// Get session token from cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		h.writeError(w, "No active session", http.StatusUnauthorized)
		return
	}

	// Validate session
	session, err := h.authService.ValidateSessionInTenant(r.Context(), cookie.Value, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Dashboard").
			Str("tenant_id", tenantObj.ID.String()).
			Err(err).
			Msg("Session validation failed")
		h.handleAuthError(w, err)
		// Clear session cookie on invalid session
		h.clearSessionCookie(w)
		return
	}

	// Get user information
	user, err := h.authService.repo.GetUserByIDAndTenant(r.Context(), session.UserID, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Dashboard").
			Str("user_id", session.UserID.String()).
			Err(err).
			Msg("Failed to get user information")
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Dashboard").
			Str("user_id", session.UserID.String()).
			Msg("User not found")
		h.writeError(w, "User not found", http.StatusNotFound)
		return
	}

	// Set CORS headers
	h.setCORSHeaders(w, tenantObj.Domain)

	log.Info().
		Str("pkg", pkgName).
		Str("method", "Dashboard").
		Str("user_id", session.UserID.String()).
		Str("tenant_id", tenantObj.ID.String()).
		Msg("User accessed dashboard")

	response := &AuthResponse{
		User:         ToUserResponse(user),
		SessionToken: session.SessionToken,
		CSRFToken:    session.CsrfToken,
		ExpiresAt:    session.ExpiresAt,
		Message:      "Dashboard data retrieved successfully",
	}
	h.writeJSON(w, response, http.StatusOK)
}

func (h *Handler) parseRequest(r *http.Request, v interface{}) error {
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")

	// Handle form-encoded data
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("failed to parse form: %w", err)
		}

		// Use reflection to populate struct fields from form data
		val := reflect.ValueOf(v).Elem()
		typ := val.Type()

		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			fieldType := typ.Field(i)

			// Get the field name from json tag, fallback to struct field name
			fieldName := fieldType.Tag.Get("json")
			if fieldName == "" || fieldName == "-" {
				fieldName = strings.ToLower(fieldType.Name)
			} else {
				// Remove options like ",omitempty"
				if idx := strings.Index(fieldName, ","); idx != -1 {
					fieldName = fieldName[:idx]
				}
			}

			// Get form value and set field
			if formValue := r.FormValue(fieldName); formValue != "" && field.CanSet() {
				switch field.Kind() {
				case reflect.String:
					field.SetString(formValue)
				case reflect.Bool:
					if boolVal, err := strconv.ParseBool(formValue); err == nil {
						field.SetBool(boolVal)
					}
				}
			}
		}
		return nil
	}

	// Handle JSON data (default)
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *Handler) handleAuthError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "user already exists") {
		h.writeError(w, "User already exists", http.StatusConflict)
	} else if strings.Contains(err.Error(), "invalid credentials") {
		h.writeError(w, "Invalid email or password", http.StatusUnauthorized)
	} else if strings.Contains(err.Error(), "email not verified") {
		h.writeError(w, "Email not verified. Please check your email for verification link.", http.StatusUnauthorized)
	} else if strings.Contains(err.Error(), "invalid session") {
		h.writeError(w, "Session invalid or expired", http.StatusUnauthorized)
	} else if strings.Contains(err.Error(), "session expired") {
		h.writeError(w, "Session expired", http.StatusUnauthorized)
	} else if strings.Contains(err.Error(), "invalid OTP code") {
		h.writeError(w, "Invalid OTP code", http.StatusUnauthorized)
	} else if strings.Contains(err.Error(), "invalid or expired OTP code") {
		h.writeError(w, "Invalid or expired OTP code", http.StatusBadRequest)
	} else if strings.Contains(err.Error(), "email already verified") {
		h.writeError(w, "Email already verified", http.StatusBadRequest)
	} else if strings.Contains(err.Error(), "OTP code has expired") {
		h.writeError(w, "OTP code has expired", http.StatusBadRequest)
	} else if strings.Contains(err.Error(), "user not found") {
		h.writeError(w, "User not found", http.StatusNotFound)
	} else {
		h.writeError(w, "Authentication error", http.StatusInternalServerError)
	}
}

func (h *Handler) setCORSHeaders(w http.ResponseWriter, domain string) {
	// Set CORS headers based on tenant domain
	origin := "https://" + domain
	if os.Getenv("ENV") == "development" || os.Getenv("ENV") == "test" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionToken string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
		Path:     "/",
		Expires:  expiresAt,
	}
	http.SetCookie(w, cookie)
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour), // Set to past time to delete
	}
	http.SetCookie(w, cookie)
}
