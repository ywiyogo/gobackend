package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
		user, otpCode, err = h.authService.RegisterWithOTPInTenant(r.Context(), req.Email, tenantObj.ID)
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
			Message:     "User registered successfully. Please login to continue.",
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
		user, otpCode, err = h.authService.LoginWithOTPInTenant(r.Context(), req.Email, tenantObj.ID)
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
		h.writeError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Get session token from cookie if not provided in request
	sessionToken := req.SessionToken
	if sessionToken == "" {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			h.writeError(w, "Session token required", http.StatusBadRequest)
			return
		}
		sessionToken = cookie.Value
	}

	// Verify OTP
	session, err := h.authService.VerifyOTPInTenant(r.Context(), sessionToken, req.OTPCode, tenantObj.ID)
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

	// Get user information - we need to find the user by ID since we have it from session
	// For now, let's create a basic user response from the session data
	userResponse := &UserResponse{
		ID:        session.UserID.String(),
		Email:     "",         // We'd need to get this from the database if needed
		CreatedAt: time.Now(), // Placeholder
		UpdatedAt: time.Now(), // Placeholder
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
		User:         userResponse,
		SessionToken: session.SessionToken,
		CSRFToken:    session.CsrfToken,
		ExpiresAt:    session.ExpiresAt,
		Message:      "OTP verified successfully",
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
		"message": "Logged out successfully",
	}
	h.writeJSON(w, response, http.StatusOK)
}

// Dashboard handles dashboard access with multi-tenant support
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
		h.writeError(w, "Authentication required", http.StatusUnauthorized)
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
		h.clearSessionCookie(w)
		h.writeError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Get user information - we need to find the user by ID since we have it from session
	// For now, let's create a basic user response from the session data
	userResponse := &UserResponse{
		ID:        session.UserID.String(),
		Email:     "",         // We'd need to get this from the database if needed
		CreatedAt: time.Now(), // Placeholder
		UpdatedAt: time.Now(), // Placeholder
	}

	// Get user sessions
	sessions, err := h.authService.GetUserSessionsInTenant(r.Context(), session.UserID, tenantObj.ID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Dashboard").
			Str("user_id", session.UserID.String()).
			Err(err).
			Msg("Failed to get user sessions")
		// Don't fail the request, just log the error
		sessions = []*sqlc.Session{}
	}

	// Convert sessions to response format
	sessionInfos := make([]*SessionInfo, len(sessions))
	for i, s := range sessions {
		sessionInfos[i] = ToSessionInfo(s, cookie.Value)
	}

	response := map[string]interface{}{
		"user":     userResponse,
		"tenant":   tenantObj.Name,
		"sessions": sessionInfos,
		"message":  "Dashboard data retrieved successfully",
	}

	h.writeJSON(w, response, http.StatusOK)
}

// Helper methods

func (h *Handler) parseRequest(r *http.Request, v interface{}) error {
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		return json.NewDecoder(r.Body).Decode(v)
	}

	// Handle form data for backward compatibility
	if err := r.ParseForm(); err != nil {
		return err
	}

	// Convert form values to JSON and then decode
	formData := make(map[string]string)
	for key, values := range r.Form {
		if len(values) > 0 {
			formData[key] = values[0]
		}
	}

	// Convert to JSON and back to struct
	jsonData, err := json.Marshal(formData)
	if err != nil {
		return err
	}

	return json.Unmarshal(jsonData, v)
}

func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeError(w http.ResponseWriter, message string, status int) {
	errorResponse := &ErrorResponse{
		Error: message,
	}
	h.writeJSON(w, errorResponse, status)
}

func (h *Handler) handleAuthError(w http.ResponseWriter, err error) {
	errMsg := err.Error()

	if strings.Contains(errMsg, "already exists") {
		h.writeError(w, "User already exists in this application", http.StatusConflict)
	} else if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "invalid credentials") {
		h.writeError(w, "Invalid credentials", http.StatusUnauthorized)
	} else if strings.Contains(errMsg, "invalid OTP") {
		h.writeError(w, "Invalid OTP code", http.StatusUnauthorized)
	} else if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "expired") {
		h.writeError(w, errMsg, http.StatusBadRequest)
	} else {
		h.writeError(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *Handler) setCORSHeaders(w http.ResponseWriter, domain string) {
	origin := fmt.Sprintf("https://%s", domain)
	if os.Getenv("ENV") != "production" && strings.Contains(domain, "localhost") {
		origin = fmt.Sprintf("http://%s", domain)
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
		Path:     "/",
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Path:     "/",
	})
}
