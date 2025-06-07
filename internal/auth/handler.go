package auth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.service.Register(w, r); err != nil {
		log.Error().
			Str("pkg", "auth").
			Str("method", "Register").
			Err(err).
			Msg("Registration failed")

		// Handle different error types with appropriate status codes
		errMsg := err.Error()
		if strings.Contains(errMsg, "email is required") ||
			strings.Contains(errMsg, "invalid email format") ||
			strings.Contains(errMsg, "invalid password format") {
			http.Error(w, errMsg, http.StatusBadRequest)
		} else if strings.Contains(errMsg, "email already exists") {
			http.Error(w, errMsg, http.StatusConflict)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.service.Login(w, r); err != nil {
		log.Error().
			Str("pkg", "auth").
			Str("method", "Login").
			Err(err).
			Msg("Login failed")

		// Handle different error types with appropriate status codes
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid password") ||
			strings.Contains(errMsg, "invalid email") {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
}

func (h *Handler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Invalid session token in cookie", http.StatusBadRequest)
		return
	}

	otpCode := r.FormValue("otp_code")
	if len(otpCode) != 6 {
		http.Error(w, "Invalid OTP format", http.StatusBadRequest)
		return
	}

	newSessionToken, err := h.service.VerifyOTP(r.Context(), sessionToken.Value, otpCode)
	if err != nil {
		log.Error().
			Str("pkg", "auth").
			Str("method", "VerifyOTP").
			Err(err).
			Msgf("OTP verification failed %v", err)
		http.Error(w, "OTP verification failed", http.StatusUnauthorized)
		return
	}

	// Get CSRF token for the new session
	csrfToken, err := h.service.GetCSRFTokenBySessionToken(r.Context(), newSessionToken)
	if err != nil {
		log.Error().
			Str("pkg", "auth").
			Str("method", "VerifyOTP").
			Err(err).
			Msg("Error retrieving CSRF token")
		http.Error(w, "Error setting up session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    newSessionToken,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production", // Use secure cookies in production
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OTP verified successfully, new session token set in cookie. CSRF: %s", csrfToken)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.service.Logout(w, r); err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "Logout").
			Err(err).
			Msg("Logout failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
