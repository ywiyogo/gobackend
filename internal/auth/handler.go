package auth

import (
	"fmt"
	"net/http"

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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    newSessionToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OTP verified successfully, new session token set in cookie")
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
