package auth

import (
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
			Str("pkg", pkgName).
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
			Str("pkg", pkgName).
			Str("method", "Login").
			Err(err).
			Msg("Login failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
