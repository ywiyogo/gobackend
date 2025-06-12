// Improved Architecture Using Handler Registry
// Package api provides a simple HTTP router for handling API requests.
// It allows for easy registration of handlers and serves as a central point for routing HTTP requests.
// It is designed to be used in a web application to manage API endpoints.
package api

import (
	"encoding/json"
	"gobackend/internal/auth"
	"net/http"
	"time"
)

const (
	rateLimitRequests = 50 // 50 requests per minute
	rateLimitWindow   = time.Minute
)

type Router struct {
	mux  *http.ServeMux
	serv *auth.Service
}

func NewRouter(serv *auth.Service) *Router {
	mux := http.NewServeMux()
	return &Router{mux: mux, serv: serv}
}

func (r *Router) Handler() http.Handler {
	return r.mux
}

func (r *Router) AppendHandler(pathPattern string, handler http.HandlerFunc) {
	limiter := auth.NewRateLimiter(rateLimitRequests, rateLimitWindow)
	rateLimitMiddleware := auth.RateLimitMiddleware(limiter)
	r.mux.Handle(pathPattern, rateLimitMiddleware(http.HandlerFunc(handler)))
}
func (r *Router) AppendProtectedHandler(pathPattern string, handler http.HandlerFunc) {
	limiter := auth.NewRateLimiter(rateLimitRequests, rateLimitWindow)
	rateLimitMiddleware := auth.RateLimitMiddleware(limiter)
	authMiddleware := auth.NewAuthMiddleware(r.serv)
	r.mux.Handle(pathPattern, rateLimitMiddleware(authMiddleware(http.HandlerFunc(handler))))
}

func (r *Router) AppendHandlerFromMap(routes map[string]http.HandlerFunc) {
	limiter := auth.NewRateLimiter(rateLimitRequests, rateLimitWindow)
	rateLimitMiddleware := auth.RateLimitMiddleware(limiter)
	for pathPattern, handler := range routes {
		r.mux.Handle(pathPattern, rateLimitMiddleware(http.HandlerFunc(handler)))
	}
}

// AppendHandlerWithoutMiddleware adds handlers that bypass all middleware (for health checks)
func (r *Router) AppendHandlerWithoutMiddleware(pathPattern string, handler http.HandlerFunc) {
	r.mux.Handle(pathPattern, http.HandlerFunc(handler))
}

// AppendHandlerFromMapWithoutMiddleware adds multiple handlers that bypass all middleware
func (r *Router) AppendHandlerFromMapWithoutMiddleware(routes map[string]http.HandlerFunc) {
	for pathPattern, handler := range routes {
		r.mux.Handle(pathPattern, http.HandlerFunc(handler))
	}
}

func (r *Router) AppendProtectedHandlerFromMap(routes map[string]http.HandlerFunc) {
	limiter := auth.NewRateLimiter(rateLimitRequests, rateLimitWindow)
	rateLimitMiddleware := auth.RateLimitMiddleware(limiter)
	authMiddleware := auth.NewAuthMiddleware(r.serv)
	for pathPattern, handler := range routes {
		r.mux.Handle(pathPattern, rateLimitMiddleware(authMiddleware(http.HandlerFunc(handler))))
	}
}

func Dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Dashboard accessed successfully",
	})
}
