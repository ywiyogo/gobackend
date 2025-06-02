// Improved Architecture Using Handler Registry
// Package api provides a simple HTTP router for handling API requests.
// It allows for easy registration of handlers and serves as a central point for routing HTTP requests.
// It is designed to be used in a web application to manage API endpoints.
package api

import (
	"encoding/json"
	"gobackend/internal/auth"
	"net/http"
)

type Router struct {
	mux  *http.ServeMux
	serv *auth.Service
}

func NewRouter(serv *auth.Service) *Router {
	mux := http.NewServeMux()
	// Register the dashboard handler with authentication middleware
	authMiddleware := auth.NewAuthMiddleware(serv)
	mux.Handle("POST /dashboard", authMiddleware(http.HandlerFunc(Dashboard)))
	return &Router{mux: mux, serv: serv}
}

func (r *Router) Handler() http.Handler {
	return r.mux
}

func (r *Router) AppendHandler(pathPattern string, handler http.HandlerFunc) {
	r.mux.HandleFunc(pathPattern, handler)
}

func (r *Router) AppendHandlerFromMap(routes map[string]http.HandlerFunc) {
	for pathPattern, handler := range routes {
		r.mux.HandleFunc(pathPattern, handler)
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
