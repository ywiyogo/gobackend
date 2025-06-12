package health

import (
	"encoding/json"
	"net/http"
	"time"

	"gobackend/internal/tenant"

	"github.com/rs/zerolog/log"
)

type Handler struct {
	tenantService *tenant.Service
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
	Message   string            `json:"message,omitempty"`
}

func NewHandler(tenantService *tenant.Service) *Handler {
	return &Handler{
		tenantService: tenantService,
	}
}

// Health performs comprehensive health checks
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	checks := make(map[string]string)
	overallStatus := "healthy"
	var message string

	// Check database connectivity
	if err := h.tenantService.CheckDatabaseConnectivity(); err != nil {
		checks["database"] = "unhealthy"
		overallStatus = "unhealthy"
		message = "Database connectivity issues detected. Please check database connection and ensure migrations have been run."
		log.Error().Err(err).Msg("Health check: Database connectivity failed")
	} else {
		checks["database"] = "healthy"
	}

	// Check if basic tenant exists (localhost)
	if overallStatus == "healthy" {
		_, err := h.tenantService.GetTenantByDomain("http://localhost")
		if err != nil {
			checks["default_tenant"] = "unhealthy"
			overallStatus = "degraded"
			if message == "" {
				message = "Default tenant not found. Please ensure database migrations have been run."
			}
			log.Warn().Err(err).Msg("Health check: Default tenant not found")
		} else {
			checks["default_tenant"] = "healthy"
		}
	} else {
		checks["default_tenant"] = "skipped"
	}

	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
		Message:   message,
	}

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	} else if overallStatus == "degraded" {
		statusCode = http.StatusPartialContent
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Simple readiness check
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	// Quick database connectivity check
	if err := h.tenantService.CheckDatabaseConnectivity(); err != nil {
		http.Error(w, "Service not ready: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Simple liveness check
func (h *Handler) Live(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
