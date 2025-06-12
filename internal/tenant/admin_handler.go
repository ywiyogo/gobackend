package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gobackend/internal/db/sqlc"
	"github.com/google/uuid"
)

// AdminHandler handles tenant management API endpoints
type AdminHandler struct {
	service *Service
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(service *Service) *AdminHandler {
	return &AdminHandler{
		service: service,
	}
}



// CreateTenant handles POST /admin/tenants
func (h *AdminHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	// TODO: Add admin authentication/authorization check
	// if !h.isAdmin(r) {
	//     h.sendError(w, http.StatusUnauthorized, "Unauthorized", "Admin access required")
	//     return
	// }

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.sendError(w, http.StatusBadRequest, "Validation Error", "Name is required")
		return
	}
	if req.Domain == "" {
		h.sendError(w, http.StatusBadRequest, "Validation Error", "Domain is required")
		return
	}
	if req.AdminEmail == "" {
		h.sendError(w, http.StatusBadRequest, "Validation Error", "Admin email is required")
		return
	}

	// Check if tenant with domain already exists
	existing, err := h.service.GetTenantByDomain(req.Domain)
	if err == nil && existing != nil {
		h.sendError(w, http.StatusConflict, "Tenant Exists", fmt.Sprintf("Tenant with domain '%s' already exists", req.Domain))
		return
	}



	// Set default settings if not provided
	if req.Settings == nil {
		req.Settings = &TenantSettings{
			OTPEnabled:               true,
			SessionTimeoutMinutes:    720,
			RateLimitPerMinute:       100,
			RequireEmailVerification: false,
			AllowedOrigins:           []string{},
			CustomBranding:           make(map[string]string),
		}
	}

	createReq := &CreateTenantRequest{
		Name:      req.Name,
		Domain:    req.Domain,
		Subdomain: req.Subdomain,
		Settings:  req.Settings,
	}

	createdTenant, err := h.service.CreateTenantAdmin(r.Context(), createReq)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Creation Failed", err.Error())
		return
	}

	response := h.sqlcTenantToResponse(createdTenant)
	h.sendJSON(w, http.StatusCreated, response)
}

// GetTenants handles GET /admin/tenants
func (h *AdminHandler) GetTenants(w http.ResponseWriter, r *http.Request) {
	// TODO: Add admin authentication/authorization check

	tenants, err := h.service.GetAllTenants(r.Context())
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Fetch Failed", err.Error())
		return
	}

	var tenantResponses []TenantResponse
	for _, tenant := range tenants {
		tenantResponses = append(tenantResponses, h.sqlcTenantToResponse(tenant))
	}

	response := TenantsListResponse{
		Tenants: tenantResponses,
		Total:   len(tenantResponses),
	}

	h.sendJSON(w, http.StatusOK, response)
}

// GetTenant handles GET /admin/tenants/{id}
func (h *AdminHandler) GetTenant(w http.ResponseWriter, r *http.Request) {
	// TODO: Add admin authentication/authorization check

	tenantID := h.extractTenantID(r)
	if tenantID == "" {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Tenant ID is required")
		return
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Invalid UUID format")
		return
	}

	tenant, err := h.service.GetTenantByID(r.Context(), tenantUUID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "Tenant Not Found", err.Error())
		return
	}

	response := h.sqlcTenantToResponse(tenant)
	h.sendJSON(w, http.StatusOK, response)
}

// UpdateTenant handles PUT /admin/tenants/{id}
func (h *AdminHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	// TODO: Add admin authentication/authorization check

	tenantID := h.extractTenantID(r)
	if tenantID == "" {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Tenant ID is required")
		return
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Invalid UUID format")
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
		return
	}



	updatedTenant, err := h.service.UpdateTenant(r.Context(), tenantUUID, &req)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Update Failed", err.Error())
		return
	}

	response := h.sqlcTenantToResponse(updatedTenant)
	h.sendJSON(w, http.StatusOK, response)
}

// DeleteTenant handles DELETE /admin/tenants/{id}
func (h *AdminHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	// TODO: Add admin authentication/authorization check

	tenantID := h.extractTenantID(r)
	if tenantID == "" {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Tenant ID is required")
		return
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid ID", "Invalid UUID format")
		return
	}

	err = h.service.DeleteTenant(r.Context(), tenantUUID)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Delete Failed", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper methods

func (h *AdminHandler) extractTenantID(r *http.Request) string {
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) >= 4 && parts[1] == "admin" && parts[2] == "tenants" {
		return parts[3]
	}
	return ""
}



func (h *AdminHandler) sqlcTenantToResponse(tenant *sqlc.Tenant) TenantResponse {
	response := TenantResponse{
		ID:       tenant.ID.String(),
		Name:     tenant.Name,
		Domain:   tenant.Domain,
		APIKey:   tenant.ApiKey,
		IsActive: tenant.IsActive.Valid && tenant.IsActive.Bool,
	}

	if tenant.Subdomain.Valid {
		response.Subdomain = &tenant.Subdomain.String
	}

	if tenant.CreatedAt.Valid {
		response.CreatedAt = tenant.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	if tenant.UpdatedAt.Valid {
		response.UpdatedAt = tenant.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	// Parse settings from JSON
	response.Settings = make(map[string]interface{})
	if len(tenant.Settings) > 0 {
		json.Unmarshal(tenant.Settings, &response.Settings)
	}

	// Extract admin email from settings if available
	if adminEmail, ok := response.Settings["admin_email"].(string); ok {
		response.AdminEmail = adminEmail
	}

	return response
}

func (h *AdminHandler) sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *AdminHandler) sendError(w http.ResponseWriter, statusCode int, error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   error,
		Message: message,
	})
}

// generateAPIKey generates a secure API key for tenants
func generateAPIKey() (string, error) {
	// Use the same logic as in sync.go
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}