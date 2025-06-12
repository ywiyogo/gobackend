package tenant

import (
	"gobackend/internal/db/sqlc"
)

// TenantSettings represents the configurable settings for a tenant
type TenantSettings struct {
	OTPEnabled               bool              `json:"otp_enabled"`
	SessionTimeoutMinutes    int               `json:"session_timeout_minutes"`
	AllowedOrigins           []string          `json:"allowed_origins,omitempty"`
	RateLimitPerMinute       int               `json:"rate_limit_per_minute"`
	RequireEmailVerification bool              `json:"require_email_verification"`
	CustomBranding           map[string]string `json:"custom_branding,omitempty"`
}

// DefaultTenantSettings returns the default settings for a new tenant
func DefaultTenantSettings() *TenantSettings {
	return &TenantSettings{
		OTPEnabled:               false,
		SessionTimeoutMinutes:    1440, // 24 hours
		AllowedOrigins:           []string{},
		RateLimitPerMinute:       60,
		RequireEmailVerification: false,
		CustomBranding:           make(map[string]string),
	}
}

// CreateTenantRequest represents the request to create a new tenant
type CreateTenantRequest struct {
	Name      string          `json:"name" validate:"required,min=1,max=255"`
	Domain    string          `json:"domain" validate:"required,fqdn"`
	Subdomain *string         `json:"subdomain,omitempty" validate:"omitempty,min=1,max=100"`
	Settings  *TenantSettings `json:"settings,omitempty"`
}

// UpdateTenantRequest represents the request to update tenant settings
type UpdateTenantRequest struct {
	Name     *string         `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Settings *TenantSettings `json:"settings,omitempty"`
	IsActive *bool           `json:"is_active,omitempty"`
}

// TenantResponse represents the response format for tenant data
type TenantResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Domain    string          `json:"domain"`
	Subdomain *string         `json:"subdomain,omitempty"`
	Settings  *TenantSettings `json:"settings,omitempty"`
	IsActive  bool            `json:"is_active"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

// ToResponse converts a SQLC Tenant model to a TenantResponse
func ToResponse(tenant *sqlc.Tenant, settings *TenantSettings) *TenantResponse {
	response := &TenantResponse{
		ID:       tenant.ID.String(),
		Name:     tenant.Name,
		Domain:   tenant.Domain,
		Settings: settings,
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

	return response
}
