package tenant

import (
	"encoding/json"

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

// Helper functions for working with SQLC Tenant model

// GetTenantSettings parses tenant settings from JSON with defaults
func GetTenantSettings(tenant *sqlc.Tenant) (*TenantSettings, error) {
	settings := DefaultTenantSettings()

	if len(tenant.Settings) > 0 {
		settingsStr := string(tenant.Settings)
		if settingsStr != "" && settingsStr != "{}" {
			if err := json.Unmarshal(tenant.Settings, settings); err != nil {
				return nil, err
			}
		}
	}

	// Ensure defaults are set for any missing values
	if settings.SessionTimeoutMinutes == 0 {
		settings.SessionTimeoutMinutes = 1440 // 24 hours
	}
	if settings.RateLimitPerMinute == 0 {
		settings.RateLimitPerMinute = 60
	}
	if settings.AllowedOrigins == nil {
		settings.AllowedOrigins = []string{}
	}
	if settings.CustomBranding == nil {
		settings.CustomBranding = make(map[string]string)
	}

	return settings, nil
}

// Request/Response types for tenant admin API

// CreateTenantRequest represents the request body for creating a tenant
type CreateTenantRequest struct {
	Name       string          `json:"name" validate:"required"`
	Domain     string          `json:"domain" validate:"required"`
	Subdomain  *string         `json:"subdomain,omitempty"`
	Settings   *TenantSettings `json:"settings,omitempty"`
	AdminEmail string          `json:"admin_email" validate:"required,email"`
	IsActive   bool            `json:"is_active"`
}

// UpdateTenantRequest represents the request body for updating a tenant
type UpdateTenantRequest struct {
	Name       *string         `json:"name,omitempty"`
	Domain     *string         `json:"domain,omitempty"`
	Subdomain  *string         `json:"subdomain,omitempty"`
	Settings   *TenantSettings `json:"settings,omitempty"`
	AdminEmail *string         `json:"admin_email,omitempty"`
	IsActive   *bool           `json:"is_active,omitempty"`
}

// TenantResponse represents the response body for tenant operations
type TenantResponse struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Domain     string                 `json:"domain"`
	Subdomain  *string                `json:"subdomain,omitempty"`
	APIKey     string                 `json:"api_key"`
	Settings   map[string]interface{} `json:"settings"`
	AdminEmail string                 `json:"admin_email"`
	IsActive   bool                   `json:"is_active"`
	CreatedAt  string                 `json:"created_at"`
	UpdatedAt  string                 `json:"updated_at"`
}

// TenantsListResponse represents the response for listing tenants
type TenantsListResponse struct {
	Tenants []TenantResponse `json:"tenants"`
	Total   int              `json:"total"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
