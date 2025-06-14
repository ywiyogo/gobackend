package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
)

const pkgName = "tenant"

// Service handles tenant management operations
type Service struct {
	repo  Repository
	cache map[string]*sqlc.Tenant
	mutex sync.RWMutex
}

// NewService creates a new tenant service instance
func NewService(queries *sqlc.Queries) *Service {
	return &Service{
		repo:  NewRepository(queries),
		cache: make(map[string]*sqlc.Tenant),
	}
}

// NewServiceWithRepository creates a new tenant service instance with a custom repository
func NewServiceWithRepository(repo Repository) *Service {
	return &Service{
		repo:  repo,
		cache: make(map[string]*sqlc.Tenant),
	}
}

// GetTenantByDomain retrieves a tenant by domain name with caching
func (s *Service) GetTenantByDomain(origin string) (*sqlc.Tenant, error) {
	domain := utils.ExtractDomainFromOrigin(origin)
	if domain == "" {
		return nil, fmt.Errorf("invalid origin: %s", origin)
	}

	// Check cache first
	s.mutex.RLock()
	if tenant, exists := s.cache[domain]; exists {
		s.mutex.RUnlock()
		return tenant, nil
	}
	s.mutex.RUnlock()

	// Query database
	tenantData, err := s.repo.GetTenantByDomain(context.Background(), domain)
	if err != nil {
		// Check if this is a database connection issue or missing table
		errMsg := err.Error()
		if strings.Contains(errMsg, "connection") ||
			strings.Contains(errMsg, "connect") ||
			strings.Contains(errMsg, "database") ||
			strings.Contains(errMsg, "does not exist") ||
			strings.Contains(errMsg, "relation") {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "GetTenantByDomain").
				Str("domain", domain).
				Err(err).
				Msg("Database connection or schema issue")
			return nil, fmt.Errorf("database connection error or missing migrations. Please check database connection and run migrations: %w", err)
		}

		// This is likely a "no rows found" error - actual missing tenant
		log.Debug().
			Str("pkg", pkgName).
			Str("method", "GetTenantByDomain").
			Str("domain", domain).
			Err(err).
			Msg("Tenant not found for domain")
		return nil, fmt.Errorf("tenant not found for domain %s: %w", domain, err)
	}

	// Cache the result
	s.mutex.Lock()
	s.cache[domain] = &tenantData
	s.mutex.Unlock()

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "GetTenantByDomain").
		Str("domain", domain).
		Str("tenant_name", tenantData.Name).
		Msg("Tenant found and cached")

	return &tenantData, nil
}

// GetTenantByAPIKey retrieves a tenant by API key
func (s *Service) GetTenantByAPIKey(apiKey string) (*sqlc.Tenant, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}

	tenantData, err := s.repo.GetTenantByAPIKey(context.Background(), apiKey)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetTenantByAPIKey").
			Err(err).
			Msg("Tenant not found for API key")
		return nil, fmt.Errorf("tenant not found for API key: %w", err)
	}

	return &tenantData, nil
}

// CheckDatabaseConnectivity verifies database connection and schema
func (s *Service) CheckDatabaseConnectivity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try a simple query to check if tenants table exists and is accessible
	_, err := s.repo.GetTenantByDomain(ctx, "connectivity-test-domain-that-should-not-exist")
	if err != nil {
		errMsg := err.Error()
		// If we get "no rows" error, it means the table exists and query worked
		if strings.Contains(errMsg, "no rows") || strings.Contains(errMsg, "not found") {
			return nil // Database is working, just no tenant found (expected)
		}
		// Other errors indicate real database issues
		return fmt.Errorf("database connectivity check failed: %w", err)
	}
	return nil
}

// HasTenants checks if the tenants table has any data
func (s *Service) HasTenants() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tenants, err := s.repo.GetAllTenants(ctx)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "HasTenants").
			Err(err).
			Msg("Failed to check if tenants exist")
		return false, fmt.Errorf("failed to check tenants: %w", err)
	}

	return len(tenants) > 0, nil
}

// GetTenantSettings parses and returns tenant settings with defaults
func (s *Service) GetTenantSettings(tenant *sqlc.Tenant) (*TenantSettings, error) {
	return GetTenantSettings(tenant)
}

// CreateTenant creates a new tenant with the provided settings
func (s *Service) CreateTenant(req *CreateTenantRequest) (*sqlc.Tenant, error) {
	// Generate secure API key
	apiKey, err := utils.GenerateSecureToken(32)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenant").
			Err(err).
			Msg("Failed to generate API key")
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Prepare settings
	var settingsJSON []byte
	if req.Settings != nil {
		settingsJSON, err = json.Marshal(req.Settings)
	} else {
		defaultSettings := DefaultTenantSettings()
		settingsJSON, err = json.Marshal(defaultSettings)
	}
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenant").
			Err(err).
			Msg("Failed to marshal tenant settings")
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Prepare subdomain
	var subdomain pgtype.Text
	if req.Subdomain != nil {
		subdomain = pgtype.Text{String: *req.Subdomain, Valid: true}
	}

	// Create tenant in database
	tenantData, err := s.repo.CreateTenant(context.Background(), sqlc.CreateTenantParams{
		Name:      req.Name,
		Domain:    req.Domain,
		Subdomain: subdomain,
		ApiKey:    apiKey,
		Settings:  settingsJSON,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenant").
			Str("domain", req.Domain).
			Err(err).
			Msg("Failed to create tenant in database")
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Clear cache to ensure fresh data on next lookup
	s.clearCache()

	log.Info().
		Str("pkg", pkgName).
		Str("method", "CreateTenant").
		Str("tenant_id", tenantData.ID.String()).
		Str("domain", tenantData.Domain).
		Msg("Tenant created successfully")

	return &tenantData, nil
}

// CreateTenantAdmin creates a new tenant (admin API version)
func (s *Service) CreateTenantAdmin(ctx context.Context, req *CreateTenantRequest) (*sqlc.Tenant, error) {
	// Generate secure API key
	apiKey, err := utils.GenerateSecureToken(32)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenantAdmin").
			Err(err).
			Msg("Failed to generate API key")
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Prepare settings with admin email
	var settings *TenantSettings
	if req.Settings != nil {
		settings = req.Settings
	} else {
		settings = DefaultTenantSettings()
	}

	// Convert settings to map for JSON storage, including admin email
	settingsMap := map[string]interface{}{
		"otp_enabled":                settings.OTPEnabled,
		"session_timeout_minutes":    settings.SessionTimeoutMinutes,
		"allowed_origins":            settings.AllowedOrigins,
		"rate_limit_per_minute":      settings.RateLimitPerMinute,
		"require_email_verification": settings.RequireEmailVerification,
		"custom_branding":            settings.CustomBranding,
		"admin_email":                req.AdminEmail,
	}

	settingsJSON, err := json.Marshal(settingsMap)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenantAdmin").
			Err(err).
			Msg("Failed to marshal tenant settings")
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Prepare subdomain
	var subdomain pgtype.Text
	if req.Subdomain != nil {
		subdomain = pgtype.Text{String: *req.Subdomain, Valid: true}
	}

	// Create tenant in database
	sqlcTenant, err := s.repo.CreateTenant(ctx, sqlc.CreateTenantParams{
		Name:      req.Name,
		Domain:    req.Domain,
		Subdomain: subdomain,
		ApiKey:    apiKey,
		Settings:  settingsJSON,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "CreateTenantAdmin").
			Str("domain", req.Domain).
			Err(err).
			Msg("Failed to create tenant in database")
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Clear cache to ensure fresh data on next lookup
	s.clearCache()

	log.Info().
		Str("pkg", pkgName).
		Str("method", "CreateTenantAdmin").
		Str("tenant_id", sqlcTenant.ID.String()).
		Str("domain", sqlcTenant.Domain).
		Msg("Tenant created successfully")

	return &sqlcTenant, nil
}

// UpdateTenantSettings updates the settings for a tenant
func (s *Service) UpdateTenantSettings(tenantID uuid.UUID, settings *TenantSettings) error {
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	err = s.repo.UpdateTenantSettings(context.Background(), sqlc.UpdateTenantSettingsParams{
		ID:       tenantID,
		Settings: settingsJSON,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "UpdateTenantSettings").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to update tenant settings")
		return fmt.Errorf("failed to update tenant settings: %w", err)
	}

	// Clear cache to ensure fresh data
	s.clearCache()

	log.Info().
		Str("pkg", pkgName).
		Str("method", "UpdateTenantSettings").
		Str("tenant_id", tenantID.String()).
		Msg("Tenant settings updated successfully")

	return nil
}

// IsActive checks if a tenant is active
func (s *Service) IsActive(tenant *sqlc.Tenant) bool {
	return tenant.IsActive.Valid && tenant.IsActive.Bool
}

// GetSubdomain returns the subdomain if it exists
func (s *Service) GetSubdomain(tenant *sqlc.Tenant) string {
	if tenant.Subdomain.Valid {
		return tenant.Subdomain.String
	}
	return ""
}

// GetCreatedAt returns the creation timestamp
func (s *Service) GetCreatedAt(tenant *sqlc.Tenant) time.Time {
	if tenant.CreatedAt.Valid {
		return tenant.CreatedAt.Time
	}
	return time.Time{}
}

// GetUpdatedAt returns the last update timestamp
func (s *Service) GetUpdatedAt(tenant *sqlc.Tenant) time.Time {
	if tenant.UpdatedAt.Valid {
		return tenant.UpdatedAt.Time
	}
	return time.Time{}
}

// clearCache removes all cached tenants (thread-safe)
func (s *Service) clearCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.cache = make(map[string]*sqlc.Tenant)

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "clearCache").
		Msg("Tenant cache cleared")
}

// ClearCacheForDomain removes a specific domain from cache (thread-safe)
func (s *Service) ClearCacheForDomain(domain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.cache, domain)

	log.Debug().
		Str("pkg", pkgName).
		Str("method", "ClearCacheForDomain").
		Str("domain", domain).
		Msg("Tenant cache cleared for domain")
}

// GetAllTenants retrieves all tenants from the database
func (s *Service) GetAllTenants(ctx context.Context) ([]*sqlc.Tenant, error) {
	sqlcTenants, err := s.repo.GetAllTenants(ctx)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetAllTenants").
			Err(err).
			Msg("Failed to get all tenants")
		return nil, fmt.Errorf("failed to get all tenants: %w", err)
	}

	var tenants []*sqlc.Tenant
	for i := range sqlcTenants {
		tenants = append(tenants, &sqlcTenants[i])
	}

	return tenants, nil
}

// GetTenantByID retrieves a tenant by ID
func (s *Service) GetTenantByID(ctx context.Context, tenantID uuid.UUID) (*sqlc.Tenant, error) {
	sqlcTenant, err := s.repo.GetTenantByID(ctx, tenantID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "GetTenantByID").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to get tenant by ID")
		return nil, fmt.Errorf("failed to get tenant by ID: %w", err)
	}

	return &sqlcTenant, nil
}

// UpdateTenant updates an existing tenant
func (s *Service) UpdateTenant(ctx context.Context, tenantID uuid.UUID, req *UpdateTenantRequest) (*sqlc.Tenant, error) {
	// Get existing tenant
	existing, err := s.repo.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing tenant: %w", err)
	}

	// Apply updates
	name := existing.Name
	domain := existing.Domain
	subdomain := existing.Subdomain
	isActive := existing.IsActive

	if req.Name != nil {
		name = *req.Name
	}
	if req.Domain != nil {
		domain = *req.Domain
	}
	if req.Subdomain != nil {
		subdomain = pgtype.Text{String: *req.Subdomain, Valid: true}
	}
	if req.IsActive != nil {
		isActive = pgtype.Bool{Bool: *req.IsActive, Valid: true}
	}

	// Update tenant in database
	sqlcTenant, err := s.repo.UpdateTenant(ctx, sqlc.UpdateTenantParams{
		ID:        tenantID,
		Name:      name,
		Domain:    domain,
		Subdomain: subdomain,
		IsActive:  isActive,
	})
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "UpdateTenant").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to update tenant in database")
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	// Update settings if provided
	if req.Settings != nil || req.AdminEmail != nil {
		// Get current settings to merge with updates
		currentSettings := make(map[string]interface{})
		if len(sqlcTenant.Settings) > 0 {
			json.Unmarshal(sqlcTenant.Settings, &currentSettings)
		}

		// Update settings if provided
		if req.Settings != nil {
			currentSettings["otp_enabled"] = req.Settings.OTPEnabled
			currentSettings["session_timeout_minutes"] = req.Settings.SessionTimeoutMinutes
			currentSettings["allowed_origins"] = req.Settings.AllowedOrigins
			currentSettings["rate_limit_per_minute"] = req.Settings.RateLimitPerMinute
			currentSettings["require_email_verification"] = req.Settings.RequireEmailVerification
			currentSettings["custom_branding"] = req.Settings.CustomBranding
		}

		// Update admin email if provided
		if req.AdminEmail != nil {
			currentSettings["admin_email"] = *req.AdminEmail
		}

		settingsJSON, err := json.Marshal(currentSettings)
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "UpdateTenant").
				Str("tenant_id", tenantID.String()).
				Err(err).
				Msg("Failed to marshal tenant settings")
			return nil, fmt.Errorf("failed to marshal settings: %w", err)
		}

		err = s.repo.UpdateTenantSettings(ctx, sqlc.UpdateTenantSettingsParams{
			ID:       tenantID,
			Settings: settingsJSON,
		})
		if err != nil {
			log.Error().
				Str("pkg", pkgName).
				Str("method", "UpdateTenant").
				Str("tenant_id", tenantID.String()).
				Err(err).
				Msg("Failed to update tenant settings")
			return nil, fmt.Errorf("failed to update tenant settings: %w", err)
		}

		// Get updated tenant with new settings
		sqlcTenant, err = s.repo.GetTenantByID(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to get updated tenant: %w", err)
		}
	}

	// Clear cache to ensure fresh data
	s.clearCache()

	log.Info().
		Str("pkg", pkgName).
		Str("method", "UpdateTenant").
		Str("tenant_id", tenantID.String()).
		Msg("Tenant updated successfully")

	return &sqlcTenant, nil
}

// DeleteTenant deletes a tenant by ID
func (s *Service) DeleteTenant(ctx context.Context, tenantID uuid.UUID) error {
	err := s.repo.DeleteTenant(ctx, tenantID)
	if err != nil {
		log.Error().
			Str("pkg", pkgName).
			Str("method", "DeleteTenant").
			Str("tenant_id", tenantID.String()).
			Err(err).
			Msg("Failed to delete tenant")
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	// Clear cache to ensure fresh data
	s.clearCache()

	log.Info().
		Str("pkg", pkgName).
		Str("method", "DeleteTenant").
		Str("tenant_id", tenantID.String()).
		Msg("Tenant deleted successfully")

	return nil
}

// GetCacheStats returns cache statistics for monitoring
func (s *Service) GetCacheStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"cached_tenants": len(s.cache),
		"domains": func() []string {
			domains := make([]string, 0, len(s.cache))
			for domain := range s.cache {
				domains = append(domains, domain)
			}
			return domains
		}(),
	}
}
