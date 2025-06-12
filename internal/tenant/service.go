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

// GetTenantSettings parses and returns tenant settings with defaults
func (s *Service) GetTenantSettings(tenant *sqlc.Tenant) (*TenantSettings, error) {
	settings := DefaultTenantSettings()

	if len(tenant.Settings) > 0 {
		settingsStr := string(tenant.Settings)
		if settingsStr != "" && settingsStr != "{}" {
			if err := json.Unmarshal(tenant.Settings, settings); err != nil {
				log.Error().
					Str("pkg", pkgName).
					Str("method", "GetTenantSettings").
					Str("tenant_id", tenant.ID.String()).
					Err(err).
					Msg("Failed to unmarshal tenant settings")
				return nil, fmt.Errorf("failed to parse tenant settings: %w", err)
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
	settings := req.Settings
	if settings == nil {
		settings = DefaultTenantSettings()
	}

	settingsJSON, err := json.Marshal(settings)
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
