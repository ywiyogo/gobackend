package tenant

import (
	"context"

	"gobackend/internal/db/sqlc"
)

// Repository defines the interface for tenant data access operations
type Repository interface {
	// GetTenantByDomain retrieves a tenant by domain name
	GetTenantByDomain(ctx context.Context, domain string) (sqlc.Tenant, error)

	// GetTenantByAPIKey retrieves a tenant by API key
	GetTenantByAPIKey(ctx context.Context, apiKey string) (sqlc.Tenant, error)

	// CreateTenant creates a new tenant with the provided parameters
	CreateTenant(ctx context.Context, params sqlc.CreateTenantParams) (sqlc.Tenant, error)

	// UpdateTenantSettings updates the settings for a tenant
	UpdateTenantSettings(ctx context.Context, params sqlc.UpdateTenantSettingsParams) error
}

// SQLCRepository implements the Repository interface using SQLC generated queries
type SQLCRepository struct {
	queries *sqlc.Queries
}

// NewRepository creates a new tenant repository instance
func NewRepository(queries *sqlc.Queries) Repository {
	return &SQLCRepository{
		queries: queries,
	}
}

// GetTenantByDomain retrieves a tenant by domain name
func (r *SQLCRepository) GetTenantByDomain(ctx context.Context, domain string) (sqlc.Tenant, error) {
	return r.queries.GetTenantByDomain(ctx, domain)
}

// GetTenantByAPIKey retrieves a tenant by API key
func (r *SQLCRepository) GetTenantByAPIKey(ctx context.Context, apiKey string) (sqlc.Tenant, error) {
	return r.queries.GetTenantByAPIKey(ctx, apiKey)
}

// CreateTenant creates a new tenant with the provided parameters
func (r *SQLCRepository) CreateTenant(ctx context.Context, params sqlc.CreateTenantParams) (sqlc.Tenant, error) {
	return r.queries.CreateTenant(ctx, params)
}

// UpdateTenantSettings updates the settings for a tenant
func (r *SQLCRepository) UpdateTenantSettings(ctx context.Context, params sqlc.UpdateTenantSettingsParams) error {
	return r.queries.UpdateTenantSettings(ctx, params)
}
