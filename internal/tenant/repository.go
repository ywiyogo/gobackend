package tenant

import (
	"context"

	"gobackend/internal/db/sqlc"
	"github.com/google/uuid"
)

// Repository defines the interface for tenant data access operations
type Repository interface {
	// GetTenantByDomain retrieves a tenant by domain name
	GetTenantByDomain(ctx context.Context, domain string) (sqlc.Tenant, error)

	// GetTenantByAPIKey retrieves a tenant by API key
	GetTenantByAPIKey(ctx context.Context, apiKey string) (sqlc.Tenant, error)

	// GetAllTenants retrieves all tenants
	GetAllTenants(ctx context.Context) ([]sqlc.Tenant, error)

	// GetTenantByID retrieves a tenant by ID
	GetTenantByID(ctx context.Context, id uuid.UUID) (sqlc.Tenant, error)

	// CreateTenant creates a new tenant with the provided parameters
	CreateTenant(ctx context.Context, params sqlc.CreateTenantParams) (sqlc.Tenant, error)

	// UpdateTenant updates a tenant with the provided parameters
	UpdateTenant(ctx context.Context, params sqlc.UpdateTenantParams) (sqlc.Tenant, error)

	// UpdateTenantSettings updates the settings for a tenant
	UpdateTenantSettings(ctx context.Context, params sqlc.UpdateTenantSettingsParams) error

	// DeleteTenant deletes a tenant by ID
	DeleteTenant(ctx context.Context, id uuid.UUID) error
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

// GetAllTenants retrieves all tenants
func (r *SQLCRepository) GetAllTenants(ctx context.Context) ([]sqlc.Tenant, error) {
	return r.queries.ListTenants(ctx)
}

// GetTenantByID retrieves a tenant by ID
func (r *SQLCRepository) GetTenantByID(ctx context.Context, id uuid.UUID) (sqlc.Tenant, error) {
	return r.queries.GetTenantByID(ctx, id)
}

// UpdateTenant updates a tenant with the provided parameters
func (r *SQLCRepository) UpdateTenant(ctx context.Context, params sqlc.UpdateTenantParams) (sqlc.Tenant, error) {
	return r.queries.UpdateTenant(ctx, params)
}

// DeleteTenant deletes a tenant by ID
func (r *SQLCRepository) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteTenantByID(ctx, id)
}
