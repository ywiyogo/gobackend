package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

type TenantConfig struct {
	Name       string                 `yaml:"name"`
	Domain     string                 `yaml:"domain"`
	Subdomain  *string                `yaml:"subdomain,omitempty"`
	Settings   map[string]interface{} `yaml:"settings"`
	AdminEmail string                 `yaml:"admin_email"`
	IsActive   bool                   `yaml:"is_active"`
}

type TenantsConfig struct {
	Tenants []TenantConfig `yaml:"tenants"`
}

type TenantSyncService struct {
	pool *pgxpool.Pool
}

func NewTenantSyncService(pool *pgxpool.Pool) *TenantSyncService {
	return &TenantSyncService{pool: pool}
}

// SyncTenantsFromConfig reads the tenants.yaml file and syncs tenants to database
func (s *TenantSyncService) SyncTenantsFromConfig(configPath string) error {
	log.Printf("Loading tenants configuration from: %s", configPath)

	// Read the YAML file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the YAML
	var config TenantsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	log.Printf("Found %d tenants in configuration", len(config.Tenants))

	ctx := context.Background()

	// Sync each tenant
	for _, tenantConfig := range config.Tenants {
		if err := s.syncTenant(ctx, tenantConfig); err != nil {
			log.Printf("❌ Failed to sync tenant %s: %v", tenantConfig.Name, err)
			continue
		}
		log.Printf("✅ Synced tenant: %s (%s)", tenantConfig.Name, tenantConfig.Domain)
	}

	return nil
}

// syncTenant creates or updates a single tenant
func (s *TenantSyncService) syncTenant(ctx context.Context, config TenantConfig) error {
	// Convert settings to JSON first
	settingsJSON, err := json.Marshal(config.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Check if tenant exists by domain
	var existingID string
	var existingAPIKey string
	err = s.pool.QueryRow(ctx, "SELECT id, api_key FROM tenants WHERE domain = $1", config.Domain).Scan(&existingID, &existingAPIKey)

	if err == pgx.ErrNoRows {
		// Tenant doesn't exist, create it
		return s.createTenant(ctx, config, settingsJSON)
	} else if err != nil {
		return fmt.Errorf("failed to check tenant existence: %w", err)
	}

	// Tenant exists, update it
	return s.updateTenant(ctx, existingID, config, settingsJSON)
}

// createTenant creates a new tenant
func (s *TenantSyncService) createTenant(ctx context.Context, config TenantConfig, settingsJSON []byte) error {
	apiKey, err := s.generateAPIKey()
	if err != nil {
		return fmt.Errorf("failed to generate API key: %w", err)
	}

	query := `
		INSERT INTO tenants (name, domain, subdomain, api_key, settings, is_active) 
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = s.pool.Exec(ctx, query,
		config.Name,
		config.Domain,
		config.Subdomain,
		apiKey,
		settingsJSON,
		config.IsActive)

	if err != nil {
		return fmt.Errorf("failed to insert tenant: %w", err)
	}

	log.Printf("🔑 Generated API key for %s: %s", config.Name, apiKey)
	return nil
}

// updateTenant updates an existing tenant
func (s *TenantSyncService) updateTenant(ctx context.Context, tenantID string, config TenantConfig, settingsJSON []byte) error {
	query := `
		UPDATE tenants 
		SET name = $1, subdomain = $2, settings = $3, is_active = $4, updated_at = NOW()
		WHERE id = $5`

	_, err := s.pool.Exec(ctx, query,
		config.Name,
		config.Subdomain,
		settingsJSON,
		config.IsActive,
		tenantID)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	return nil
}

// generateAPIKey generates a secure random API key
func (s *TenantSyncService) generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetTenantByDomain retrieves a tenant by domain
func (s *TenantSyncService) GetTenantByDomain(ctx context.Context, domain string) (*TenantConfig, error) {
	var name, apiKey string
	var subdomain pgtype.Text
	var settingsJSON []byte
	var isActive bool

	query := "SELECT name, subdomain, api_key, settings, is_active FROM tenants WHERE domain = $1"
	err := s.pool.QueryRow(ctx, query, domain).Scan(&name, &subdomain, &apiKey, &settingsJSON, &isActive)

	if err != nil {
		return nil, err
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(settingsJSON, &settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	var subdomainPtr *string
	if subdomain.Valid {
		subdomainPtr = &subdomain.String
	}

	return &TenantConfig{
		Name:      name,
		Domain:    domain,
		Subdomain: subdomainPtr,
		Settings:  settings,
		IsActive:  isActive,
	}, nil
}
