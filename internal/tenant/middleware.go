package tenant

import (
	"context"
	"net/http"
	"strings"

	"gobackend/internal/db/sqlc"
	"gobackend/internal/utils"

	"github.com/rs/zerolog/log"
)

const middlewarePkgName = "tenant"

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// TenantContextKey is the key used to store tenant information in request context
const TenantContextKey contextKey = "tenant"

// TenantMiddleware is a middleware that extracts tenant information from the request
// and adds it to the request context. It supports domain-based tenant resolution.
func TenantMiddleware(tenantService *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the origin from various headers (in order of preference)
			origin := utils.ParseOriginHeader(
				r.Header.Get("Origin"),
				r.Header.Get("Referer"),
				r.Header.Get("Host"),
				r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			)

			if origin == "" {
				log.Warn().
					Str("pkg", middlewarePkgName).
					Str("method", "TenantMiddleware").
					Str("path", r.URL.Path).
					Msg("No origin found in request headers")
				http.Error(w, "Origin header required", http.StatusBadRequest)
				return
			}

			// Resolve tenant by domain
			tenant, err := tenantService.GetTenantByDomain(origin)
			if err != nil {
				errMsg := err.Error()
				// Check if this is a database/infrastructure issue
				if strings.Contains(errMsg, "database connection error") ||
					strings.Contains(errMsg, "missing migrations") {
					log.Error().
						Str("pkg", middlewarePkgName).
						Str("method", "TenantMiddleware").
						Str("origin", origin).
						Str("path", r.URL.Path).
						Err(err).
						Msg("Database or migration issue")
					http.Error(w, "Service temporarily unavailable. Please check database connection and migrations.", http.StatusServiceUnavailable)
					return
				}

				// This is likely a missing tenant
				log.Error().
					Str("pkg", middlewarePkgName).
					Str("method", "TenantMiddleware").
					Str("origin", origin).
					Str("path", r.URL.Path).
					Err(err).
					Msg("Failed to resolve tenant")
				http.Error(w, "Tenant not found", http.StatusNotFound)
				return
			}

			// Check if tenant is active
			if !tenantService.IsActive(tenant) {
				log.Warn().
					Str("pkg", middlewarePkgName).
					Str("method", "TenantMiddleware").
					Str("tenant_id", tenant.ID.String()).
					Str("origin", origin).
					Msg("Inactive tenant attempted access")
				http.Error(w, "Tenant is inactive", http.StatusForbidden)
				return
			}

			// Add tenant to request context
			ctx := context.WithValue(r.Context(), TenantContextKey, tenant)
			r = r.WithContext(ctx)
			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// GetTenantFromContext retrieves the tenant from the request context
func GetTenantFromContext(ctx context.Context) (*sqlc.Tenant, bool) {
	tenant, ok := ctx.Value(TenantContextKey).(*sqlc.Tenant)
	return tenant, ok
}

// RequireTenant is a helper middleware that ensures a tenant is present in the context
func RequireTenant(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenantFromContext(r.Context())
		if !ok || tenant == nil {
			log.Error().
				Str("pkg", middlewarePkgName).
				Str("method", "RequireTenant").
				Str("path", r.URL.Path).
				Msg("No tenant found in request context")
			http.Error(w, "Tenant context required", http.StatusInternalServerError)
			return
		}

		next(w, r)
	}
}

// APIKeyMiddleware is an alternative middleware for API-based tenant resolution
// This can be used for API endpoints that use API keys instead of domain-based resolution
func APIKeyMiddleware(tenantService *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get API key from Authorization header or query parameter
			apiKey := getAPIKeyFromRequest(r)

			if apiKey == "" {
				log.Warn().
					Str("pkg", middlewarePkgName).
					Str("method", "APIKeyMiddleware").
					Str("path", r.URL.Path).
					Msg("No API key found in request")
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			// Resolve tenant by API key
			tenant, err := tenantService.GetTenantByAPIKey(apiKey)
			if err != nil {
				log.Error().
					Str("pkg", middlewarePkgName).
					Str("method", "APIKeyMiddleware").
					Str("path", r.URL.Path).
					Err(err).
					Msg("Failed to resolve tenant by API key")
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			// Check if tenant is active
			if !tenantService.IsActive(tenant) {
				log.Warn().
					Str("pkg", middlewarePkgName).
					Str("method", "APIKeyMiddleware").
					Str("tenant_id", tenant.ID.String()).
					Msg("Inactive tenant attempted API access")
				http.Error(w, "Tenant is inactive", http.StatusForbidden)
				return
			}

			// Add tenant to request context
			ctx := context.WithValue(r.Context(), TenantContextKey, tenant)
			r = r.WithContext(ctx)

			log.Debug().
				Str("pkg", middlewarePkgName).
				Str("method", "APIKeyMiddleware").
				Str("tenant_id", tenant.ID.String()).
				Str("tenant_name", tenant.Name).
				Str("path", r.URL.Path).
				Msg("Tenant resolved via API key")

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// getAPIKeyFromRequest extracts the API key from the request
// Checks Authorization header (Bearer token) and X-API-Key header
func getAPIKeyFromRequest(r *http.Request) string {
	// Check Authorization header for Bearer token
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Check X-API-Key header
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Check query parameter as fallback (less secure, but sometimes needed)
	if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
		return apiKey
	}

	return ""
}

// TenantAwareHandler is a helper type for handlers that need tenant context
type TenantAwareHandler func(w http.ResponseWriter, r *http.Request, tenant *sqlc.Tenant)

// WithTenant wraps a TenantAwareHandler to automatically extract tenant from context
func WithTenant(handler TenantAwareHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenantFromContext(r.Context())
		if !ok || tenant == nil {
			log.Error().
				Str("pkg", middlewarePkgName).
				Str("method", "WithTenant").
				Str("path", r.URL.Path).
				Msg("No tenant found in request context")
			http.Error(w, "Tenant context required", http.StatusInternalServerError)
			return
		}

		handler(w, r, tenant)
	}
}
