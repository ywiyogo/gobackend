package utils

import (
	"net/url"
	"strings"
)

// ExtractDomainFromOrigin extracts the domain from an origin string for tenant matching
// This function preserves ports for localhost development but removes them for production domains
func ExtractDomainFromOrigin(origin string) string {
	if origin == "" {
		return ""
	}

	// Handle localhost and development scenarios - preserve port for local development
	if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
		// Parse URL to extract host with port
		if !strings.HasPrefix(origin, "http") {
			origin = "http://" + origin
		}
		u, err := url.Parse(origin)
		if err != nil {
			return "localhost"
		}
		return u.Host // This preserves the port (e.g., localhost:3000)
	}

	// Parse URL to extract domain
	if !strings.HasPrefix(origin, "http") {
		origin = "https://" + origin
	}

	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}

	domain := strings.TrimPrefix(u.Host, "www.")

	// Remove port if present for production domains
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	return domain
}

// ExtractHostFromURL extracts just the host (domain:port) from a full URL
// This preserves the port number and removes protocol and path
func ExtractHostFromURL(urlStr string) string {
	// Remove protocol if present
	if strings.HasPrefix(urlStr, "http://") {
		urlStr = strings.TrimPrefix(urlStr, "http://")
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = strings.TrimPrefix(urlStr, "https://")
	}
	
	// Remove path if present (take only the host part)
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		urlStr = urlStr[:idx]
	}
	
	return urlStr
}

// ParseOriginHeader parses various origin-related headers and returns a normalized host
// This function handles Origin, Referer, and Host headers consistently
func ParseOriginHeader(originHeader, refererHeader, hostHeader string, isTLS bool) string {
	// First, try the Origin header (most reliable for CORS requests)
	if originHeader != "" {
		return ExtractHostFromURL(originHeader)
	}

	// Second, try the Referer header
	if refererHeader != "" {
		return ExtractHostFromURL(refererHeader)
	}

	// Third, use Host header directly
	if hostHeader != "" {
		return hostHeader
	}

	return ""
}

// IsLocalhost checks if the given domain/host is a localhost variant
func IsLocalhost(domain string) bool {
	return strings.Contains(domain, "localhost") || 
		   strings.Contains(domain, "127.0.0.1") ||
		   strings.HasPrefix(domain, "0.0.0.0")
}

// NormalizeDomain normalizes a domain for consistent tenant matching
// Removes www prefix and handles special cases
func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}
	
	// Remove www prefix
	domain = strings.TrimPrefix(domain, "www.")
	
	// Convert to lowercase for case-insensitive matching
	domain = strings.ToLower(domain)
	
	return domain
}