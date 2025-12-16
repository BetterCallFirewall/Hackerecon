package utils

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// Operation types for better type safety
type OperationType string

const (
	OperationRead   OperationType = "read"
	OperationCreate OperationType = "create"
	OperationUpdate OperationType = "update"
	OperationDelete OperationType = "delete"
)

type CRUDMapper struct {
	mu sync.RWMutex
}

func NewCRUDMapper() *CRUDMapper {
	return &CRUDMapper{}
}

// MapRequest analyzes HTTP request and maps it to CRUD operation
func (cm *CRUDMapper) MapRequest(method, path string) (resource string, operation OperationType, detected bool) {
	method = strings.ToUpper(method)

	// Extract resource path from URL
	resource = cm.extractResourcePath(path)
	if resource == "" {
		return "", "", false
	}

	// Map HTTP method to CRUD operation
	switch method {
	case "GET":
		operation = OperationRead
	case "POST":
		operation = OperationCreate
	case "PUT", "PATCH":
		operation = OperationUpdate
	case "DELETE":
		operation = OperationDelete
	default:
		operation = OperationType(method) // Unknown operation
	}

	return resource, operation, true
}

// extractResourcePath extracts base resource path from URL
func (cm *CRUDMapper) extractResourcePath(path string) string {
	// Parse URL to handle query parameters
	parsedURL, err := url.Parse(path)
	if err != nil {
		return ""
	}

	path = parsedURL.Path
	if path == "" || path == "/" {
		return ""
	}

	// Remove trailing slash
	path = strings.TrimSuffix(path, "/")

	// Filter out static resources
	if cm.isStaticResource(path) {
		return ""
	}

	// Look for API patterns first
	if strings.HasPrefix(path, "/api/") {
		return cm.extractAPIResource(path)
	}

	// Look for REST patterns - only if first part looks like a resource
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 {
		// Check if second part looks like an ID (numeric or UUID-like)
		if !cm.looksLikeID(parts[1]) {
			return "/" + parts[0] + "/" + parts[1]
		}
		// If second part is ID, return first part as resource
		return "/" + parts[0]
	}

	if len(parts) == 1 && !cm.looksLikeStatic(parts[0]) {
		return "/" + parts[0]
	}

	return ""
}

// isStaticResource checks if path is for static content
func (cm *CRUDMapper) isStaticResource(path string) bool {
	staticPatterns := []string{
		"/static/", "/assets/", "/css/", "/js/", "/img/", "/images/",
		"/public/", "/files/", "/uploads/", "/media/",
	}

	for _, pattern := range staticPatterns {
		if strings.HasPrefix(path, pattern) {
			return true
		}
	}

	// Check file extensions
	if strings.Contains(path, ".") {
		parts := strings.Split(path, ".")
		ext := strings.ToLower(parts[len(parts)-1])
		staticExts := []string{"css", "js", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "ttf"}
		for _, staticExt := range staticExts {
			if ext == staticExt {
				return true
			}
		}
	}

	return false
}

// looksLikeID checks if string looks like an identifier
func (cm *CRUDMapper) looksLikeID(s string) bool {
	// Numeric ID
	if len(s) <= 10 && isNumeric(s) {
		return true
	}

	// UUID-like
	if len(s) >= 8 && len(s) <= 36 && isHexadecimal(s) {
		return true
	}

	return false
}

// looksLikeStatic checks if word is commonly used for static resources
func (cm *CRUDMapper) looksLikeStatic(s string) bool {
	staticWords := []string{"static", "assets", "css", "js", "img", "images", "public", "files"}
	for _, word := range staticWords {
		if s == word {
			return true
		}
	}
	return false
}

// isNumeric checks if string contains only digits
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isHexadecimal checks if string contains only hex characters
func isHexadecimal(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// extractAPIResource handles API path patterns
func (cm *CRUDMapper) extractAPIResource(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/"), "/")

	if len(parts) == 0 {
		return ""
	}

	// Handle versioned APIs
	if parts[0] == "v1" || parts[0] == "v2" {
		if len(parts) >= 2 {
			return "/api/" + parts[0] + "/" + parts[1]
		}
		// Return empty for incomplete versioned API paths like /api/v1/, /api/v2/
		return ""
	}

	// Standard API path
	if parts[0] == "" {
		return ""
	}
	return "/api/" + parts[0]
}

// UpdateResourceMapping updates CRUD mappings in site context
func (cm *CRUDMapper) UpdateResourceMapping(
	siteContext *models.SiteContext,
	method, path string,
) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	resource, operation, detected := cm.MapRequest(method, path)
	if !detected {
		return
	}

	// Get or create resource mapping
	mapping, exists := siteContext.ResourceCRUD[resource]
	if !exists {
		mapping = &models.ResourceMapping{
			ResourcePath: resource,
			Operations:   make(map[string]string),
			RelatedPaths: []string{},
			DetectedAt:   time.Now().Unix(),
		}
		siteContext.ResourceCRUD[resource] = mapping
	}

	// Add operation if not exists
	methodKey := method
	if _, exists := mapping.Operations[methodKey]; !exists {
		mapping.Operations[methodKey] = string(operation)
		mapping.RelatedPaths = appendUnique(mapping.RelatedPaths, path)
	}
}

// appendUnique adds path to slice if not already present
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// HasFullCRUD checks if resource supports all CRUD operations
func (cm *CRUDMapper) HasFullCRUD(mapping *models.ResourceMapping) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	required := []string{"GET", "POST", "PUT", "DELETE"}
	for _, method := range required {
		if _, exists := mapping.Operations[method]; !exists {
			// PATCH can substitute for PUT
			if method == "PUT" && mapping.Operations["PATCH"] != "" {
				continue
			}
			return false
		}
	}
	return true
}

// GetResourceStats returns statistics about detected resources
func (cm *CRUDMapper) GetResourceStats(siteContext *models.SiteContext) map[string]int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := make(map[string]int)
	for _, mapping := range siteContext.ResourceCRUD {
		if cm.HasFullCRUD(mapping) {
			stats["full_crud"]++
		} else {
			stats["partial_crud"]++
		}
	}
	stats["total_resources"] = len(siteContext.ResourceCRUD)

	return stats
}
