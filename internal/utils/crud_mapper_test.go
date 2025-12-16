package utils

import (
	"sync"
	"testing"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestCRUDMapper_MapRequest(t *testing.T) {
	mapper := NewCRUDMapper()

	tests := []struct {
		name         string
		method, path string
		wantResource string
		wantOp       OperationType
		wantDetected bool
	}{
		{
			name:         "API users resource",
			method:       "GET",
			path:         "/api/users/123",
			wantResource: "/api/users",
			wantOp:       OperationRead,
			wantDetected: true,
		},
		{
			name:         "API users create",
			method:       "POST",
			path:         "/api/users",
			wantResource: "/api/users",
			wantOp:       OperationCreate,
			wantDetected: true,
		},
		{
			name:         "API users update",
			method:       "PUT",
			path:         "/api/users/456",
			wantResource: "/api/users",
			wantOp:       OperationUpdate,
			wantDetected: true,
		},
		{
			name:         "API users delete",
			method:       "DELETE",
			path:         "/api/users/789",
			wantResource: "/api/users",
			wantOp:       OperationDelete,
			wantDetected: true,
		},
		{
			name:         "Versioned API",
			method:       "GET",
			path:         "/api/v1/posts/123",
			wantResource: "/api/v1/posts",
			wantOp:       OperationRead,
			wantDetected: true,
		},
		{
			name:         "REST pattern",
			method:       "GET",
			path:         "/users/123",
			wantResource: "/users",
			wantOp:       OperationRead,
			wantDetected: true,
		},
		{
			name:         "Query parameters",
			method:       "GET",
			path:         "/api/users/123?include=posts",
			wantResource: "/api/users",
			wantOp:       OperationRead,
			wantDetected: true,
		},
		{
			name:         "Static resource",
			method:       "GET",
			path:         "/static/image.png",
			wantResource: "",
			wantOp:       "",
			wantDetected: false,
		},
		{
			name:         "Root path",
			method:       "GET",
			path:         "/",
			wantResource: "",
			wantOp:       "",
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, op, detected := mapper.MapRequest(tt.method, tt.path)
			assert.Equal(t, tt.wantResource, res)
			assert.Equal(t, tt.wantOp, op)
			assert.Equal(t, tt.wantDetected, detected)
		})
	}
}

func TestCRUDMapper_UpdateResourceMapping(t *testing.T) {
	mapper := NewCRUDMapper()
	siteContext := &models.SiteContext{
		Host:         "example.com",
		ResourceCRUD: make(map[string]*models.ResourceMapping),
	}

	// Add CRUD operations for users
	mapper.UpdateResourceMapping(siteContext, "GET", "/api/users/123")
	mapper.UpdateResourceMapping(siteContext, "POST", "/api/users")
	mapper.UpdateResourceMapping(siteContext, "PUT", "/api/users/456")
	mapper.UpdateResourceMapping(siteContext, "DELETE", "/api/users/789")

	// Check mapping
	mapping, exists := siteContext.ResourceCRUD["/api/users"]
	assert.True(t, exists)
	assert.Len(t, mapping.Operations, 4)
	assert.Equal(t, "read", mapping.Operations["GET"])
	assert.Equal(t, "create", mapping.Operations["POST"])
	assert.Equal(t, "update", mapping.Operations["PUT"])
	assert.Equal(t, "delete", mapping.Operations["DELETE"])
	assert.Len(t, mapping.RelatedPaths, 4)
	assert.True(t, mapper.HasFullCRUD(mapping))

	// Test with PATCH instead of PUT
	siteContext2 := &models.SiteContext{
		Host:         "example.com",
		ResourceCRUD: make(map[string]*models.ResourceMapping),
	}

	mapper.UpdateResourceMapping(siteContext2, "GET", "/api/posts/1")
	mapper.UpdateResourceMapping(siteContext2, "POST", "/api/posts")
	mapper.UpdateResourceMapping(siteContext2, "PATCH", "/api/posts/2")
	mapper.UpdateResourceMapping(siteContext2, "DELETE", "/api/posts/3")

	mapping2, exists := siteContext2.ResourceCRUD["/api/posts"]
	assert.True(t, exists)
	assert.True(t, mapper.HasFullCRUD(mapping2)) // PATCH should count as PUT
}

func TestCRUDMapper_ExtractResourcePath(t *testing.T) {
	mapper := NewCRUDMapper()

	tests := []struct {
		path string
		want string
	}{
		{"/api/users/123", "/api/users"},
		{"/api/v1/posts/456", "/api/v1/posts"},
		{"/api/products", "/api/products"},
		{"/users/789", "/users"},
		{"/posts", "/posts"},
		{"/static/css/style.css", ""}, // Not a resource
		{"/", ""},                     // Root path
		{"", ""},                      // Empty path
		{"/api/v2/", ""},              // Incomplete path
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, mapper.extractResourcePath(tt.path))
		})
	}
}

func TestCRUDMapper_GetResourceStats(t *testing.T) {
	mapper := NewCRUDMapper()
	siteContext := &models.SiteContext{
		Host:         "example.com",
		ResourceCRUD: make(map[string]*models.ResourceMapping),
	}

	// Add full CRUD resource
	mapper.UpdateResourceMapping(siteContext, "GET", "/api/users/1")
	mapper.UpdateResourceMapping(siteContext, "POST", "/api/users")
	mapper.UpdateResourceMapping(siteContext, "PUT", "/api/users/2")
	mapper.UpdateResourceMapping(siteContext, "DELETE", "/api/users/3")

	// Add partial CRUD resource
	mapper.UpdateResourceMapping(siteContext, "GET", "/api/posts/1")
	mapper.UpdateResourceMapping(siteContext, "POST", "/api/posts")

	stats := mapper.GetResourceStats(siteContext)
	assert.Equal(t, 2, stats["total_resources"])
	assert.Equal(t, 1, stats["full_crud"])
	assert.Equal(t, 1, stats["partial_crud"])
}

func TestCRUDMapper_ConcurrentAccess(t *testing.T) {
	mapper := NewCRUDMapper()
	siteContext := &models.SiteContext{
		Host:         "example.com",
		ResourceCRUD: make(map[string]*models.ResourceMapping),
	}

	var wg sync.WaitGroup

	// Test concurrent mapping updates
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := "/api/items/" + string(rune(id))
			mapper.UpdateResourceMapping(siteContext, "GET", path)
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	stats := mapper.GetResourceStats(siteContext)
	assert.Equal(t, 1, stats["total_resources"])
}
