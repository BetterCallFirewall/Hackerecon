package driven

import (
	"fmt"
	"testing"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/limits"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSiteContextManager(t *testing.T) {
	manager := NewSiteContextManager()

	require.NotNil(t, manager, "Manager should not be nil")
	assert.NotNil(t, manager.contexts, "Contexts map should be initialized")
	assert.NotNil(t, manager.stopChan, "Stop channel should be initialized")
	assert.NotNil(t, manager.limiter, "Limiter should be initialized")
	assert.Equal(t, 100, manager.maxContexts, "Max contexts should be 100")
	assert.NotNil(t, manager.cleanupTicker, "Cleanup ticker should be initialized")
}

func TestNewSiteContextManagerWithOptions(t *testing.T) {
	customLimits := &limits.ContextLimits{
		MaxRecentRequests: 25,
		MaxForms:          15,
		MaxResources:      20,
		MaxAgeHours:       12 * time.Hour,
		MaxURLPatterns:    80,
		MaxNotesPerURL:    50,
	}

	opts := &SiteContextManagerOptions{
		MaxContexts:     50,
		CleanupInterval: 5 * time.Minute,
		Limits:          limits.NewContextLimiter(customLimits),
	}

	manager := NewSiteContextManagerWithOptions(opts)

	require.NotNil(t, manager)
	assert.Equal(t, 50, manager.maxContexts, "Max contexts should match options")
	assert.NotNil(t, manager.cleanupTicker, "Cleanup ticker should be initialized")

	// Cleanup
	manager.Stop()
}

func TestSiteContextManager_GetOrCreate(t *testing.T) {
	// Create manager with minimal cleanup interval for testing
	opts := &SiteContextManagerOptions{
		MaxContexts:     5,
		CleanupInterval: 0, // Disable auto cleanup for testing
		Limits:          limits.NewContextLimiter(nil),
	}

	manager := NewSiteContextManagerWithOptions(opts)
	defer manager.Stop()

	host1 := "example.com"
	host2 := "test.com"

	// First call should create new context
	context1 := manager.GetOrCreate(host1)
	require.NotNil(t, context1, "First call should create context")
	assert.Equal(t, host1, context1.Host, "Context host should match")

	// Second call should return existing context
	context1Again := manager.GetOrCreate(host1)
	assert.Same(t, context1, context1Again, "Should return same context instance")

	// Different host should create new context
	context2 := manager.GetOrCreate(host2)
	require.NotNil(t, context2, "Should create new context for different host")
	assert.Equal(t, host2, context2.Host, "Context host should match")
	assert.NotSame(t, context1, context2, "Should be different instances")

	// Test context limit enforcement
	for i := 0; i < 10; i++ {
		host := fmt.Sprintf("site%d.com", i)
		manager.GetOrCreate(host)
	}

	// Should not exceed max contexts
	assert.LessOrEqual(t, len(manager.contexts), manager.maxContexts, "Should not exceed max contexts")
}

func TestSiteContextManager_Get(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	host := "example.com"

	// Get non-existent context
	context := manager.Get(host)
	assert.Nil(t, context, "Getting non-existent context should return nil")

	// Create context
	createdContext := manager.GetOrCreate(host)
	require.NotNil(t, createdContext)

	// Get existing context
	retrievedContext := manager.Get(host)
	assert.Same(t, createdContext, retrievedContext, "Should return same context instance")
}

func TestSiteContextManager_UpdateURLPattern(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	host := "example.com"
	context := manager.GetOrCreate(host)

	note := &models.URLNote{
		Content:    "Test endpoint",
		Suspicious: false,
		Confidence: 0.8,
	}

	err := manager.UpdateURLPattern(context, "/api/test", "GET", note)
	assert.NoError(t, err, "Updating URL pattern should not error")

	// Test error cases
	err = manager.UpdateURLPattern(nil, "/api/test", "GET", note)
	assert.Error(t, err, "Should error when context is nil")
	assert.Contains(t, err.Error(), "siteContext cannot be nil")

	err = manager.UpdateURLPattern(context, "/api/test", "GET", nil)
	assert.Error(t, err, "Should error when note is nil")
	assert.Contains(t, err.Error(), "urlNote cannot be nil")
}

func TestSiteContextManager_PerformGlobalCleanup(t *testing.T) {
	// Create manager without auto cleanup
	opts := &SiteContextManagerOptions{
		MaxContexts:     10,
		CleanupInterval: 0, // Disable auto cleanup
		Limits:          limits.NewContextLimiter(nil),
	}

	manager := NewSiteContextManagerWithOptions(opts)
	defer manager.Stop()

	// Add contexts with old data
	oldTimestamp := time.Now().Add(-25 * time.Hour).Unix()

	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("old-site%d.com", i)
		context := manager.GetOrCreate(host)

		// Add old data
		oldRequest := models.TimedRequest{
			ID:         fmt.Sprintf("old-req-%d", i),
			Timestamp:  oldTimestamp,
			Method:     "GET",
			Path:       "/api/old",
			StatusCode: 200,
		}

		context.AddRecentRequest(oldRequest)

		// Set last activity to old time
		context.LastActivity = oldTimestamp
	}

	// Add one active context
	activeHost := "active-site.com"
	activeContext := manager.GetOrCreate(activeHost)
	activeRequest := models.TimedRequest{
		ID:         "active-req",
		Timestamp:  time.Now().Unix(),
		Method:     "GET",
		Path:       "/api/active",
		StatusCode: 200,
	}
	activeContext.AddRecentRequest(activeRequest)

	initialContextCount := len(manager.contexts)
	assert.Equal(t, 6, initialContextCount, "Should have 6 contexts before cleanup")

	// Perform global cleanup
	manager.PerformGlobalCleanup()

	// Old contexts should be evicted
	remainingContexts := len(manager.contexts)
	assert.Less(t, remainingContexts, initialContextCount, "Old contexts should be evicted")

	// Active context should remain
	activeContextAfterCleanup := manager.Get(activeHost)
	assert.NotNil(t, activeContextAfterCleanup, "Active context should remain")
}

func TestSiteContextManager_GetStats(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	// Add some contexts and data
	for i := 0; i < 3; i++ {
		host := fmt.Sprintf("site%d.com", i)
		context := manager.GetOrCreate(host)

		request := models.TimedRequest{
			ID:         fmt.Sprintf("req-%d", i),
			Timestamp:  time.Now().Unix(),
			Method:     "GET",
			Path:       fmt.Sprintf("/api/test%d", i),
			StatusCode: 200,
		}

		context.AddRecentRequest(request)
	}

	stats := manager.GetStats()

	require.NotNil(t, stats, "Stats should not be nil")
	assert.Equal(t, 3, stats["total_contexts"], "Should have 3 total contexts")
	assert.Equal(t, 100, stats["max_contexts"], "Max contexts should be 100")
	assert.Greater(t, stats["total_memory_bytes"], int64(0), "Total memory should be positive")
	assert.Equal(t, int64(3), stats["total_requests"], "Should have 3 total requests")
	assert.Greater(t, stats["last_global_cleanup"], int64(0), "Last cleanup should be set")
}

func TestSiteContextManager_GetAllHosts(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	// Add some contexts
	hosts := []string{"site1.com", "site2.com", "site3.com"}
	for _, host := range hosts {
		manager.GetOrCreate(host)
	}

	allHosts := manager.GetAllHosts()

	require.NotNil(t, allHosts, "Hosts list should not be nil")
	assert.Len(t, allHosts, len(hosts), "Should have correct number of hosts")

	// Check that all hosts are present
	hostSet := make(map[string]bool)
	for _, host := range allHosts {
		hostSet[host] = true
	}

	for _, expectedHost := range hosts {
		assert.True(t, hostSet[expectedHost], "Host %s should be present", expectedHost)
	}
}

func TestSiteContextManager_RemoveContext(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	host := "example.com"
	context := manager.GetOrCreate(host)
	require.NotNil(t, context, "Context should be created")

	// Verify context exists
	retrievedContext := manager.Get(host)
	assert.Same(t, context, retrievedContext, "Context should exist before removal")

	// Remove context
	manager.RemoveContext(host)

	// Verify context is removed
	retrievedContext = manager.Get(host)
	assert.Nil(t, retrievedContext, "Context should be nil after removal")
}

func TestSiteContextManager_UpdateLimits(t *testing.T) {
	manager := NewSiteContextManager()
	defer manager.Stop()

	// Add a context first
	host := "example.com"
	manager.GetOrCreate(host)

	// Update limits
	newLimits := &limits.ContextLimits{
		MaxRecentRequests: 100,
		MaxForms:          50,
		MaxResources:      75,
		MaxAgeHours:       48 * time.Hour,
		MaxURLPatterns:    200,
		MaxNotesPerURL:    150,
	}

	err := manager.UpdateLimits(newLimits)
	assert.NoError(t, err, "Updating valid limits should not error")

	// Test invalid limits
	invalidLimits := &limits.ContextLimits{
		MaxRecentRequests: -1, // Invalid
	}

	err = manager.UpdateLimits(invalidLimits)
	assert.Error(t, err, "Updating invalid limits should error")
	assert.Contains(t, err.Error(), "failed to update limits")
}

func TestSiteContextManager_Stop(t *testing.T) {
	manager := NewSiteContextManager()

	// Add some contexts
	for i := 0; i < 3; i++ {
		host := fmt.Sprintf("site%d.com", i)
		manager.GetOrCreate(host)
	}

	// Stop should not panic and should cleanup
	assert.NotPanics(t, manager.Stop, "Stop should not panic")

	// Verify cleanup ticker is stopped
	assert.Nil(t, manager.cleanupTicker, "Cleanup ticker should be nil after stop")
}

func TestSiteContextManager_ContextEviction(t *testing.T) {
	opts := &SiteContextManagerOptions{
		MaxContexts:     3, // Small limit for testing
		CleanupInterval: 0, // Disable auto cleanup
		Limits:          limits.NewContextLimiter(nil),
	}

	manager := NewSiteContextManagerWithOptions(opts)
	defer manager.Stop()

	// Add contexts up to limit
	for i := 0; i < 3; i++ {
		host := fmt.Sprintf("site%d.com", i)
		context := manager.GetOrCreate(host)

		// Set different last activity times
		context.LastActivity = time.Now().Add(-time.Duration(i) * time.Hour).Unix()
	}

	assert.Equal(t, 3, len(manager.contexts), "Should have 3 contexts")

	// Add one more context - should evict oldest
	newHost := "new-site.com"
	newContext := manager.GetOrCreate(newHost)

	assert.NotNil(t, newContext, "New context should be created")
	assert.Equal(t, 3, len(manager.contexts), "Should still have 3 contexts")

	// Check that the new context exists
	retrievedContext := manager.Get(newHost)
	assert.Same(t, newContext, retrievedContext, "New context should be retrievable")
}
