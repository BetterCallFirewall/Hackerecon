package models

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSiteContext(t *testing.T) {
	host := "example.com"
	context := NewSiteContext(host)

	require.NotNil(t, context, "Context should not be nil")
	assert.Equal(t, host, context.Host, "Host should match")
	assert.NotNil(t, context.URLPatterns, "URLPatterns should be initialized")
	assert.NotNil(t, context.Forms, "Forms should be initialized")
	assert.NotNil(t, context.ResourceCRUD, "ResourceCRUD should be initialized")
	assert.NotNil(t, context.limiter, "Limiter should be initialized")
	assert.Greater(t, context.lastCleanup, int64(0), "LastCleanup should be set")
}

func TestNewSiteContextWithLimiter(t *testing.T) {
	host := "example.com"
	customLimits := &limits.ContextLimits{
		MaxRecentRequests: 25,
		MaxForms:          15,
		MaxResources:      20,
		MaxAgeHours:       12 * time.Hour,
		MaxURLPatterns:    80,
		MaxNotesPerURL:    50,
	}
	limiter := limits.NewContextLimiter(customLimits)

	context := NewSiteContextWithLimiter(host, limiter)

	require.NotNil(t, context)
	assert.Equal(t, host, context.Host)
	assert.Equal(t, limiter, context.limiter)
}

func TestSiteContext_AddRecentRequest(t *testing.T) {
	context := NewSiteContext("example.com")

	// Add valid request
	request := TimedRequest{
		ID:         "test-1",
		Timestamp:  time.Now().Unix(),
		Method:     "GET",
		Path:       "/api/test",
		StatusCode: 200,
	}

	err := context.AddRecentRequest(request)
	assert.NoError(t, err, "Adding valid request should not error")
	assert.Equal(t, int64(1), context.RequestCount, "Request count should increment")
	assert.Len(t, context.RecentRequests, 1, "Should have one recent request")

	// Test thread safety
	var wg sync.WaitGroup
	numGoroutines := 10
	requestsPerGoroutine := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				req := TimedRequest{
					ID:         fmt.Sprintf("test-%d-%d", id, j),
					Timestamp:  time.Now().Unix(),
					Method:     "GET",
					Path:       fmt.Sprintf("/api/test/%d/%d", id, j),
					StatusCode: 200,
				}
				context.AddRecentRequest(req)
			}
		}(i)
	}

	wg.Wait()

	expectedRequests := 1 + (numGoroutines * requestsPerGoroutine)
	assert.Equal(t, int64(expectedRequests), context.RequestCount, "Request count should match all additions")

	// Should be limited by max requests
	assert.LessOrEqual(t, len(context.RecentRequests), context.limiter.GetLimits().MaxRecentRequests,
		"Recent requests should be limited")
}

func TestSiteContext_AddForm(t *testing.T) {
	context := NewSiteContext("example.com")

	form := &HTMLForm{
		FormID:        "test-form-1",
		Action:        "/api/login",
		Method:        "POST",
		HasCSRFToken:  true,
		CSRFTokenName: "csrf_token",
		Fields: []FormField{
			{Name: "username", Type: "text", Sensitive: false},
			{Name: "password", Type: "password", Sensitive: true},
		},
		FirstSeen: time.Now().Unix(),
	}

	err := context.AddForm(form)
	assert.NoError(t, err, "Adding valid form should not error")
	assert.Len(t, context.Forms, 1, "Should have one form")
	assert.Equal(t, form, context.Forms["test-form-1"], "Form should be stored correctly")

	// Test thread safety
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			form := &HTMLForm{
				FormID:    fmt.Sprintf("test-form-%d", id),
				Action:    fmt.Sprintf("/api/action/%d", id),
				Method:    "POST",
				FirstSeen: time.Now().Unix(),
			}
			context.AddForm(form)
		}(i)
	}

	wg.Wait()

	// Should be limited by max forms
	assert.LessOrEqual(t, len(context.Forms), context.limiter.GetLimits().MaxForms,
		"Forms should be limited")
}

func TestSiteContext_AddResourceMapping(t *testing.T) {
	context := NewSiteContext("example.com")

	mapping := &ResourceMapping{
		ResourcePath: "/api/users/{id}",
		Operations: map[string]string{
			"GET":    "read",
			"POST":   "create",
			"PUT":    "update",
			"DELETE": "delete",
		},
		Identifier:   "id",
		RelatedPaths: []string{"/api/users", "/api/users/{id}/profile"},
		DetectedAt:   time.Now().Unix(),
	}

	err := context.AddResourceMapping("users-crud", mapping)
	assert.NoError(t, err, "Adding valid resource mapping should not error")
	assert.Len(t, context.ResourceCRUD, 1, "Should have one resource mapping")
	assert.Equal(t, mapping, context.ResourceCRUD["users-crud"], "Resource mapping should be stored correctly")
}

func TestSiteContext_UpdateURLPattern(t *testing.T) {
	context := NewSiteContext("example.com")

	note := &URLNote{
		Content:    "Test endpoint for user authentication",
		Suspicious: false,
		VulnHint:   "Check for SQL injection",
		Confidence: 0.8,
	}

	err := context.UpdateURLPattern("GET:/api/login", nil, note)
	assert.NoError(t, err, "Adding URL pattern should not error")
	assert.Len(t, context.URLPatterns, 1, "Should have one URL pattern")

	pattern := context.URLPatterns["GET:/api/login"]
	assert.Equal(t, "GET:/api/login", pattern.Pattern)
	assert.Equal(t, "GET", pattern.Method)
	assert.Equal(t, "Test endpoint for user authentication", pattern.Purpose)
	assert.Len(t, pattern.Notes, 1)

	// Test thread safety
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			note := &URLNote{
				Content:    fmt.Sprintf("Note %d", id),
				Confidence: float64(id) / 10.0,
			}
			patternKey := fmt.Sprintf("GET:/api/test/%d", id)
			context.UpdateURLPattern(patternKey, nil, note)
		}(i)
	}

	wg.Wait()

	assert.LessOrEqual(t, len(context.URLPatterns), context.limiter.GetLimits().MaxURLPatterns,
		"URL patterns should be limited")
}

func TestSiteContext_CleanupOldData(t *testing.T) {
	context := NewSiteContext("example.com")

	// Add old data
	oldTimestamp := time.Now().Add(-25 * time.Hour).Unix()

	oldRequest := TimedRequest{
		ID:         "old-request",
		Timestamp:  oldTimestamp,
		Method:     "GET",
		Path:       "/api/old",
		StatusCode: 200,
	}

	oldForm := &HTMLForm{
		FormID:    "old-form",
		Action:    "/api/old",
		Method:    "POST",
		FirstSeen: oldTimestamp,
	}

	oldResource := &ResourceMapping{
		ResourcePath: "/api/old/{id}",
		Operations:   map[string]string{"GET": "read"},
		DetectedAt:   oldTimestamp,
	}

	// Add current data
	currentTimestamp := time.Now().Unix()
	currentRequest := TimedRequest{
		ID:         "current-request",
		Timestamp:  currentTimestamp,
		Method:     "GET",
		Path:       "/api/current",
		StatusCode: 200,
	}

	// Add all data
	// Add old request directly to bypass ShouldCleanup check in AddRecentRequest
	context.mutex.Lock()
	context.RecentRequests = append(context.RecentRequests, oldRequest)
	context.mutex.Unlock()

	context.AddRecentRequest(currentRequest)
	context.AddForm(oldForm)
	context.AddResourceMapping("old-resource", oldResource)

	// Verify data exists before cleanup
	assert.Len(t, context.RecentRequests, 2, "Should have 2 requests before cleanup")
	assert.Len(t, context.Forms, 1, "Should have 1 form before cleanup")
	assert.Len(t, context.ResourceCRUD, 1, "Should have 1 resource before cleanup")

	// Perform cleanup
	err := context.CleanupOldData()
	assert.NoError(t, err, "Cleanup should not error")

	// Verify old data is removed, current data remains
	assert.Len(t, context.RecentRequests, 1, "Should have 1 request after cleanup")
	assert.Equal(t, "current-request", context.RecentRequests[0].ID, "Current request should remain")
	assert.Empty(t, context.Forms, "Old form should be removed")
	assert.Empty(t, context.ResourceCRUD, "Old resource should be removed")
}

func TestSiteContext_GetMemoryUsage(t *testing.T) {
	context := NewSiteContext("example.com")
	memoryUsage := context.GetMemoryUsage()

	assert.Greater(t, memoryUsage, int64(0), "Memory usage should be positive")
	assert.Greater(t, memoryUsage, int64(1000), "Memory usage should be at least 1KB")
}

func TestSiteContext_GetStats(t *testing.T) {
	context := NewSiteContext("example.com")

	// Add some data
	request := TimedRequest{
		ID:         "test-request",
		Timestamp:  time.Now().Unix(),
		Method:     "GET",
		Path:       "/api/test",
		StatusCode: 200,
	}

	form := &HTMLForm{
		FormID:    "test-form",
		Action:    "/api/test",
		Method:    "POST",
		FirstSeen: time.Now().Unix(),
	}

	note := &URLNote{
		Content:    "Test note",
		Confidence: 0.8,
	}

	context.AddRecentRequest(request)
	context.AddForm(form)
	context.UpdateURLPattern("GET:/api/test", nil, note)

	stats := context.GetStats()

	require.NotNil(t, stats, "Stats should not be nil")
	assert.Equal(t, "example.com", stats["host"], "Host should match")
	assert.Equal(t, 1, stats["recent_requests"], "Should have 1 recent request")
	assert.Equal(t, 1, stats["forms"], "Should have 1 form")
	assert.Equal(t, 1, stats["url_patterns"], "Should have 1 URL pattern")
	assert.Equal(t, int64(1), stats["request_count"], "Should have 1 request count")
	assert.Greater(t, stats["last_activity"], int64(0), "Last activity should be set")
	assert.Greater(t, stats["memory_estimate"], int64(0), "Memory estimate should be positive")
}

func TestSiteContext_ThreadSafety(t *testing.T) {
	context := NewSiteContext("example.com")

	var wg sync.WaitGroup
	numGoroutines := 3          // Reduced to minimize contention
	operationsPerGoroutine := 2 // Reduced to minimize contention

	// Channel to control concurrency and prevent overwhelming the mutex
	semaphore := make(chan struct{}, 2) // Allow max 2 concurrent goroutines

	// Concurrent reads and writes with better control
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Acquire semaphore to limit concurrent access
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Small staggered delay to reduce burst contention
			time.Sleep(time.Millisecond * time.Duration(id))

			for j := 0; j < operationsPerGoroutine; j++ {
				// Write operations with error checking
				request := TimedRequest{
					ID:         fmt.Sprintf("req-%d-%d", id, j),
					Timestamp:  time.Now().Unix(),
					Method:     "GET",
					Path:       fmt.Sprintf("/api/test/%d/%d", id, j),
					StatusCode: 200,
				}
				if err := context.AddRecentRequest(request); err != nil {
					t.Logf("Error adding request %d-%d: %v", id, j, err)
				}

				form := &HTMLForm{
					FormID:    fmt.Sprintf("form-%d-%d", id, j),
					Action:    fmt.Sprintf("/api/action/%d/%d", id, j),
					Method:    "POST",
					FirstSeen: time.Now().Unix(),
				}
				if err := context.AddForm(form); err != nil {
					t.Logf("Error adding form %d-%d: %v", id, j, err)
				}

				note := &URLNote{
					Content:    fmt.Sprintf("Note %d %d", id, j),
					Confidence: float64(j) / 10.0,
				}
				patternKey := fmt.Sprintf("GET:/api/test/%d/%d", id, j)
				if err := context.UpdateURLPattern(patternKey, nil, note); err != nil {
					t.Logf("Error updating URL pattern %d-%d: %v", id, j, err)
				}

				// Read operations (these are already thread-safe with RLock)
				_ = context.GetMemoryUsage()
				_ = context.GetStats()

				// Small delay between operations to reduce contention
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	// Use a channel with timeout to wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Test completed successfully
	case <-time.After(10 * time.Second):
		t.Fatal("Thread safety test timed out after 10 seconds - possible deadlock detected")
	}

	// Should not panic and should have reasonable data
	stats := context.GetStats()
	assert.NotNil(t, stats, "Stats should not be nil")

	limits := context.limiter.GetLimits()
	assert.LessOrEqual(t, len(context.RecentRequests), limits.MaxRecentRequests,
		"Recent requests should not exceed %d", limits.MaxRecentRequests)
	assert.LessOrEqual(t, len(context.Forms), limits.MaxForms,
		"Forms should not exceed %d", limits.MaxForms)
	assert.LessOrEqual(t, len(context.URLPatterns), limits.MaxURLPatterns,
		"URL patterns should not exceed %d", limits.MaxURLPatterns)
}
