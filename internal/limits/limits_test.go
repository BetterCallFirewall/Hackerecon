package limits

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultContextLimits(t *testing.T) {
	limits := DefaultContextLimits()

	assert.Equal(t, 50, limits.MaxRecentRequests, "Default MaxRecentRequests should be 50")
	assert.Equal(t, 20, limits.MaxForms, "Default MaxForms should be 20")
	assert.Equal(t, 30, limits.MaxResources, "Default MaxResources should be 30")
	assert.Equal(t, 24*time.Hour, limits.MaxAgeHours, "Default MaxAgeHours should be 24 hours")
	assert.Equal(t, 100, limits.MaxURLPatterns, "Default MaxURLPatterns should be 100")
	assert.Equal(t, 100, limits.MaxNotesPerURL, "Default MaxNotesPerURL should be 100")
}

func TestNewContextLimiter(t *testing.T) {
	limiter := NewContextLimiter(nil)
	require.NotNil(t, limiter, "Limiter should not be nil")
	require.NotNil(t, limiter.limits, "Limits should not be nil")

	customLimits := &ContextLimits{
		MaxRecentRequests: 100,
		MaxForms:          50,
		MaxResources:      75,
		MaxAgeHours:       12 * time.Hour,
		MaxURLPatterns:    200,
		MaxNotesPerURL:    150,
	}

	limiter = NewContextLimiter(customLimits)
	require.NotNil(t, limiter)
	assert.Equal(t, customLimits.MaxRecentRequests, limiter.GetLimits().MaxRecentRequests)
}

func TestContextLimiter_UpdateLimits(t *testing.T) {
	limiter := NewContextLimiter(nil)

	validLimits := &ContextLimits{
		MaxRecentRequests: 25,
		MaxForms:          15,
		MaxResources:      20,
		MaxAgeHours:       48 * time.Hour,
		MaxURLPatterns:    80,
		MaxNotesPerURL:    50,
	}

	err := limiter.UpdateLimits(validLimits)
	assert.NoError(t, err, "Valid limits should be updated without error")
	assert.Equal(t, validLimits.MaxRecentRequests, limiter.GetLimits().MaxRecentRequests)

	// Test invalid limits
	invalidLimits := &ContextLimits{
		MaxRecentRequests: -1, // Invalid
	}

	err = limiter.UpdateLimits(invalidLimits)
	assert.Error(t, err, "Invalid limits should return error")
	assert.Contains(t, err.Error(), "MaxRecentRequests must be positive")
}

func TestContextLimiter_ShouldCleanup(t *testing.T) {
	limiter := NewContextLimiter(nil)

	now := time.Now().Unix()
	oldTimestamp := now - int64(25*time.Hour/time.Second) // 25 часов назад

	assert.False(t, limiter.ShouldCleanup(now), "Recent timestamp should not be cleaned up")
	assert.True(t, limiter.ShouldCleanup(oldTimestamp), "Old timestamp should be cleaned up")
}

func TestContextLimiter_ValidateLimits(t *testing.T) {
	limiter := NewContextLimiter(nil)

	// Valid limits
	err := limiter.ValidateLimits()
	assert.NoError(t, err, "Default limits should be valid")

	// Test limits that are too large
	invalidLimits := &ContextLimits{
		MaxRecentRequests: 2000, // Too large
		MaxForms:          20,
		MaxResources:      30,
		MaxAgeHours:       24 * time.Hour,
		MaxURLPatterns:    100,
		MaxNotesPerURL:    100,
	}

	limiter.limits = invalidLimits
	err = limiter.ValidateLimits()
	assert.Error(t, err, "Too large limits should return error")
	assert.Contains(t, err.Error(), "MaxRecentRequests too large")
}

func TestContextLimiter_GetMemoryUsage(t *testing.T) {
	limiter := NewContextLimiter(nil)
	memoryUsage := limiter.GetMemoryUsage()

	assert.Greater(t, memoryUsage, int64(0), "Memory usage should be positive")
	assert.Greater(t, memoryUsage, int64(1000), "Memory usage should be at least 1KB")
}

func TestContextLimiter_CleanupRequests(t *testing.T) {
	limiter := NewContextLimiter(nil)

	// Create mock requests
	requests := make([]interface{}, 100)
	for i := 0; i < 100; i++ {
		requests[i] = i
	}

	cleaned := limiter.CleanupRequests(requests)
	assert.Equal(t, limiter.limits.MaxRecentRequests, len(cleaned), "Should limit requests to max limit")
}

func TestContextLimiter_CleanupMap(t *testing.T) {
	limiter := NewContextLimiter(nil)

	// Create mock map
	m := make(map[string]interface{})
	for i := 0; i < 50; i++ {
		m[fmt.Sprintf("key%d", i)] = i
	}

	cleaned := limiter.CleanupMap(m)
	expectedMaxSize := limiter.limits.MaxForms
	if limiter.limits.MaxResources < expectedMaxSize {
		expectedMaxSize = limiter.limits.MaxResources
	}
	assert.LessOrEqual(t, len(cleaned), expectedMaxSize, "Should limit map size to max limit")
}
