package utils

import (
	"testing"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestTemporalTracker_TrackRequest(t *testing.T) {
	tracker := NewTemporalTracker()
	siteContext := &models.SiteContext{
		Host:           "example.com",
		RecentRequests: []models.TimedRequest{},
	}

	// Track 3 requests
	for i := 0; i < 3; i++ {
		err := tracker.TrackRequest(siteContext, "GET", "/api/users/test", 200, 50, "")
		assert.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	assert.Len(t, siteContext.RecentRequests, 3)
	assert.Equal(t, int64(3), siteContext.RequestCount)
	assert.Greater(t, siteContext.LastActivity, int64(0))
}

func TestTemporalTracker_MaxRequests(t *testing.T) {
	tracker := NewTemporalTracker()
	siteContext := &models.SiteContext{
		Host:           "example.com",
		RecentRequests: []models.TimedRequest{},
	}

	// Add more requests than the limit
	for i := 0; i < 60; i++ {
		err := tracker.TrackRequest(siteContext, "GET", "/test", 200, 10, "")
		assert.NoError(t, err)
	}

	// Should only keep the most recent MaxRecentRequests (50)
	assert.Len(t, siteContext.RecentRequests, models.MaxRecentRequests)
	assert.Equal(t, int64(60), siteContext.RequestCount)
}
