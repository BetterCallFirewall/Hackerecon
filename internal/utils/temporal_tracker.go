package utils

import (
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/google/uuid"
)

type TemporalTracker struct {
	mu sync.RWMutex
}

// NewTemporalTracker creates a new temporal tracker
func NewTemporalTracker() *TemporalTracker {
	return &TemporalTracker{}
}

// TrackRequest adds a request to the temporal history for LLM context
func (tt *TemporalTracker) TrackRequest(
	siteContext *models.SiteContext,
	method, path string,
	statusCode int,
	duration int64,
	referer string,
) error {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	// Generate unique request ID
	reqID := uuid.New().String()[:8]

	// Create timed request snapshot
	req := models.TimedRequest{
		ID:         reqID,
		Timestamp:  time.Now().Unix(),
		Method:     method,
		Path:       path,
		StatusCode: statusCode,
		Duration:   duration,
		Referer:    referer,
	}

	// Add to recent requests (FIFO with max limit)
	if len(siteContext.RecentRequests) >= models.MaxRecentRequests {
		// Remove oldest (first element)
		siteContext.RecentRequests = siteContext.RecentRequests[1:]
	}
	siteContext.RecentRequests = append(siteContext.RecentRequests, req)
	siteContext.RequestCount++
	siteContext.LastActivity = time.Now().Unix()

	return nil
}
