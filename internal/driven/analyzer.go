package driven

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// GenkitSecurityAnalyzer implements the new detective flow
// Simplified from ~1470 lines to ~300 lines by replacing 5-phase ReAct with 2-phase detective
type GenkitSecurityAnalyzer struct {
	// Single orchestration flow for all AI operations
	detectiveAIFlow *genkitcore.Flow[*llm.DetectiveAIRequest, *llm.DetectiveAIResult, struct{}]

	// Storage (NOT part of Genkit flow)
	graph *models.InMemoryGraph

	// WebSocket
	wsHub *websocket.WebsocketManager
}

// NewGenkitSecurityAnalyzer creates a new analyzer with the detective flow
func NewGenkitSecurityAnalyzer(
	genkitApp *genkit.Genkit,
	modelName string,
	wsHub *websocket.WebsocketManager,
) *GenkitSecurityAnalyzer {
	// Create atomic flows
	unifiedFlow := llm.DefineUnifiedAnalysisFlow(genkitApp, modelName)
	reflectionFlow := llm.DefineReflectionFlow(genkitApp, modelName)
	leadFlow := llm.DefineLeadGenerationFlow(genkitApp, modelName)

	// Create orchestration flow with function wrappers
	detectiveFlow := llm.DefineDetectiveAIFlow(
		genkitApp,
		func(ctx context.Context, req *llm.UnifiedAnalysisRequest) (*llm.UnifiedAnalysisResponse, error) {
			return unifiedFlow.Run(ctx, req)
		},
		func(ctx context.Context, req *llm.ReflectionRequest) (*llm.ReflectionResponse, error) {
			return reflectionFlow.Run(ctx, req)
		},
		func(ctx context.Context, req *llm.LeadGenerationRequest) (*llm.LeadGenerationResponse, error) {
			return leadFlow.Run(ctx, req)
		},
	)

	return &GenkitSecurityAnalyzer{
		detectiveAIFlow: detectiveFlow,
		graph:           models.NewInMemoryGraph(),
		wsHub:           wsHub,
	}
}

// AnalyzeHTTPTraffic analyzes HTTP traffic using the detective flow
// This is the MAIN entry point - simplifies the old 5-phase flow to 2-phase
func (a *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context,
	method, url string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
) error {
	// STEP 1: Request Filter (heuristic, NO LLM)
	// This gives us 60-70% reduction in LLM calls by skipping static assets, health checks, etc.
	// IMPORTANT: Filter BEFORE storage to avoid storing 60-70% of traffic that will be skipped
	skipReason := a.shouldSkipRequest(method, url, statusCode, respHeaders, respBody)
	if skipReason != "" {
		// Store in site map only (not main exchange store)
		a.storeInSiteMap(method, url, reqHeaders, respHeaders, reqBody, respBody, statusCode, skipReason)
		log.Printf("⚪ Skipping %s %s: %s", method, url, skipReason)
		return nil
	}

	// STEP 2: Store exchange (only for requests that pass filter)
	exchange := models.HTTPExchange{
		Request: models.RequestPart{
			Method:  method,
			URL:     url,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: models.ResponsePart{
			StatusCode: statusCode,
			Headers:    respHeaders,
			Body:       respBody,
		},
		Timestamp: time.Now(),
	}
	exchangeID := a.graph.StoreExchange(&exchange)

	log.Printf("🔍 Analyzing %s %s", method, url)
	log.Printf("💾 Stored exchange %s", exchangeID)

	// STEP 2.5: Prepare exchange for LLM (truncate large bodies to save tokens)
	exchangeForLLM := a.prepareExchangeForLLM(exchange)

	// STEP 3: SINGLE AI orchestration flow (unified + lead)
	// This replaces the old 5-phase pipeline
	aiResult, err := a.detectiveAIFlow.Run(ctx, &llm.DetectiveAIRequest{
		Exchange:           exchangeForLLM,
		BigPicture:         a.graph.GetBigPicture(),
		RecentObservations: a.getAllObservations(),
		RecentLeads:        a.graph.GetRecentLeads(20),
	})
	if err != nil {
		return fmt.Errorf("detective AI failed: %w", err)
	}

	// STEP 4: Apply results to storage (OUTSIDE Genkit flow)
	// Storage operations are separate from LLM operations
	a.applyAIResult(exchangeID, exchange, aiResult)

	// STEP 5: SINGLE WebSocket message
	// Replaces multiple broadcasts from old flow
	a.wsHub.Broadcast(websocket.DetectiveDTO{
		ExchangeID:   exchangeID,
		Method:       method,
		URL:          url,
		StatusCode:   statusCode,
		Comment:      aiResult.Comment,
		Observations: aiResult.Observations,
		Connections:  aiResult.Connections,
		BigPicture:   a.graph.GetBigPicture(),
		Leads:        aiResult.Leads,
	})

	log.Printf("✅ Analysis complete for %s %s", method, url)
	return nil
}

// applyAIResult stores AI results (storage operations separate from LLM)
func (a *GenkitSecurityAnalyzer) applyAIResult(
	exchangeID string,
	exchange models.HTTPExchange,
	aiResult *llm.DetectiveAIResult,
) {
	// Store all observations
	for i := range aiResult.Observations {
		aiResult.Observations[i].ExchangeID = exchangeID
		obsID := a.graph.AddObservation(&aiResult.Observations[i])

		log.Printf("💡 Added observation %s", obsID)
		log.Printf("   - What: %s", aiResult.Observations[i].What)
		log.Printf("   - Where: %s", aiResult.Observations[i].Where)
		log.Printf("   - Why: %s", aiResult.Observations[i].Why)
	}

	// Update BigPicture
	if aiResult.BigPictureImpact != nil {
		if err := a.graph.UpdateBigPictureWithImpact(aiResult.BigPictureImpact); err != nil {
			log.Printf("⚠️ Failed to update BigPicture: %v", err)
		} else {
			log.Printf("🖼️ Updated BigPicture: %s = %s", aiResult.BigPictureImpact.Field, aiResult.BigPictureImpact.Value)
		}
	}

	// Store site map entry
	a.storeInSiteMap(
		exchange.Request.Method,
		exchange.Request.URL,
		exchange.Request.Headers,
		exchange.Response.Headers,
		exchange.Request.Body,
		exchange.Response.Body,
		exchange.Response.StatusCode,
		aiResult.SiteMapComment,
	)

	// Store all leads from AI result
	// New architecture: Leads are standalone entities without ObservationID
	// Connections (from AI result) link leads to observations
	// Step 1: Store all leads (without ObservationID)
	for _, leadData := range aiResult.Leads {
		lead := models.Lead{
			Title:          leadData.Title,
			ActionableStep: leadData.ActionableStep,
			PoCs:           leadData.PoCs,
			CreatedAt:      time.Now(),
		}
		leadID := a.graph.AddLead(&lead)
		log.Printf("🎯 Added lead %s: %s", leadID, lead.Title)
	}

	// Step 2: Store all connections (including lead↔obs)
	// Note: AI result now includes connections with actual entity IDs
	for _, conn := range aiResult.Connections {
		a.graph.AddConnection(conn.ID1, conn.ID2, conn.Reason)
		log.Printf("🔗 Connection: %s <-> %s", conn.ID1, conn.ID2)
	}
}

// shouldSkipRequest checks if a request should be skipped using heuristic filtering
// Accepts individual parameters to avoid creating HTTPExchange object for filtered requests
func (a *GenkitSecurityAnalyzer) shouldSkipRequest(method, url string, statusCode int, respHeaders map[string]string, respBody string) string {
	// Skip static assets
	if isStaticAsset(url) {
		return "static asset"
	}

	// Skip health checks
	if isHealthCheck(url) {
		return "health check"
	}

	// Skip based on status code
	if statusCode >= 400 && statusCode < 500 {
		return fmt.Sprintf("client error %d", statusCode)
	}

	// Skip large responses
	if len(respBody) > 1000000 { // 1MB
		return "large response"
	}

	// Skip common non-interesting content types
	contentType := respHeaders["Content-Type"]
	if isSkippableContentType(contentType) {
		return fmt.Sprintf("content-type: %s", contentType)
	}

	return ""
}

// isStaticAsset checks if URL is a static asset
func isStaticAsset(url string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
	}
	for _, ext := range staticExtensions {
		if strings.Contains(strings.ToLower(url), ext) {
			return true
		}
	}
	return false
}

// isHealthCheck checks if URL is a health check endpoint
func isHealthCheck(url string) bool {
	urlLower := strings.ToLower(url)
	healthPatterns := []string{"/health", "/ping", "/status", "/ready", "/live"}
	for _, pattern := range healthPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}
	return false
}

// isSkippableContentType checks if content-type should be skipped
func isSkippableContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	skippable := []string{"image/", "video/", "audio/", "font/", "application/wasm"}
	for _, s := range skippable {
		if strings.Contains(ct, s) {
			return true
		}
	}
	return false
}

// getAllObservations gets recent observations with a configurable limit
// CRITICAL FIX: Limit prevents token explosion after many requests
// Default limit of 100 prevents ~150K token prompts after 1000+ requests
func (a *GenkitSecurityAnalyzer) getAllObservations() []models.Observation {
	const maxObservations = 100 // Configurable limit to prevent token explosion

	// Get recent observations with limit
	obsPointers := a.graph.GetRecentObservations(maxObservations)
	observations := make([]models.Observation, len(obsPointers))
	for i, obs := range obsPointers {
		observations[i] = *obs
	}

	if len(obsPointers) >= maxObservations {
		log.Printf("⚠️ Observation limit reached: using %d most recent observations", maxObservations)
	}

	return observations
}

// storeInSiteMap stores an entry in the site map
func (a *GenkitSecurityAnalyzer) storeInSiteMap(
	method, url string,
	reqHeaders, respHeaders map[string]string,
	reqBody, respBody string,
	statusCode int,
	comment string,
) {
	entry := models.SiteMapEntry{
		ID:      fmt.Sprintf("sitemap-%s:%s", method, url),
		Method:  method,
		URL:     url,
		Comment: comment,
		Request: models.RequestPart{
			Method:  method,
			URL:     url,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: models.ResponsePart{
			StatusCode: statusCode,
			Headers:    respHeaders,
			Body:       respBody,
		},
	}

	a.graph.AddOrUpdateSiteMapEntry(&entry)
}

// Close closes the analyzer and cleans up resources
func (a *GenkitSecurityAnalyzer) Close() error {
	// No async workers to clean up in new flow
	log.Printf("🧹 Analyzer closed")
	return nil
}

// GetGraph returns the in-memory graph (for testing/debugging)
func (a *GenkitSecurityAnalyzer) GetGraph() *models.InMemoryGraph {
	return a.graph
}

// GetWsHub returns the WebSocket manager (for API server)
func (a *GenkitSecurityAnalyzer) GetWsHub() *websocket.WebsocketManager {
	return a.wsHub
}

const (
	maxBodySizeForLLM = 10_000 // 10KB limit for LLM analysis
)

// prepareExchangeForLLM creates a copy of exchange with truncated bodies for LLM analysis
// This prevents sending large binary data (images, videos, etc.) to the LLM
func (a *GenkitSecurityAnalyzer) prepareExchangeForLLM(exchange models.HTTPExchange) models.HTTPExchange {
	result := exchange

	// Truncate request body if needed
	if len(exchange.Request.Body) > maxBodySizeForLLM {
		result.Request.Body = truncateBody(exchange.Request.Body)
		log.Printf("⚠️ Truncated request body for LLM: %d → %d bytes", len(exchange.Request.Body), maxBodySizeForLLM)
	}

	// Truncate response body if needed
	if len(exchange.Response.Body) > maxBodySizeForLLM {
		result.Response.Body = truncateBody(exchange.Response.Body)
		log.Printf("⚠️ Truncated response body for LLM: %d → %d bytes", len(exchange.Response.Body), maxBodySizeForLLM)
	}

	return result
}

// truncateBody truncates body to maxBodySizeForLLM and adds a marker
func truncateBody(body string) string {
	omitted := len(body) - maxBodySizeForLLM
	return body[:maxBodySizeForLLM] + "\n\n... [TRUNCATED: " + strconv.Itoa(omitted) + " bytes omitted]"
}
