package llm

import (
	"context"
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Global Tool Definition (registered once)
// ═══════════════════════════════════════════════════════════════════════════════

// GetExchangeInput defines tool input schema
type GetExchangeInput struct {
	ExchangeID string `json:"exchangeID"`
}

// GetExchangeOutput defines tool output schema
type GetExchangeOutput struct {
	Exchange models.HTTPExchange `json:"exchange"`
}

// getExchangeToolHandler retrieves exchanges from global InMemoryGraph
// Uses global graph reference because Genkit ToolContext doesn't inherit parent context values
func getExchangeToolHandler(toolCtx *ai.ToolContext, input GetExchangeInput) (GetExchangeOutput, error) {
	// Get InMemoryGraph from global reference (set during analyzer initialization)
	graph := models.GetGlobalInMemoryGraph()
	if graph == nil {
		log.Printf("❌ Tool getExchange failed: global InMemoryGraph not initialized")
		return GetExchangeOutput{}, fmt.Errorf("global InMemoryGraph not initialized")
	}

	exchange, err := graph.GetExchange(input.ExchangeID)
	if err != nil {
		log.Printf("❌ Tool getExchange failed: %v", err)
		return GetExchangeOutput{}, fmt.Errorf("get exchange failed: %w", err)
	}

	log.Printf("🔍 Tool getExchange success: exchangeID=%s, url=%s", input.ExchangeID, exchange.Request.URL)
	return GetExchangeOutput{Exchange: *exchange}, nil
}

var getExchangeTool ai.ToolRef

// DefineGetExchangeTool registers the getExchange tool ONCE at initialization
// Must be called before DefineLeadGenerationFlow
func DefineGetExchangeTool(g *genkit.Genkit) {
	getExchangeTool = genkit.DefineTool(
		g,
		"getExchange",
		"Retrieves full HTTP request/response details for a specific exchange ID. Use this when you need to see exact headers, body, or status codes to generate accurate PoCs.",
		getExchangeToolHandler,
	)
	log.Printf("✅ getExchange tool registered successfully")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Lead Generation Flow - Atomic Genkit Flow
// ═══════════════════════════════════════════════════════════════════════════════

// DefineLeadGenerationFlow creates an atomic Genkit flow for lead generation
// This flow is called separately after unified analysis completes
func DefineLeadGenerationFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*LeadGenerationRequest, *LeadGenerationResponse, struct{}] {
	return genkit.DefineFlow(
		g,
		"leadGenerationFlow",
		func(ctx context.Context, req *LeadGenerationRequest) (*LeadGenerationResponse, error) {
			log.Printf("💡 Starting lead generation for %d observation(s)", len(req.Observations))

			// Build prompt
			prompt := BuildLeadGenerationPrompt(req)

			// Execute LLM call using genkit.GenerateData with tool support
			log.Printf("🤖 Calling LLM for lead generation with getExchange tool")
			result, _, err := genkit.GenerateData[LeadGenerationResponse](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithTools(getExchangeTool),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("LLM generation failed: %w", err)
			}

			log.Printf("✅ Lead generation complete: leads_count=%d", len(result.Leads))
			for i, lead := range result.Leads {
				log.Printf(
					"   Lead %d: is_actionable=%v, title=%s, pocs_count=%d",
					i, lead.IsActionable, lead.Title, len(lead.PoCs),
				)
			}

			return result, nil
		},
	)
}
