package llm

import (
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
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

var GetExchangeTool ai.ToolRef

// DefineGetExchangeTool registers the getExchange tool ONCE at initialization
// Must be called before DefineLeadGenerationFlow
func DefineGetExchangeTool(g *genkit.Genkit) {
	GetExchangeTool = genkit.DefineTool(
		g,
		"getExchange",
		"Retrieves full HTTP request/response details for a specific exchange ID. Use this when you need to see exact headers, body, or status codes to generate accurate PoCs.",
		getExchangeToolHandler,
	)
	log.Printf("✅ getExchange tool registered successfully")
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOTE: DefineLeadGenerationFlow and related types removed - replaced by
// new architect flows (strategist, tactician, analyst)
// ═══════════════════════════════════════════════════════════════════════════════
