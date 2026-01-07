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

// AnalystRequest - input for Analyst flow
type AnalystRequest struct {
	Exchange models.HTTPExchange `json:"exchange"`
}

// AnalystResponse - output from Analyst flow
type AnalystResponse struct {
	Observations []models.Observation `json:"observations"`
}

// DefineAnalystFlow creates the Analyst Genkit flow
func DefineAnalystFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*AnalystRequest, *AnalystResponse, struct{}] {
	return genkit.DefineFlow(
		g,
		"analystFlow",
		func(ctx context.Context, req *AnalystRequest) (*AnalystResponse, error) {
			// Check context early
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled before analyst analysis: %w", err)
			}

			log.Printf("🔵 Analyst analyzing %s %s", req.Exchange.Request.Method, req.Exchange.Request.URL)

			prompt := BuildAnalystPrompt(req)

			// Check again after prompt building
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("context cancelled during analyst prompt building: %w", err)
			}

			result, _, err := genkit.GenerateData[AnalystResponse](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("analyst LLM failed: %w", err)
			}

			log.Printf("✅ Analyst complete: %d raw observations", len(result.Observations))
			return result, nil
		},
	)
}
