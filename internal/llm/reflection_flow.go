package llm

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/firebase/genkit/go/ai"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ReflectionRequest represents input for reflection phase
type ReflectionRequest struct {
	Observations    []models.Observation `json:"observations" jsonschema:"description=Observations from unified analysis to reflect on"`
	AllObservations []models.Observation `json:"all_observations" jsonschema:"description=All existing observations for connection finding"`
	BigPicture      *models.BigPicture   `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application,nullable"`
}

// ReflectionResponse represents output from reflection phase
type ReflectionResponse struct {
	Observations []models.Observation `json:"observations" jsonschema:"description=Observations with IsSignificant and Hint populated"`
	Connections  []models.Connection  `json:"connections" jsonschema:"description=Connections created between observations"`
}

// DefineReflectionFlow creates a Genkit flow for reflection phase
func DefineReflectionFlow(
	g *genkit.Genkit,
	modelName string,
) *genkitcore.Flow[*ReflectionRequest, *ReflectionResponse, struct{}] {
	return genkit.DefineFlow(
		g,
		"reflectionFlow",
		func(ctx context.Context, req *ReflectionRequest) (*ReflectionResponse, error) {
			log.Printf("🧠 Starting reflection for %d observations", len(req.Observations))

			// Build prompt
			prompt := BuildReflectionPrompt(req)

			// Execute LLM call
			log.Printf("🤖 Calling LLM for reflection")
			result, _, err := genkit.GenerateData[ReflectionResponse](
				ctx,
				g,
				ai.WithModelName(modelName),
				ai.WithPrompt(prompt),
				ai.WithMiddleware(getMiddlewares()...),
			)
			if err != nil {
				return nil, fmt.Errorf("LLM reflection failed: %w", err)
			}

			// Post-process connections: convert index to ID and set timestamp
			for i := range result.Connections {
				// Convert ID1 from index to actual observation ID
				// LLM returns index (e.g., "0", "1") in ID1 field
				if idx, err := strconv.Atoi(result.Connections[i].ID1); err == nil {
					if idx >= 0 && idx < len(req.Observations) {
						result.Connections[i].ID1 = req.Observations[idx].ID
					}
				}
				// ID2 should already be populated by LLM as existing obs ID

				// Set timestamp if not already set
				if result.Connections[i].CreatedAt.IsZero() {
					result.Connections[i].CreatedAt = time.Now()
				}
			}

			// Log results
			significantCount := 0
			for _, obs := range result.Observations {
				if obs.IsSignificant != nil && *obs.IsSignificant {
					significantCount++
				}
			}

			log.Printf("✅ Reflection complete: significant=%d/%d, connections=%d",
				significantCount, len(result.Observations), len(result.Connections))

			return result, nil
		},
	)
}
