package llm

import (
	"context"
	"fmt"
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Detective AI Flow - Orchestrates Unified Analysis + Lead Generation
// ═══════════════════════════════════════════════════════════════════════════════

// DetectiveAIRequest represents input for the detective AI orchestration flow
type DetectiveAIRequest struct {
	Exchange           models.HTTPExchange   `json:"exchange"`
	BigPicture         *models.BigPicture    `json:"big_picture,omitempty"`
	RecentObservations []models.Observation  `json:"recent_observations,omitempty"`
	RecentLeads        []models.Lead         `json:"recent_leads,omitempty"`     // for deduplication
	SiteMapEntries     []models.SiteMapEntry `json:"site_map_entries,omitempty"` // all available endpoints with exchange_id
	Graph              *models.InMemoryGraph `json:"-"`                          // InMemoryGraph for getExchange tool (not serialized)
}

// DetectiveAIResult represents the complete output from detective AI analysis
type DetectiveAIResult struct {
	// Unified analysis results
	Comment          string                   `json:"comment"`
	Observations     []models.Observation     `json:"observations,omitempty"`
	Connections      []models.Connection      `json:"connections,omitempty"`
	BigPictureImpact *models.BigPictureImpact `json:"big_picture_impact,omitempty"`
	SiteMapComment   string                   `json:"site_map_comment,omitempty"`

	// Lead generation results (optional, direct leads)
	Leads []models.Lead `json:"leads,omitempty"` // Changed from []*LeadGenerationResponse
}

// DefineDetectiveAIFlow creates the orchestration flow that coordinates:
// 1. Unified Analysis (atomic flow)
// 2. Reflection (filters observations, finds connections)
// 3. Lead Generation (optional, conditional on observation)
func DefineDetectiveAIFlow(
	g *genkit.Genkit,
	unifiedFlow func(context.Context, *UnifiedAnalysisRequest) (*UnifiedAnalysisResponse, error),
	reflectionFlow func(context.Context, *ReflectionRequest) (*ReflectionResponse, error),
	leadFlow func(context.Context, *LeadGenerationRequest) (*LeadGenerationResponse, error),
) *genkitcore.Flow[*DetectiveAIRequest, *DetectiveAIResult, struct{}] {
	return genkit.DefineFlow(
		g,
		"detectiveAIFlow",
		func(ctx context.Context, req *DetectiveAIRequest) (*DetectiveAIResult, error) {
			log.Printf("🕵️ Starting Detective AI flow for %s %s", req.Exchange.Request.Method, req.Exchange.Request.URL)

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 1: Unified Analysis (atomic flow)
			// ═══════════════════════════════════════════════════════════════════════════════

			unifiedReq := &UnifiedAnalysisRequest{
				Exchange:           req.Exchange,
				BigPicture:         req.BigPicture,
				RecentObservations: req.RecentObservations,
			}

			unifiedResp, err := genkit.Run(
				ctx, "unifiedAnalysis",
				func() (*UnifiedAnalysisResponse, error) {
					return unifiedFlow(ctx, unifiedReq)
				},
			)
			if err != nil {
				return nil, fmt.Errorf("unified analysis failed: %w", err)
			}

			log.Printf(
				"✅ Unified analysis complete: comment=%s, observations_count=%d",
				unifiedResp.Comment, len(unifiedResp.Observations),
			)

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 2: Reflection (filters observations, finds connections)
			// ═══════════════════════════════════════════════════════════════════════════════

			var finalObservations []models.Observation
			var allConnections []models.Connection

			if len(unifiedResp.Observations) > 0 {
				reflectionReq := &ReflectionRequest{
					Observations:    unifiedResp.Observations,
					AllObservations: req.RecentObservations,
					BigPicture:      req.BigPicture,
				}

				reflectionResp, err := genkit.Run(
					ctx, "reflection",
					func() (*ReflectionResponse, error) {
						return reflectionFlow(ctx, reflectionReq)
					},
				)
				if err != nil {
					// Reflection is non-critical, fall back to original observations
					log.Printf("⚠️ Reflection failed (non-critical): %v", err)
					finalObservations = unifiedResp.Observations
					allConnections = unifiedResp.Connections
				} else {
					// Use reflected observations with IsSignificant and Hint populated
					finalObservations = reflectionResp.Observations
					// Merge connections from both phases
					allConnections = append(unifiedResp.Connections, reflectionResp.Connections...)
					log.Printf(
						"✅ Reflection complete: observations_count=%d, connections_count=%d",
						len(finalObservations), len(reflectionResp.Connections),
					)
				}
			} else {
				finalObservations = unifiedResp.Observations
				allConnections = unifiedResp.Connections
			}

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 3: Lead Generation (optional, conditional - batch mode)
			// NOTE: Processes all significant observations in a single batch call
			// to enable cross-observation lead generation and reduce LLM calls
			// ═══════════════════════════════════════════════════════════════════════════════

			var allLeads []models.Lead

			if len(finalObservations) > 0 {
				// Filter significant observations first
				var significantObs []models.Observation
				for _, obs := range finalObservations {
					if obs.IsSignificant != nil && *obs.IsSignificant {
						significantObs = append(significantObs, obs)
					}
				}

				if len(significantObs) > 0 {
					log.Printf(
						"💡 Found %d significant observation(s) out of %d total, generating batch leads...",
						len(significantObs), len(finalObservations),
					)

					leadReq := &LeadGenerationRequest{
						Observations:   significantObs, // Batch mode: all significant observations
						ExistingLeads:  req.RecentLeads,
						SiteMapEntries: req.SiteMapEntries, // All available endpoints with exchange_id
						BigPicture:     req.BigPicture,
						Graph:          req.Graph, // InMemoryGraph for getExchange tool
					}

					leadResult, err := genkit.Run(
						ctx, "leadGeneration_batch", // Single batch call
						func() (*LeadGenerationResponse, error) {
							return leadFlow(ctx, leadReq)
						},
					)
					if err != nil {
						// Lead generation is optional, don't fail entire flow
						log.Printf("⚠️ Batch lead generation failed (non-critical): %v", err)
					} else {
						// Convert LeadData to models.Lead
						for _, leadData := range leadResult.Leads {
							lead := models.Lead{
								Title:          leadData.Title,
								ActionableStep: leadData.ActionableStep,
								PoCs:           leadData.PoCs,
							}
							allLeads = append(allLeads, lead)
						}
						log.Printf("✅ Batch lead generation complete: leads_count=%d", len(leadResult.Leads))
					}
				} else {
					log.Printf("ℹ️ No significant observations found, skipping lead generation")
				}
			} else {
				log.Printf("ℹ️ No observations found, skipping lead generation")
			}

			// ═══════════════════════════════════════════════════════════════════════════════
			// Step 3: Combine results
			// ═══════════════════════════════════════════════════════════════════════════════

			result := &DetectiveAIResult{
				Comment:          unifiedResp.Comment,
				Observations:     finalObservations,
				Connections:      allConnections,
				BigPictureImpact: unifiedResp.BigPictureImpact,
				SiteMapComment:   unifiedResp.SiteMapComment,
				Leads:            allLeads,
			}

			log.Printf(
				"🎯 Detective AI flow complete: observations_count=%d, leads_count=%d",
				len(result.Observations), len(result.Leads),
			)

			return result, nil
		},
	)
}
