package llm

import (
	"fmt"
)

// BuildTacticianPrompt creates prompt for Tactician agent
func BuildTacticianPrompt(req *TacticianRequest) string {
	return fmt.Sprintf(`You are a Tactician (Pentester). Verify observations and generate leads.

Task: %s

Observations in this task:
%s

Big Picture:
Description: %s

Site Map (%d endpoints):
%s

Available tools:
- getExchange(id): Get full HTTP exchange details

Instructions:
1. Read the Hint in each observation
2. Use getExchange to check actual request data
3. If lead relates to a specific request: generate working curl PoC
4. If lead is general advice (e.g., "check CVE"): no PoC needed

Return JSON:
{
  "leads": [
    {
      "title": "lead title",
      "actionable_step": "what to do",
      "pocs": [
        {
          "description": "PoC description",
          "command": "curl http://..."
        }
      ]
    }
  ]
}`,
		req.Task.Description,
		FormatObservations(req.Task.Observations, true),
		req.BigPicture.Description,
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
	)
}
