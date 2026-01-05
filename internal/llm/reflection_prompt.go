package llm

import (
	"fmt"
)

// BuildReflectionPrompt creates prompt for reflection phase
func BuildReflectionPrompt(req *ReflectionRequest) string {
	prompt := "You are reflecting on security observations to filter significant ones and build connections.\n\n"

	// Input section
	prompt += "## Input\n\n"
	prompt += fmt.Sprintf("**New Observations (%d)**:\n", len(req.Observations))
	for i, obs := range req.Observations {
		prompt += fmt.Sprintf("[%d] What: %s\n", i, obs.What)
		prompt += fmt.Sprintf("    Where: %s\n", obs.Where)
		prompt += fmt.Sprintf("    Why: %s\n", obs.Why)
		prompt += "\n"
	}

	if len(req.AllObservations) > 0 {
		prompt += fmt.Sprintf("\n**Existing Observations (%d)** - check for duplicates/connections:\n", len(req.AllObservations))
		for _, obs := range req.AllObservations {
			prompt += fmt.Sprintf("- [%s] What: %s\n", obs.ID, obs.What)
			prompt += fmt.Sprintf("        Where: %s\n", TruncateString(obs.Where, 150))
		}
	}

	// BigPicture context
	if req.BigPicture != nil {
		prompt += "\n**Site Context**:\n"
		prompt += fmt.Sprintf("- Technologies: %s\n", req.BigPicture.Technologies)
		prompt += fmt.Sprintf("- Functionalities: %s\n", req.BigPicture.Functionalities)
	}

	// Task description
	prompt += "\n## Task\n\n"
	prompt += "Reflect on each observation and:\n"
	prompt += "1. Mark IsSignificant = true if it reveals server architecture OR creates attack opportunity\n"
	prompt += "2. Mark IsSignificant = false if it's frontend/duplicate/insignificant\n"
	prompt += "3. Add Hint for significant observations (actionable guidance, not generic advice)\n"
	prompt += "4. Create Connections to related existing observations\n\n"

	// Output format
	prompt += "## Output Format (JSON):\n\n"
	prompt += `{
  "observations": [
    {
      "what": "MongoDB ObjectId in response._id",
      "where": "Response body: _id: 'eab3d383...'",
      "why": "Reveals MongoDB backend",

      "is_significant": true,
      "hint": "URL parameter /api/shop/{id} is used directly as DB identifier. Try NoSQL operators in URL path: /api/shop/{\"$ne\":null}"
    },
    {
      "what": "Orbitron font in CSS body rule",
      "where": "CSS: body { font-family: 'Orbitron' }",
      "why": "Futuristic cyberpunk styling",

      "is_significant": false
    }
  ],

  "connections": [
    {
      "id1": "<current_obs_index>",
      "id2": "<existing_obs_id>",
      "reason": "Both relate to MongoDB injection vectors"
    }
  ]
}

IMPORTANT:
- id1 in connections is the INDEX (0, 1, 2...) from input observations
- id2 in connections is the ID (obs-1, obs-2...) from existing observations
- Return ALL observations with is_significant populated
- Only create connections to EXISTING observations, not between new ones
`

	return prompt
}
