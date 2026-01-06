package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Lead Generation Prompt - Async, separate call with human-readable PoCs
// ═══════════════════════════════════════════════════════════════════════════════

// LeadGenerationRequest represents input for lead generation
// Supports both single observation (backward compatibility) and batch mode
// Now includes existing leads for deduplication (many-to-many relationship)
// Now includes site_map entries for context (all available endpoints with exchange_id)
type LeadGenerationRequest struct {
	Observation    models.Observation    `json:"observation,omitempty" jsonschema:"description=Single observation (deprecated, use observations)"`
	Observations   []models.Observation  `json:"observations" jsonschema:"description=Observations to generate leads from (batch mode)"`
	ExistingLeads  []models.Lead         `json:"existing_leads,omitempty" jsonschema:"description=Existing leads for deduplication (LLM should reuse these instead of creating duplicates)"`
	SiteMapEntries []models.SiteMapEntry `json:"site_map_entries,omitempty" jsonschema:"description=All site map entries with exchange_id for context (helps generate accurate PoCs by knowing available endpoints)"`
	BigPicture     *models.BigPicture    `json:"big_picture,omitempty" jsonschema:"description=Current understanding of target application,nullable"`
	Graph          *models.InMemoryGraph `json:"-"` // InMemoryGraph for getExchange tool (not serialized)
}

// LeadData represents a single lead with all its details
// NOTE: No observation_index - leads are standalone entities, linked via Connection
type LeadData struct {
	IsActionable   bool              `json:"is_actionable" jsonschema:"description=Whether this lead is actionable"`
	Title          string            `json:"title" jsonschema:"description=Short title (max 10 words),required"`
	ActionableStep string            `json:"actionable_step" jsonschema:"description=Concrete testing step,required"`
	PoCs           []models.PoCEntry `json:"pocs" jsonschema:"description=Human-readable PoC instructions,required"`
}

// LeadGenerationResponse represents output from lead generation
// Returns leads and their connections to observations
// NOTE: Does NOT include CanAutoVerify field (per user requirements)
type LeadGenerationResponse struct {
	Leads       []LeadData          `json:"leads" jsonschema:"description=Array of leads (0, 1, or many)"`
	Connections []models.Connection `json:"connections" jsonschema:"description=Connections between leads and observations (id1=obs-*, id2=lead-*)"`
}

// BuildLeadGenerationPrompt creates prompt for generating leads from observations
// Uses simple string concatenation (not strings.Builder)
// Emphasis on human-readable PoC instructions
// NEW: Includes existing leads for deduplication, uses connections instead of observation_index
func BuildLeadGenerationPrompt(req *LeadGenerationRequest) string {
	prompt := "You are generating actionable leads from security observations.\n\n"

	// Input section
	prompt += "## Context\n\n"

	// Support both batch mode and single observation (backward compatibility)
	if len(req.Observations) > 0 {
		// Batch mode - multiple observations
		prompt += fmt.Sprintf("**New Observations (%d):**\n", len(req.Observations))
		for i, obs := range req.Observations {
			prompt += fmt.Sprintf("\n**Observation %d (ID: %s):**\n", i+1, obs.ID)
			prompt += fmt.Sprintf("- What: %s\n", obs.What)
			prompt += fmt.Sprintf("- Where: %s\n", obs.Where)
			prompt += fmt.Sprintf("- Why: %s\n", obs.Why)
			// CRITICAL: Include Hint field if present
			if obs.Hint != "" {
				prompt += fmt.Sprintf("- **HINT**: %s\n", obs.Hint)
			}
		}
	} else {
		// Single observation mode (backward compatibility)
		prompt += fmt.Sprintf("**New Observation (ID: %s):**\n", req.Observation.ID)
		prompt += fmt.Sprintf("- What: %s\n", req.Observation.What)
		prompt += fmt.Sprintf("- Where: %s\n", req.Observation.Where)
		prompt += fmt.Sprintf("- Why: %s\n", req.Observation.Why)

		// CRITICAL: Include Hint field if present
		if req.Observation.Hint != "" {
			prompt += fmt.Sprintf("- **HINT**: %s\n", req.Observation.Hint)
		}
	}

	// Existing leads section (NEW - for deduplication)
	if len(req.ExistingLeads) > 0 {
		prompt += fmt.Sprintf("\n**Existing Leads (%d) - CHECK FOR DUPLICATES:**\n", len(req.ExistingLeads))
		for i, lead := range req.ExistingLeads {
			prompt += fmt.Sprintf("\n**Lead %d (ID: %s):**\n", i+1, lead.ID)
			prompt += fmt.Sprintf("- Title: %s\n", lead.Title)
			prompt += fmt.Sprintf("- Actionable Step: %s\n", lead.ActionableStep)
			if len(lead.PoCs) > 0 {
				prompt += "- PoCs:\n"
				for j, poc := range lead.PoCs {
					prompt += fmt.Sprintf("  %d. %s\n", j+1, poc.Payload)
				}
			}
		}
		prompt += "\nIMPORTANT: Before creating a new lead, check if an existing lead already covers the same testing approach.\n"
		prompt += "If an existing lead is conceptually equivalent, do NOT create a duplicate - instead create a connection to the existing lead.\n"
	}

	// Site map section (NEW - for context about available endpoints)
	if len(req.SiteMapEntries) > 0 {
		prompt += fmt.Sprintf("\n**Site Map (%d entries) - ALL AVAILABLE ENDPOINTS:**\n", len(req.SiteMapEntries))
		prompt += "Each entry shows the endpoint URL, method, exchange_id (for getExchange tool), and comment.\n\n"
		for i, entry := range req.SiteMapEntries {
			prompt += fmt.Sprintf("%d. **%s %s** (exchange_id: %s)\n", i+1, entry.Method, entry.URL, entry.ID)
			if entry.Comment != "" {
				prompt += "   Comment: " + entry.Comment + "\n"
			}
		}
		prompt += "\n**USE THIS SITE MAP TO:**\n"
		prompt += "- Understand what endpoints are available on the target\n"
		prompt += "- Identify related endpoints for testing (e.g., /api/login vs /api/user)\n"
		prompt += "- Use exchange_id with getExchange() tool to examine exact requests\n"
		prompt += "- Craft accurate PoCs that target real endpoints\n\n"
	}

	// Available tools section (NEW - getExchange tool)
	prompt += "\n## Available Tools\n\n"
	prompt += "You have access to the **getExchange** tool.\n\n"
	prompt += "**⚠️ MANDATORY USAGE:**\n"
	prompt += "You **MUST** call getExchange() for EVERY observation before generating a lead.\n"
	prompt += "Leads generated WITHOUT examining the actual HTTP exchange will be REJECTED.\n\n"
	prompt += "**When to use it:**\n"
	prompt += "- ALWAYS before generating a lead (to see exact headers, URLs, body format)\n"
	prompt += "- When you need to understand authentication headers\n"
	prompt += "- When observation mentions specific parameters or values\n"
	prompt += "- To craft accurate PoCs with exact syntax\n\n"
	prompt += "**How to use:**\n"
	prompt += "Call getExchange(exchangeID) where exchangeID comes from Observation.ExchangeID field\n\n"
	prompt += "**Example:**\n"
	prompt += "```\n"
	prompt += "Observation: \"Cookie header contains weak session token (session=abc123)\"\n"
	prompt += "ExchangeID: \"exch-456\"\n\n"
	prompt += "Step 1: Call getExchange(\"exch-456\")\n"
	prompt += "Returns: Full HTTP request with all headers, body, URL\n\n"
	prompt += "Step 2: Use this information to craft accurate PoC:\n"
	prompt += "curl -X GET 'https://...' -H 'Cookie: session=abc123' ...\n"
	prompt += "```\n\n"
	prompt += "**Remember:** ALWAYS examine the actual HTTP exchange before writing PoCs. Generic PoCs without exact headers/values are not useful.\n\n"

	// BigPicture context (optional)
	if req.BigPicture != nil {
		prompt += "\n**Site Context (Big Picture):**\n"
		prompt += fmt.Sprintf("- Description: %s\n", req.BigPicture.Description)
		prompt += fmt.Sprintf("- Functionalities: %s\n", req.BigPicture.Functionalities)
		prompt += fmt.Sprintf("- Technologies: %s\n", req.BigPicture.Technologies)
	}

	// Task description
	prompt += "\n## Task\n\n"

	prompt += "Generate 0, 1, or MULTIPLE actionable leads from the new observations.\n\n"
	prompt += "**Key Requirements:**\n"
	prompt += "1. **Check for duplicates** - Review existing leads and reuse them when conceptually equivalent\n"
	prompt += "2. **Many-to-many relationships** - One lead can relate to MULTIPLE observations\n"
	prompt += "3. **Create connections** - Link leads to observations using Connection entities (obs-*, lead-*)\n\n"

	prompt += "**Decision Process:**\n"
	prompt += "- For each new observation, check existing leads\n"
	prompt += "- If existing lead covers this observation → Create Connection(obs-*, existing-lead-*)\n"
	prompt += "- If no existing lead applies → Create new Lead + Connections\n\n"

	prompt += "If NO actionable leads - return empty arrays: {\"leads\": [], \"connections\": []}\n"

	// Output format
	prompt += "\n## Output Format (JSON):\n\n"
	prompt += `{
  "leads": [
    {
      "is_actionable": true,
      "title": "Short title (max 10 words)",
      "actionable_step": "Specific what to try",
      "pocs": [
        {
          "payload": "Testing instruction (curl command, description, or steps)",
          "comment": "Explanation of what this PoC tests"
        }
      ]
    }
  ],
  "connections": [
    {
      "id1": "obs-19",
      "id2": "lead-45",
      "reason": "This observation suggests file enumeration"
    },
    {
      "id1": "obs-20",
      "id2": "lead-45",
      "reason": "This observation also suggests file enumeration"
    }
  ]
}
`

	prompt += `
**IMPORTANT NOTES:**
- "id1" and "id2" in connections use the actual observation/lead IDs (e.g., "obs-19", "lead-45")
- One lead can connect to MULTIPLE observations (see example above: lead-45 connects to both obs-19 and obs-20)
- When reusing existing leads, use their actual ID (e.g., "lead-42") in the connection
- Connection order doesn't matter (id1/id2 are interchangeable)
`

	// Rules section - emphasis on human-readable PoCs and deduplication
	prompt += "\n\n## Rules\n\n"
	prompt += "1. **⚠️ ALWAYS call getExchange FIRST** - Before generating ANY lead, you MUST call getExchange() to examine the actual HTTP request/response. Leads created without examining the exchange will be low-quality and may be rejected.\n"
	prompt += "2. **Check existing leads FIRST** - Before creating new leads, review existing leads for duplicates\n"
	prompt += "3. **No duplicate leads** - If an existing lead is conceptually equivalent (same testing approach), reuse it via connection\n"
	prompt += "4. **Many-to-many is OK** - One lead can relate to multiple observations, one observation can have multiple leads\n"
	prompt += "5. **Connection IDs** - Use actual entity IDs (obs-*, lead-*) in connections\n"
	prompt += "6. **Each PoC must have both payload AND comment** - both fields are required, never omit comment\n"
	prompt += "7. **Each lead must be actionable** - specific step, not generic advice\n"
	prompt += "8. **Human-readable PoCs** - provide clear instructions, NOT raw JSON payloads\n"
	prompt += "9. **Multiple PoC formats** - use curl commands, step-by-step instructions, or descriptions\n"
	prompt += "10. **Be concrete** - exact changes to make or commands to run\n"
	prompt += "11. **CRITICAL: Use the Hint field** - If observation.Hint is provided and contains specific guidance (e.g., \"try MongoDB operators\", \"test XSS with\", \"attempt SQL injection\"), you MUST generate at least one lead that follows this hint exactly. The hint contains expert security guidance that should take priority over generic approaches.\n"

	// Examples section - show new connection-based format
	prompt += "\n## Examples\n\n"

	prompt += "**Example 0: Proper workflow with getExchange tool**\n"
	prompt += "Input:\n"
	prompt += "- Observation (ID: obs-1): \"Cookie header contains session token\"\n"
	prompt += "- ExchangeID: \"exch-123\"\n\n"
	prompt += "Workflow:\n"
	prompt += "1. **CALL TOOL FIRST**: getExchange(\"exch-123\")\n"
	prompt += "   - Returns: Full HTTP request with Cookie: session=abc123def456\n"
	prompt += "   - URL: https://api.example.com/user/profile\n"
	prompt += "   - Headers: Authorization: Bearer tokenxyz...\n\n"
	prompt += "2. **GENERATE LEAD** using actual data from exchange:\n"
	prompt += "Output:\n"
	prompt += "{\n"
	prompt += `  "leads": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Test session token fixation",` + "\n"
	prompt += `      "actionable_step": "Reuse session cookie from different IP",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {"payload": "curl -X GET 'https://api.example.com/user/profile' -H 'Cookie: session=abc123def456'",` + "\n"
	prompt += `          "comment": "Reuse captured session token"}` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ],` + "\n"
	prompt += `  "connections": [` + "\n"
	prompt += `    {"id1": "obs-1", "id2": "lead-1", "reason": "Observation indicates session token in cookie"}` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "**Example 1: New lead connecting to multiple observations**\n"
	prompt += "Input: 2 observations about file enumeration, no existing leads\n\n"
	prompt += "Output:\n"
	prompt += "{\n"
	prompt += `  "leads": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Enumerate stored wallpapers",` + "\n"
	prompt += `      "actionable_step": "Brute-force the 8-character hex prefix to discover other uploaded files",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {"payload": "curl http://example.com/files/00000000.jpg", "comment": "Test prefix 00000000"},` + "\n"
	prompt += `        {"payload": "curl http://example.com/files/00000001.jpg", "comment": "Test prefix 00000001"}` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ],` + "\n"
	prompt += `  "connections": [` + "\n"
	prompt += `    {"id1": "obs-19", "id2": "lead-56", "reason": "This observation suggests file enumeration"},` + "\n"
	prompt += `    {"id1": "obs-20", "id2": "lead-56", "reason": "This observation also suggests file enumeration"}` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "**Example 2: Reusing existing lead**\n"
	prompt += "Input: 1 new observation about file enumeration\n"
	prompt += "Existing leads: lead-56 (Enumerate stored wallpapers)\n\n"
	prompt += "Output:\n"
	prompt += "{\n"
	prompt += `  "leads": [],` + "\n"
	prompt += `  "connections": [` + "\n"
	prompt += `    {"id1": "obs-21", "id2": "lead-56", "reason": "New observation also suggests file enumeration, reuse existing lead"}` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "**Example 3: No actionable leads**\n"
	prompt += "Input: Observation about static CSS file\n\n"
	prompt += "Output:\n"
	prompt += "{\n"
	prompt += `  "leads": [],` + "\n"
	prompt += `  "connections": []` + "\n"
	prompt += "}\n\n"

	// Example showing Hint usage
	prompt += "**Example 4: Using Hint field**\n"
	prompt += "Observation includes Hint: \"If any endpoint accepts this _id directly, try MongoDB operators like {$ne:null} or {$gt:''} in place of the ID to trigger NoSQL injection\"\n\n"
	prompt += "Expected lead (MUST follow the hint):\n"
	prompt += "{\n"
	prompt += `  "leads": [` + "\n"
	prompt += `    {` + "\n"
	prompt += `      "is_actionable": true,` + "\n"
	prompt += `      "title": "Test NoSQL injection with MongoDB operators",` + "\n"
	prompt += `      "actionable_step": "Replace ObjectId with MongoDB operators in the URL parameter",` + "\n"
	prompt += `      "pocs": [` + "\n"
	prompt += `        {` + "\n"
	prompt += `          "payload": "curl -X GET 'http://example.com/api/tickets/{$ne:null}' -H 'Cookie: session=...'",` + "\n"
	prompt += `          "comment": "Test NoSQL injection by using MongoDB $ne operator to bypass ObjectId validation"` + "\n"
	prompt += `        },` + "\n"
	prompt += `        {` + "\n"
	prompt += `          "payload": "curl -X GET 'http://example.com/api/tickets/{$gt:'}' -H 'Cookie: session=...'",` + "\n"
	prompt += `          "comment": "Test NoSQL injection by using MongoDB $gt operator with empty string"` + "\n"
	prompt += `        }` + "\n"
	prompt += `      ]` + "\n"
	prompt += `    }` + "\n"
	prompt += `  ],` + "\n"
	prompt += `  "connections": [` + "\n"
	prompt += `    {"id1": "obs-15", "id2": "lead-57", "reason": "Hint indicates NoSQL injection testing"}` + "\n"
	prompt += `  ]` + "\n"
	prompt += "}\n\n"

	prompt += "IMPORTANT: Focus on HUMAN-READABLE instructions that a security researcher can understand and execute."

	return prompt
}
