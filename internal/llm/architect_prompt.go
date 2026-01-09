package llm

import (
	"fmt"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildArchitectPrompt creates prompt for Architect agent
func BuildArchitectPrompt(req *ArchitectRequest) string {
	return fmt.Sprintf(
		`You are a System Architect for a security team. Your job is to reconstruct the backend architecture and map DATA FLOWS from HTTP traffic observations.

=== INPUT ===

Raw Observations (%d):
%s

=== SITE MAP (%d routes) ===
%s

=== YOUR TASK ===

You must deduce the TECHNOLOGY STACK and map DATA FLOW CHAINS by connecting observations.

**IMPORTANT**: RawObservations come from security-focused Analyst, but contain VALUABLE metadata:
- ID formats detected (MongoDB ObjectID, UUID, integer)
- Response field names ("file_id", "user_id", etc.)
- Request/response patterns
- Parameter names and structures

EXTRACT THIS INFO from observations even if they mention security - the data is still valid for architecture!

STEP 1 - FINGERPRINT TECHNOLOGY STACK (EXPLICIT INFERENCE):

Your goal is to DEDUCE backend logic from parameter formats with EXPLICIT justification.

RULES:
• IF input is Integer ID → Likely SQL database (auto-increment)
• IF input is 24-char Hex → Likely MongoDB (ObjectID)
• IF input is JWT → Likely stateless authentication / microservices
• IF input is UUID → Likely PostgreSQL/UUID field

REQUIREMENT: Justify your inferences with SPECIFIC indicators:
❌ BAD: "MongoDB, Node.js/Express, Auth via JWT"
✅ GOOD: "MongoDB (inferred from 24-char hex ObjectIDs in /api/files/:id, /api/users/:id), Node.js/Express (inferred from connect.sid cookie in 8/10 requests), Auth via JWT (inferred from Bearer tokens in Authorization headers)"

Database Indicators:
• "24-char hex string" + Type="MongoDB ObjectID" → MongoDB
• "36-char UUID" + Type="UUID" → PostgreSQL with UUID field
• Integer IDs + Type="Integer ID" → SQL auto-increment
• Error messages: "MongoError", "PostgreSQL", "mysql_fetch"
• Response keys: "_id" → MongoDB, "id" → SQL

Backend Indicators:
• "connect.sid" cookie → Express/Node.js
• "X-Powered-By: Express" → Node.js
• "CSRF token", "sessionid" → Python/Django
• "PHPSESSID" → PHP
• Server headers, error formats

Auth Indicators:
• "Bearer" header + Type="JWT Token" → JWT
• "session", "sess:" cookie → Session-based
• "OAuth", "Bearer" + refresh token → OAuth

Output TechStack format:
"Database (justification), Backend/Framework (justification), Auth method (justification)"
Example: "MongoDB (from ObjectID patterns in 10 routes), Node.js/Express (from connect.sid), JWT (from Bearer tokens)"

STEP 2 - MAP DATA FLOW CHAINS:

**CRITICAL**: Your main job is to find CHAINS of routes that show how data flows.

**USE OBSERVATIONS + SITE MAP TOGETHER**:
- Observations tell you WHAT was detected (ID formats, field names, patterns)
- SiteMap tells you WHICH routes exist (with ExchangeID for reference)
- Cross-reference: If obs mentions "MongoDB ObjectID in /api/files/XXX", find matching route in SiteMap

HOW TO FIND CHAINS:
Look for CONNECTIONS between routes:

1. **By ID flow**:
   - Observation: "POST /api/upload returns MongoDB ObjectID (file_id)"
   - SiteMap: GET /api/files/:id exists
   - Connection: POST creates ID → GET uses same ID
   - Chain: POST /api/upload/ --> GET /api/files/:id

2. **By resource pattern**:
   - SiteMap: POST /api/users, GET /api/users/:id, PUT /api/users/:id, DELETE /api/users/:id
   - Observation: "Integer IDs in user endpoints"
   - Chain: POST /api/users/ --> GET /api/users/:id --> PUT /api/users/:id --> DELETE /api/users/:id

3. **By session/token**:
   - Observation: "JWT token returned from /api/login"
   - Observation: "JWT used in Authorization header for /api/profile"
   - Chain: POST /api/login --> GET /api/profile

4. **By parameter names**:
   - Observation: "Response has file_id field (MongoDB ObjectID)"
   - Observation: "Next request uses file_id in query parameter"
   - Chain shows data lineage

FOR EACH CHAIN:
- Route: "METHOD path1 --> METHOD path2 --> ..."
- InferredLogic: Describe what happens at each step WITH technology implications
  - Where does data come FROM? (user input, database, external API)
  - How is it TRANSFORMED? (validation, storage, processing)
  - Where does it GO TO? (database, file system, client response)
  - What TECHNOLOGY is involved? (MongoDB find(), SQL SELECT, JWT verification)

  ❌ BAD: "User requests file via file_id"
  ✅ GOOD: "User requests file via file_id (MongoDB ObjectID). The ID format suggests NoSQL document retrieval by ObjectID via MongoDB find() query."

EXAMPLE CHAINS:

GOOD CHAIN 1 (File Upload - MongoDB):
Route: "POST /api/upload --> GET /api/files/:id --> DELETE /api/files/:id"
InferredLogic: "User uploads file via POST → Server saves to MongoDB/GridFS with generated ObjectID (24-char hex) → Server returns ObjectID in response → Client retrieves file via GET /api/files/:id (MongoDB find() by ObjectID) → Client can delete via DELETE /api/files/:id. Attack surface: NoSQLi if :id parameter passed directly to MongoDB query."

GOOD CHAIN 2 (User Management - SQL):
Route: "POST /api/users --> POST /api/login --> GET /api/users/:id --> PUT /api/users/:id"
InferredLogic: "User registration via POST /api/users → User login via POST /api/login → Server returns JWT token → Client accesses profile via GET /api/users/:id using integer ID → SQL SELECT by primary key → Client updates profile via PUT /api/users/:id. Attack surface: IDOR if :id not validated, SQLi if integer parameter concatenated into SQL query."

GOOD CHAIN 3 (Shop Flow):
Route: "POST /api/shop/ --> GET /api/shop/:id --> POST /api/shop/:id/buy"
InferredLogic: "User creates shop item via POST /api/shop/ → Server stores item with MongoDB ObjectID (24-char hex) → User views item via GET /api/shop/:id (MongoDB find() by ObjectID) → User purchases item via POST /api/shop/:id/buy. Attack surface: NoSQLi in :id parameter, price manipulation if item data not validated on server."

STEP 3 - BUILD OUTPUT:

Return ONLY this JSON structure:
{
  "system_architecture": {
    "tech_stack": "MongoDB, Node.js/Express, Auth via JWT | PostgreSQL, Python/Django, Session-based | etc.",
    "data_flows": [
      {
        "route": "POST /api/upload --> GET /api/files/:id",
        "inferred_logic": "User uploads file → Server stores with generated ID → Server returns ID in response → Client retrieves file by ID via GET /api/files/:id"
      }
    ]
  }
}

=== RULES ===

1. Be SPECIFIC about tech stack - no "maybe", "could be"
2. Map 1-3 MOST INTERESTING data flow chains
3. Each chain must show 2+ routes connected by data flow
4. InferredLogic MUST describe the data journey WITH technology-specific behavior (MongoDB find(), SQL SELECT)
   - Include brief attack surface mention at the end (see examples)
5. Use "-->" to connect routes in the chain

== CRITICAL OUTPUT RULES ==

1. Return ONLY valid JSON - NO text before or after
2. Start DIRECTLY with "{"
3. End DIRECTLY with "}"
4. NO markdown code blocks`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		len(req.SiteMap),
		formatSiteMapForArchitect(req.SiteMap),
	)
}

// formatSiteMapForArchitect formats site map with focus on route structure
// Note: Comment field removed in new architecture - use TrafficDigest.Summary instead
func formatSiteMapForArchitect(entries []models.SiteMapEntry) string {
	result := ""
	for _, e := range entries {
		// Skip static assets and health checks
		if isStaticAssetForArchitect(e.URL) {
			continue
		}
		result += fmt.Sprintf("- %s %s ExchangeID: %s\n", e.Method, e.URL, e.ExchangeID)
		// If TrafficDigest is available, include the summary
		if e.Digest != nil && e.Digest.Summary != "" {
			result += fmt.Sprintf("  Summary: %s\n", e.Digest.Summary)
		}
	}
	return result
}

// isStaticAssetForArchitect checks if URL is a static asset (skip in architect analysis)
func isStaticAssetForArchitect(url string) bool {
	// Check file extensions first (these can be anywhere in the URL)
	extPatterns := []string{".css", ".js", ".png", ".jpg", ".svg"}
	for _, p := range extPatterns {
		if strings.Contains(url, p) {
			return true
		}
	}

	// Check path patterns (must be at the start to avoid substring matches)
	pathPatterns := []string{"/health", "/ping", "/static"}
	for _, p := range pathPatterns {
		if strings.HasPrefix(url, p) {
			return true
		}
	}

	return false
}
