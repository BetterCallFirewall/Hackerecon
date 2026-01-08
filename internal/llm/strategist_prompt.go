package llm

import (
	"fmt"
)

// BuildStrategistPrompt creates prompt for Strategist agent
func BuildStrategistPrompt(req *StrategistRequest) string {
	return fmt.Sprintf(
		`You are a Strategist. Aggregate and analyze these raw observations.

Raw Observations (%d):
%s

Big Picture:
Description: %s

Site Map (%d endpoints):
%s

Your tasks:
1. MERGE: Deduplicate and consolidate similar observations
   - When merging duplicates, collect ALL exchange_ids from merged observations
   - Example: If obs-1 has [exch-1] and obs-2 has [exch-2], merged result should have exchange_ids: [exch-1, exch-2]
2. ANALYZE: Update BigPicture with new insights
3. DIRECT: For dangerous findings, write a clear Hint for the pentester
4. GROUP: Organize related findings into tasks for the pentester
5. CONNECT: Identify EXPLOITABLE RELATIONSHIPS between findings

CRITICAL: Your most important job is finding exploitable CONNECTIONS between observations.
CTFs are rarely about single bugs - they're about chaining findings together.

Definitions:
- "DANGEROUS": Finding that could lead to:
  * Direct flag/credential exposure
  * Authentication bypass (JWT, session, IDOR)
  * Remote code execution
  * SQL injection with sensitive data
  * Privilege escalation
  NOT: informational findings like "React detected" or "CORS misconfig on public endpoint"

CHAIN OF THOUGHT - Think step by step before outputting JSON:

STEP 1 - MERGE: Scan for duplicates
  - Same what/where/why? Merge them
  - Collect ALL exchange_ids from merged observations
  - Example: obs-1 (JWT in /api/auth, exch-1) + obs-5 (JWT in /api/auth, exch-9) → single obs with [exch-1, exch-9]

STEP 2 - ANALYZE: Build a Technical Profile
  - Database: (e.g., MySQL, MongoDB, PostgreSQL). Look for ID formats (UUID vs ObjectID), error messages.
  - Backend: (e.g., Python/Django, Node/Express, PHP). Look for headers, cookie names.
  - Architecture: REST, GraphQL, etc.

STEP 3 - MAP ATTACK VECTORS (TECH STACK SPECIFIC):
  - If MongoDB + URL IDs detected -> CHECK FOR NoSQL INJECTION IN URL.
    Rule: Express.js often parses JSON in URL params automatically.
    Vector: Replace ID with JSON: /api/item/123 -> /api/item/{"$ne":null}
  - If Python/Flask + Reflected Input -> CHECK FOR SSTI.
  - If JWT -> CHECK FOR 'NONE' ALG or WEAK SECRET.

STEP 4 - CONNECT: Find EXPLOITABLE relationships (THIS IS CRITICAL)
  Good exploitable connections:
    ✓ "MongoDB ObjectID (obs-1) + REST API (obs-2) → Potential NoSQLi via URL Injection"
      Reason: Backend might pass URL parameter directly to find() query.
    ✓ "Jinja2 template syntax in error (obs-2) → user-controlled name parameter (obs-5)"
      Reason: SSTI via {{7*7}} → RCE through {{config.items()}}
    ✓ "MD5 hash as user ID in /users/a3f5e... (obs-3) → hash decryptable (obs-7)"
      Reason: Can decrypt MD5 via rainbow tables and impersonate other users
    ✓ "JWT authentication endpoint (obs-1) → public key endpoint /static/key.pem (obs-3)"
      Reason: Can download public key, attempt to forge JWT signature
    ✓ "IDOR on /api/users/{id} (obs-2) → no auth check on PUT /api/users/{id} (obs-7)"
      Reason: Chain IDOR with missing auth to modify any user's data

  Bad trivial connections (DO NOT MAKE):
    ✗ "React frontend (obs-1) → Node.js backend (obs-2)"
      Reason: Just technology stack, NOT an exploitable relationship
    ✗ "HTTPS used (obs-3) → has cookies (obs-5)"
      Reason: Standard web behavior, no exploit potential

STEP 5 - CREATE HINTS: For dangerous findings, give ACTIONABLE hints
  Good: "NoSQLi test: POST /api/login with {\"user\":{\"$ne\":null}}"
  Good: "SSTI test: {{7*7}} or {{config.items()}} in template parameter"
  Good: "MD5 ID: extract hash from /users/a3f5e..., decrypt via rainbow tables, substitute with admin's hash"
  Good: "Try negative IDs: /api/users/-1 might expose admin data"
  Bad: "Check JWT security" (too vague)
  Bad: "Test for SQLi" (no specific guidance)

STEP 6 - GROUP: Organize related findings into tasks
  - Group by exploit chain (e.g., "Authentication Bypass Chain")
  - Group by vulnerability type (e.g., "SQL Injection Opportunities")
  - Group by endpoint/feature (e.g., "User Management Issues")
  - Each task should have 2-5 related observations

== CRITICAL OUTPUT RULES ==

1. Return ONLY valid JSON - NO text before or after
2. Do NOT include conversational filler like:
   - "Here is the analysis:"
   - "I'll provide the findings:"
   - "Based on the observations:"
3. Start your response DIRECTLY with "{"
4. End DIRECTLY with "}"
5. NO markdown code blocks around JSON

Return JSON:
{
  "observations": [
    {
      "exchange_ids": ["exch-1", "exch-5"],  // ALL exchange IDs where this observation was found (merge duplicates)
      "what": "consolidated fact",
      "where": "location",
      "why": "why interesting",
      "hint": "specific exploit technique (for actionable findings)"
    }
  ],
  "connections": [
    {
      "from": "obs-1",
      "to": "obs-3",
      "reason": "JWT endpoint (obs-1) lacks algorithm verification + public key exposed (obs-3) = token forgery possible"
    }
  ],
  "big_picture_impact": {
    "field": "description|functionalities|technologies",
    "value": "updated content"
  },
  "tactician_tasks": [
    {
      "observations": [/* observation objects */],
      "description": "Authentication bypass chain: JWT + public key + no alg verification"
    }
  ],
  "technical_profile": {
    "database": "detected from error messages and ID formats",
    "backend": "inferred from headers and cookie names",
    "architecture": "REST or GraphQL",
    "notes": "specific patterns relevant to exploitation"
  }
}`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		req.BigPicture.Description,
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
	)
}
