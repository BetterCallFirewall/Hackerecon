package llm

import (
	"fmt"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildStrategistPrompt creates prompt for Strategist agent
func BuildStrategistPrompt(req *StrategistRequest) string {
	return fmt.Sprintf(
		`You are a Strategist. Aggregate and analyze these raw observations.

Raw Observations (%d):
%s

Big Picture:
Description: %s

=== SYSTEM ARCHITECTURE (from Architect) ===
%s

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

STEP 2 - THREAT MODELING (USE INDICATORS, NOT JUST CONFIRMATIONS):

Generate tasks based on TECHNOLOGY INDICATORS, even if tech stack is not 100%% confirmed.

APPROACH: [Indicator] → [Hypothesis] → [Task]

RULE: Single observation with Type="MongoDB ObjectID" → Generate NoSQLi task immediately
DO NOT wait for multiple confirmations - be AGGRESSIVE in hypothesis generation.

INDICATOR-TO-VULNERABILITY MAPPING:

• Indicator: Type="MongoDB ObjectID" OR 24-char hex ID in URL
  → Hypothesis: Backend is MongoDB
  → Task: Send GET /api/users/{\"$ne\":null} and check if status code is 200

• Indicator: Type="Integer ID" OR integer IDs in URL
  → Hypothesis: Backend is SQL database
  → Task: Send GET /api/users/1 OR 1=1-- and check for SQLi errors

• Indicator: Type="UUID"
  → Hypothesis: UUIDs are random, but check access controls
  → Task: Send GET /api/files/{OTHER_UUID} to test IDOR

• Indicator: Type="JWT Token" OR JWT in headers
  → Hypothesis: Stateless auth with potential verification bypass
  → Task: Test alg=none by removing signature from JWT

SYSTEM ARCHITECTURE (from Architect):
(See "=== SYSTEM ARCHITECTURE ===" section at top of prompt)

USE SystemArchitecture for CONTEXT, but don't require confirmation:
- If Architect says "MongoDB" → HIGH confidence, generate NoSQLi tasks
- If observations show "MongoDB ObjectID" → MEDIUM confidence, STILL generate NoSQLi tasks
- If only one observation shows hex ID → LOW confidence, GENERATE ANYWAY (let Tactician validate)

TECHNOLOGY-SPECIFIC ATTACK VECTORS (for reference):

MongoDB:
  • NoSQLi in URL params: /api/item/507f1f... → /api/item/{\"$ne\":null}
  • NoSQLi in JSON body: {\"user\":{\"$ne\":null}, \"pass\":{\"$ne\":null}}
  • Regex extraction: {\"password\":{\"$regex\":\".*\"}}
  • Operator injection: {\"$gt\":\"\"}, {\"$in\":[...]}

PostgreSQL/MySQL:
  • SQLi in string params: ' OR '1'='1
  • UNION-based extraction: ' UNION SELECT username,password FROM users--
  • Boolean-based: ' AND 1=1 (true) vs ' AND 1=2 (false)

Jinja2/Python:
  • SSTI: {{7*7}} → {{config.items()}}
  • Template injection: {{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

JWT:
  • alg=none attack: Remove signature, change payload
  • Weak secret: Brute force with jwt-cracker
  • Key confusion: RSA → HMAC

STEP 3 - PER DATAFLOW ANALYSIS (AGGRESSIVE TASK GENERATION):

FOR EACH DataFlow in SystemArchitecture.DataFlows:
1. Analyze THIS chain for indicators:
   - Input points: Where does user-controlled data enter?
   - Transformations: How is it processed/sanitized?
   - Sink points: Where does it end up (DB query, file system, response)?

2. Apply indicator-based attack vectors (AGGRESSIVE MODE):
   IF DataFlow has ID in URL (regardless of TechStack confirmation):
   → Check observation Type field:
     • Type="MongoDB ObjectID" → NoSQLi task: "Send GET /api/ENDPOINT/{\"$ne\":null}"
     • Type="Integer ID" → IDOR task: "Try sequential IDs: current-1, current+1"
     • Type="UUID" → IDOR task: "Try random UUID from other endpoint"

   IF DataFlow has user input in HTML context:
   → Check TechStack for frontend framework:
     • "React"/"Vue"/"Angular" → XSS task: "Inject <img src=x onerror=alert(1)>"
     • No framework detected → Generic XSS task: "Try <script>alert(1)</script>"

   IF DataFlow has URL parameter (redirect_url, next, etc.):
   → SSRF/Open Redirect task: "Try redirect_url=http://169.254.169.254/latest/meta-data/"

3. Output TacticianTask with SPECIFIC payloads (not generic "test for X"):

   ❌ BAD: "Test for NoSQL injection"
   ✅ GOOD: "Send GET /api/files/{\"$ne\":null} and check if status code is 200"

   ❌ BAD: "Check for IDOR vulnerability"
   ✅ GOOD: "Send GET /api/users/12346 (sequential ID) to test IDOR"

   ❌ BAD: "Test JWT authentication"
   ✅ GOOD: "Modify JWT payload, set alg=none, remove signature, resend request"

   Task format:
   - dataflow: "POST /api/upload --> GET /api/files/:id"
   - observation_ids: ["obs-1", "obs-3"] (only related to this chain)
   - description: "Send GET /api/files/{\"$ne\":null} and check if status code is 200. This bypasses ObjectID validation in MongoDB query by using $ne operator."

4. Generate MULTIPLE tasks per DataFlow if multiple indicators exist:
   - One task for NoSQLi (if MongoDB indicator)
   - One task for IDOR (if sequential ID pattern)
   - One task for authentication bypass (if JWT present)

IMPORTANT:
- Generate tasks AGGRESSIVELY - let Tactician validate via actual HTTP requests
- Better to generate 5 tasks with 1 false positive than miss 1 real vulnerability
- Include EXACT payloads in description (not just "test for X")

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
      "dataflow": "POST /api/shop/ --> GET /api/shop/:id",  // The specific route chain being analyzed
      "observation_ids": ["obs-1", "obs-3", "obs-5"],  // IDs of observations for this task (only related to THIS chain)
      "description": "NoSQLi in GET /api/shop/:id via MongoDB ObjectID injection with payload {\"$ne\":null}"
    }
  ]
}`,
		len(req.RawObservations),
		FormatObservations(req.RawObservations, false),
		req.BigPicture.Description,
		formatSystemArchitecture(req.SystemArchitecture),
		len(req.SiteMap),
		FormatSiteMap(req.SiteMap),
	)
}

// formatSystemArchitecture formats SystemArchitecture for prompt display
func formatSystemArchitecture(sa *models.SystemArchitecture) string {
	if sa == nil {
		return "  (not available)\n"
	}

	result := "Tech Stack:\n"
	result += fmt.Sprintf("  %s\n", sa.TechStack)

	result += "\nData Flows:\n"
	for i, df := range sa.DataFlows {
		result += fmt.Sprintf("  %d. Route: %s\n", i+1, df.Route)
		result += fmt.Sprintf("     Logic: %s\n", df.InferredLogic)
	}
	return result
}
