package llm

import (
	"fmt"
)

const (
	maxBodySizeForAnalystPrompt = 2000 // Maximum body size for analyst prompt (2KB)
)

// BuildAnalystPrompt creates prompt for Analyst agent
func BuildAnalystPrompt(req *AnalystRequest) string {
	return fmt.Sprintf(`You are an Analyst. Extract technical facts from this HTTP exchange.

Exchange:
Method: %s
URL: %s
Request Headers: %s
Request Body: %s
Response Status: %d
Response Headers: %s
Response Body: %s

Extract facts about:
- Technologies used
- Security mechanisms
- Interesting parameters
- Potential vulnerabilities

Be brief. Local context only (this single exchange).

Return JSON:
{
  "observations": [
    {
      "what": "fact description",
      "where": "location (URL, header, body)",
      "why": "why this is interesting"
    }
  ]
}`,
		req.Exchange.Request.Method,
		req.Exchange.Request.URL,
		formatHeaders(req.Exchange.Request.Headers),
		TruncateBody(req.Exchange.Request.Body, maxBodySizeForAnalystPrompt),
		req.Exchange.Response.StatusCode,
		formatHeaders(req.Exchange.Response.Headers),
		TruncateBody(req.Exchange.Response.Body, maxBodySizeForAnalystPrompt),
	)
}
