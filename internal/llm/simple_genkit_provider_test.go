package llm

import (
	"encoding/json"
	"testing"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// TestParseMultipleTestRequests verifies that the JSON parser can handle multiple test requests
func TestParseMultipleTestRequests(t *testing.T) {
	jsonResponse := `{
		"summary": "Test endpoint analysis",
		"findings": [{
			"title": "Test finding",
			"observation": "Test observation",
			"test_requests": [
				{
					"method": "GET",
					"url": "http://example.com/test1",
					"purpose": "Test different parameter value"
				},
				{
					"method": "POST",
					"url": "http://example.com/test2",
					"body": "{\"param\": \"value\"}",
					"purpose": "Test with modified body"
				}
			],
			"expected_if_vulnerable": "Vulnerable response",
			"expected_if_safe": "Safe response",
			"effort": "low",
			"impact": "high"
		}],
		"context_for_later": {
			"identified_patterns": ["pattern1"],
			"related_endpoints": ["/test"]
		}
	}`

	var response models.SecurityAnalysisResponse
	err := json.Unmarshal([]byte(jsonResponse), &response)

	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if len(response.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(response.Findings))
	}

	finding := response.Findings[0]
	if len(finding.TestRequests) != 2 {
		t.Fatalf("Expected 2 test requests, got %d", len(finding.TestRequests))
	}

	// Verify first test request
	test1 := finding.TestRequests[0]
	if test1.Method != "GET" {
		t.Errorf("Expected test1 method 'GET', got '%s'", test1.Method)
	}
	if test1.URL != "http://example.com/test1" {
		t.Errorf("Expected test1 URL 'http://example.com/test1', got '%s'", test1.URL)
	}
	if test1.Purpose != "Test different parameter value" {
		t.Errorf("Expected test1 purpose 'Test different parameter value', got '%s'", test1.Purpose)
	}

	// Verify second test request
	test2 := finding.TestRequests[1]
	if test2.Method != "POST" {
		t.Errorf("Expected test2 method 'POST', got '%s'", test2.Method)
	}
	if test2.Body != "{\"param\": \"value\"}" {
		t.Errorf("Expected test2 body '{\"param\": \"value\"}', got '%s'", test2.Body)
	}
	if test2.Purpose != "Test with modified body" {
		t.Errorf("Expected test2 purpose 'Test with modified body', got '%s'", test2.Purpose)
	}
}
