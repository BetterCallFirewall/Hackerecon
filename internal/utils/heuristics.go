package utils

import (
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// Heuristic Analysis: быстрые проверки без LLM для определения статуса vulnerability

// QuickHeuristicAnalysis анализирует finding без LLM используя эвристики
// Returns: (status, confidence, reason) где confidence 0.0-1.0
func QuickHeuristicAnalysis(finding *models.Finding, testResult *models.TestResult, originalResp *models.ResponseData) (status string, confidence float64, reason string) {
	// Early return: no test result
	if testResult == nil {
		return "needs_llm", 0.0, "No test result available"
	}

	// Проверка 1: Identical request/response - скорее всего safe
	if originalResp != nil && isIdenticalResponse(testResult, originalResp) {
		return "likely_false", 0.95, "Response identical to original request"
	}

	// Проверка 2: Expected patterns matching
	if len(finding.TestRequests) > 0 && matchesExpectation(testResult, finding.TestRequests[0]) {
		return "confirmed", 0.90, "Response matches expected vulnerability pattern"
	}

	// Проверка 3: SQL errors - высокий индикатор уязвимости
	if ContainsSQLError(testResult.ResponseBody) {
		return "confirmed", 0.85, "SQL error detected in response"
	}

	// Проверка 4: Error traces - средний индикатор уязвимости
	if ContainsErrorTrace(testResult.ResponseBody) {
		return "likely_true", 0.75, "Error trace detected in response"
	}

	// Проверка 5: High similarity - скорее всего false positive
	if originalResp != nil {
		sim := Similarity(testResult.ResponseBody, originalResp.Body)
		if sim > 0.95 {
			return "likely_false", 0.80, "Response too similar to original (95%+)"
		}
	}

	// Проверка 6: Status code changes
	if originalResp != nil {
		// 4xx → 2xx или 2xx → 5xx может быть индикатором
		origStatus := originalResp.StatusCode
		testStatus := testResult.StatusCode

		if (origStatus >= 400 && origStatus < 500) && (testStatus >= 200 && testStatus < 300) {
			return "likely_true", 0.70, "Status changed from 4xx to 2xx"
		}
		if (origStatus >= 200 && origStatus < 300) && (testStatus >= 500) {
			return "likely_true", 0.65, "Status changed from 2xx to 5xx"
		}
	}

	// Не смогли определить эвристикой - нужен LLM
	return "needs_llm", 0.0, "Requires LLM analysis"
}

// isIdenticalResponse проверяет идентичность ответов
func isIdenticalResponse(testResult *models.TestResult, originalResp *models.ResponseData) bool {
	if testResult.StatusCode != originalResp.StatusCode {
		return false
	}

	// Exact match или очень высокое сходство
	if testResult.ResponseBody == originalResp.Body {
		return true
	}

	return Similarity(testResult.ResponseBody, originalResp.Body) > 0.99
}

// matchesExpectation проверяет соответствие ожиданиям из TestRequest
func matchesExpectation(testResult *models.TestResult, testReq models.TestRequest) bool {
	// Проверяем ExpectedIfVulnerable
	if testReq.ExpectedIfVulnerable != "" {
		if strings.Contains(testResult.ResponseBody, testReq.ExpectedIfVulnerable) {
			return true
		}
	}

	// Проверяем ExpectedIfSafe
	if testReq.ExpectedIfSafe != "" {
		if strings.Contains(testResult.ResponseBody, testReq.ExpectedIfSafe) {
			return false // Если нашли "safe" паттерн - это не vulnerability
		}
	}

	return false
}

// Similarity вычисляет простое сходство строк (0.0 - 1.0)
// Использует метрику на основе общих символов в одинаковых позициях
func Similarity(s1, s2 string) float64 {
	// Early return: exact match
	if s1 == s2 {
		return 1.0
	}

	len1 := len(s1)
	len2 := len(s2)

	// Early return: one is empty
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	// Early return: very different lengths (>50% difference)
	avgLen := float64(len1+len2) / 2.0
	lenDiff := float64(abs(len1 - len2))
	if lenDiff/avgLen > 0.5 {
		return 0.3
	}

	// Count matching characters at same positions
	minLen := len1
	if len2 < minLen {
		minLen = len2
	}

	common := 0
	for i := 0; i < minLen; i++ {
		if s1[i] == s2[i] {
			common++
		}
	}

	return float64(common) / avgLen
}

// ContainsErrorTrace проверяет наличие stack traces
func ContainsErrorTrace(body string) bool {
	patterns := []string{
		"at java.",
		"at org.",
		"at com.",
		"Traceback (most recent call last)",
		"File \"/",
		"line [0-9]+, in",
		"Exception in thread",
		"Stack trace:",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// ContainsSQLError проверяет наличие SQL ошибок
func ContainsSQLError(body string) bool {
	sqlPatterns := []string{
		"sql syntax",
		"mysql_",
		"postgresql",
		"ora-[0-9]+",
		"sqlite",
		"syntax error at or near",
		"unclosed quotation mark",
		"quoted string not properly terminated",
		"invalid column name",
		"table or view does not exist",
		"ambiguous column name",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, bodyLower)
		if matched {
			return true
		}
	}

	return false
}

// abs возвращает абсолютное значение
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ShouldSkipVerification проверяет можно ли пропустить верификацию без анализа
func ShouldSkipVerification(finding *models.Finding, originalReq *models.RequestData) bool {
	// Skip если TestRequest идентичен original request
	if len(finding.TestRequests) > 0 && isTestRequestIdentical(finding.TestRequests[0], originalReq) {
		return true
	}

	// Skip если low impact + high effort (manual check)
	if finding.Impact == "low" && finding.Effort == "high" {
		return true
	}

	return false
}

// isTestRequestIdentical проверяет идентичность тестового запроса
func isTestRequestIdentical(testReq models.TestRequest, originalReq *models.RequestData) bool {
	if testReq.Method != originalReq.Method {
		return false
	}

	if testReq.URL != originalReq.URL {
		return false
	}

	if testReq.Body != originalReq.Body {
		return false
	}

	return true
}
