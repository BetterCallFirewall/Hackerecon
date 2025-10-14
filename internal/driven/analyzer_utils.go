package driven

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// buildSecurityAnalysisPrompt создает детальный промпт для анализа
func (analyzer *GenkitSecurityAnalyzer) buildSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest) string {
	extractedDataJson, _ := json.Marshal(req.ExtractedData)

	return fmt.Sprintf(
		`
Проведи углубленный анализ безопасности HTTP запроса и ответа. Ты - эксперт по кибербезопасности.

АНАЛИЗИРУЕМЫЕ ДАННЫЕ:
URL: %s
Метод: %s
Заголовки: %v
Тело запроса: %s
Тело ответа: %s
Content-Type: %s
Извлеченные данные: %s

ЗАДАЧИ АНАЛИЗА:

1. ОЦЕНКА УЯЗВИМОСТЕЙ:
   - Проверь на SQL инъекции в параметрах и формах
   - Найди XSS уязвимости в пользовательском вводе
   - Обнаружь CSRF проблемы (отсутствие токенов)
   - Проверь Path Traversal возможности
   - Найди Command Injection векторы
   - Оцени безопасность заголовков (CSP, HSTS, X-Frame-Options)
   - Проанализируй утечки информации

2. АНАЛИЗ ИЗВЛЕЧЕННЫХ ДАННЫХ:
   - Оцени критичность найденных API ключей и секретов
   - Проверь подозрительные JavaScript функции
   - Проанализируй безопасность найденных URL'ов
   - Проверь комментарии на утечки информации

3. СОЗДАНИЕ ЧЕКЛИСТА:
   - Создай минимальный чеклист из 3-5 критически важных проверок
   - Каждый пункт должен содержать четкие инструкции для ручной проверки
   - Укажи ожидаемый результат безопасной конфигурации

4. ОЦЕНКА РИСКОВ:
   - Определи общий уровень риска (low/medium/high/critical)
   - Укажи типы найденных уязвимостей
   - Оцени уверенность в анализе (0.0-1.0)
   - Предложи конкретные рекомендации по устранению

ВАЖНО:
- Будь точным и конкретным в рекомендациях
- Если уязвимости не найдены, укажи has_vulnerability: false
- Создавай практичные чеклисты, которые можно использовать мануально
- Учитывай контекст приложения при анализе

Ответь строго в JSON формате согласно предоставленной схеме.
`,
		req.URL,
		req.Method,
		req.Headers,
		truncateString(req.RequestBody, 500),
		truncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson),
	)
}

func createSecretRegexPatterns() []*regexp.Regexp {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)(access[_\-\s]*token[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{20,}['"]|[a-zA-Z0-9]{20,})`),
		regexp.MustCompile(`(?i)(secret[_\-\s]*key[_\-\s]*[=:]\s*)(['"][a-zA-Z0-9]{16,}['"]|[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
	}
	return patterns
}

func identifySecretType(match string) string {
	lowerMatch := strings.ToLower(match)

	typeMap := map[string]string{
		"api":     "API Key",
		"token":   "Access Token",
		"secret":  "Secret Key",
		"akia":    "AWS Access Key",
		"aiza":    "Google API Key",
		"ghp_":    "GitHub Token",
		"sk_live": "Stripe Secret Key",
		"eyj":     "JWT Token",
	}

	for pattern, secretType := range typeMap {
		if strings.Contains(lowerMatch, pattern) {
			return secretType
		}
	}

	return "Unknown Secret"
}

func calculateSecretConfidence(secretType, value string) float64 {
	confidence := 0.5

	if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "AIza") {
		confidence = 0.95
	} else if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "sk_live_") {
		confidence = 0.95
	} else if len(value) > 32 && (strings.Contains(secretType, "API") || strings.Contains(secretType, "Secret")) {
		confidence = 0.8
	} else if len(value) > 16 {
		confidence = 0.7
	}

	return confidence
}

func isSuspiciousFunction(funcName, context string) (bool, string) {
	suspiciousFunctions := map[string]string{
		"eval":        "Выполнение произвольного кода",
		"settimeout":  "Потенциальное выполнение кода",
		"setinterval": "Потенциальное выполнение кода",
		"function":    "Динамическое создание функций",
		"innerhtml":   "Возможность XSS",
		"outerhtml":   "Возможность XSS",
	}

	lowerName := strings.ToLower(funcName)
	if reason, exists := suspiciousFunctions[lowerName]; exists {
		return true, reason
	}

	// Проверяем контекст
	suspiciousPatterns := []string{"crypto", "encrypt", "decrypt", "hash", "password", "token", "secret"}
	lowerContext := strings.ToLower(context)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerContext, pattern) {
			return true, fmt.Sprintf("Содержит подозрительный паттерн: %s", pattern)
		}
	}

	return false, ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func truncateSecret(secret string) string {
	if len(secret) <= 10 {
		return secret
	}
	return secret[:6] + "***" + secret[len(secret)-4:]
}

func generateReportID() string {
	return fmt.Sprintf("VR-%d", time.Now().UnixNano())
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
