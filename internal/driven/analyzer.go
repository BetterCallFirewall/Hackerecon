package driven

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/utils"
	"github.com/BetterCallFirewall/Hackerecon/internal/verification"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
	"github.com/PuerkitoBio/goquery"
	genkitcore "github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
)

// Пакет-уровневые паттерны для оптимизации hot path
// Компилируются один раз при запуске программы
var (
	// whitespaceRegex - паттерн для замены множественных пробелов на один
	whitespaceRegex = regexp.MustCompile(`\s+`)
)

// GenkitSecurityAnalyzer анализирует HTTP трафик на наличие уязвимостей безопасности
// используя LLM модели через кастомный провайдер. Поддерживает двухэтапный анализ с кэшированием
// и автоматическую генерацию гипотез об уязвимостях.
type GenkitSecurityAnalyzer struct {
	// Core components
	llmProvider llm.Provider
	WsHub       *websocket.WebsocketManager
	genkitApp   *genkit.Genkit

	// Analysis flow (возвращает SecurityAnalysisResponse или nil если анализ не нужен)
	unifiedAnalysisFlow *genkitcore.Flow[*models.SecurityAnalysisRequest, *models.SecurityAnalysisResponse, struct{}]

	// Verification flow
	verificationFlow *genkitcore.Flow[*models.VerificationRequest, *models.VerificationResponse, struct{}]

	// Modular components
	contextManager *SiteContextManager
	dataExtractor  *DataExtractor
	hypothesisGen  *HypothesisGenerator
	requestFilter  *utils.RequestFilter

	// Verification client
	verificationClient *verification.VerificationClient
}

// NewGenkitSecurityAnalyzer создаёт анализатор с кастомным LLM провайдером
func NewGenkitSecurityAnalyzer(
	genkitApp *genkit.Genkit,
	provider llm.Provider,
	wsHub *websocket.WebsocketManager,
) (*GenkitSecurityAnalyzer, error) {
	analyzer := &GenkitSecurityAnalyzer{
		llmProvider: provider,
		WsHub:       wsHub,
		genkitApp:   genkitApp,

		// Инициализация компонентов
		contextManager: NewSiteContextManager(),
		requestFilter:  utils.NewRequestFilter(),
	}

	// Инициализация data extractor
	analyzer.dataExtractor = NewDataExtractor()

	// Определяем unified flow с orchestration двух LLM вызовов
	analyzer.unifiedAnalysisFlow = genkit.DefineFlow(
		genkitApp, "unifiedAnalysisFlow",
		func(ctx context.Context, req *models.SecurityAnalysisRequest) (*models.SecurityAnalysisResponse, error) {
			// Step 1: Quick URL Analysis (traced)
			urlAnalysisReq := &models.URLAnalysisRequest{
				URL:          req.URL,
				Method:       req.Method,
				Headers:      req.Headers,
				ResponseBody: req.ResponseBody,
				ContentType:  req.ContentType,
				SiteContext:  req.SiteContext,
			}

			urlAnalysisResp, err := genkit.Run(
				ctx, "quick-url-analysis", func() (*models.URLAnalysisResponse, error) {
					return analyzer.llmProvider.GenerateURLAnalysis(ctx, urlAnalysisReq)
				},
			)
			if err != nil {
				return nil, fmt.Errorf("quick URL analysis failed: %w", err)
			}

			// Step 2: Update URL pattern в контексте
			if req.SiteContext != nil {
				analyzer.updateURLPattern(req.SiteContext, req.URL, req.Method, urlAnalysisResp.URLNote)
			}

			// Step 3: Решаем, нужен ли полный анализ (решение принимает LLM)
			if !urlAnalysisResp.ShouldAnalyze {
				// Быстрый анализ достаточен - возвращаем nil
				return nil, nil
			}

			// Step 5: Extract data для полного анализа (traced)
			extractedData, err := genkit.Run(
				ctx, "extract-data", func() (models.ExtractedData, error) {
					if analyzer.shouldExtractData(req.ContentType, req.ResponseBody) {
						return analyzer.dataExtractor.ExtractFromContent(
							req.RequestBody,
							req.ResponseBody,
							req.ContentType,
						), nil
					}
					return models.ExtractedData{
						FormActions: []string{},
						Comments:    []string{},
					}, nil
				},
			)
			if err != nil {
				return nil, err
			}

			// Step 6: Full Security Analysis (traced)
			req.ExtractedData = extractedData

			return genkit.Run(
				ctx, "full-security-analysis", func() (*models.SecurityAnalysisResponse, error) {
					return analyzer.llmProvider.GenerateSecurityAnalysis(ctx, req)
				},
			)
		},
	)

	// Определяем flow для генерации гипотез с orchestration
	hypothesisFlow := genkit.DefineFlow(
		genkitApp, "hypothesisFlow",
		func(ctx context.Context, req *models.HypothesisRequest) (*models.HypothesisResponse, error) {
			// LLM hypothesis generation с трейсингом
			result, err := genkit.Run(
				ctx, "llm-hypothesis-generation", func() (*models.HypothesisResponse, error) {
					return analyzer.llmProvider.GenerateHypothesis(ctx, req)
				},
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate hypothesis: %w", err)
			}

			return result, nil
		},
	)

	// Инициализация генератора гипотез
	analyzer.hypothesisGen = NewHypothesisGenerator(
		hypothesisFlow,
		wsHub,
		analyzer.contextManager,
	)

	// Initialize verification client
	analyzer.verificationClient = verification.NewVerificationClient(verification.VerificationClientConfig{
		Timeout:    30 * time.Second,
		MaxRetries: 2,
	})

	// Initialize verification flow
	analyzer.verificationFlow = genkit.DefineFlow(
		analyzer.genkitApp,
		"verificationFlow",
		func(ctx context.Context, req *models.VerificationRequest) (*models.VerificationResponse, error) {
			return analyzer.verifyHypothesis(ctx, req)
		},
	)

	return analyzer, nil
}

// AnalyzeHTTPTraffic анализирует HTTP трафик с unified flow
func (analyzer *GenkitSecurityAnalyzer) AnalyzeHTTPTraffic(
	ctx context.Context, req *http.Request, resp *http.Response, reqBody, respBody, contentType string,
) error {
	// 1. Умная фильтрация запросов
	shouldSkip, reason := analyzer.requestFilter.ShouldSkipRequestWithReason(req, resp, contentType)
	if shouldSkip {
		log.Printf("⚪️ Пропуск анализа %s %s: %s", req.Method, req.URL.String(), reason)
		return nil // Пропускаем анализ
	}

	log.Printf("🔍 Анализ запроса: %s %s (Content-Type: %s)", req.Method, req.URL.String(), contentType)

	// 2. Получаем/создаем контекст сайта (LLM будет использовать его для принятия решений)
	siteContext := analyzer.getOrCreateSiteContext(req.URL.Host)

	// 3. Unified анализ через один orchestration flow
	//    Quick Analysis всегда выполняется - LLM сам решает нужен ли Full Analysis
	//    на основе контекста сайта и подозрительных паттернов

	analysisReq := &models.SecurityAnalysisRequest{
		URL:          req.URL.String(),
		Method:       req.Method,
		Headers:      convertHeaders(req.Header),
		RequestBody:  analyzer.prepareContentForLLM(reqBody, req.Header.Get("Content-Type")),
		ResponseBody: analyzer.prepareContentForLLM(respBody, contentType),
		ContentType:  contentType,
		ExtractedData: models.ExtractedData{
			FormActions: []string{},
			Comments:    []string{},
		},
		SiteContext: siteContext,
	}

	// Запускаем unified flow (Quick → Full если LLM решит)
	securityAnalysis, err := analyzer.unifiedAnalysisFlow.Run(ctx, analysisReq)
	if err != nil {
		log.Printf("❌ Unified analysis failed: %v", err)
		return err
	}

	// 4. Отправляем результат в WebSocket
	analyzer.broadcastAnalysisResult(req, resp, securityAnalysis, reqBody, respBody)

	// 5. Логируем результат
	if securityAnalysis != nil && securityAnalysis.HasVulnerability {
		log.Printf(
			"🔬 Полный анализ завершен для %s %s (риск: %s)",
			req.Method, req.URL.String(), securityAnalysis.RiskLevel,
		)
	} else {
		log.Printf("✅ Анализ завершен для %s %s", req.Method, req.URL.String())
	}

	return nil
}

// broadcastAnalysisResult отправляет результат анализа в WebSocket
func (analyzer *GenkitSecurityAnalyzer) broadcastAnalysisResult(
	req *http.Request,
	resp *http.Response,
	result *models.SecurityAnalysisResponse,
	reqBody, respBody string,
) {
	// Логируем критические находки
	if result.HasVulnerability && (result.RiskLevel == "high" || result.RiskLevel == "critical") {
		log.Printf("🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: %s - Risk: %s", req.URL.String(), result.RiskLevel)
		log.Printf("💡 AI Комментарий: %s", result.AIComment)
	}

	// Convert request info
	requestInfo := models.RequestResponseInfo{
		URL:         req.URL.String(),
		Method:      req.Method,
		StatusCode:  resp.StatusCode,
		ReqHeaders:  convertHeaders(req.Header),
		RespHeaders: convertHeaders(resp.Header),
		ReqBody:     llm.TruncateString(reqBody, maxContentSizeForLLM),
		RespBody:    llm.TruncateString(respBody, maxContentSizeForLLM),
	}

	// Run synchronous verification if there are checklist items
	if result.HasVulnerability && len(result.SecurityChecklist) > 0 {
		log.Printf("🔬 Starting synchronous verification for %d checklist items", len(result.SecurityChecklist))
		
		// Verify and filter checklist
		verifiedChecklist := analyzer.verifyAndFilterChecklist(result.SecurityChecklist, requestInfo)
		
		// Update checklist with only valid items
		result.SecurityChecklist = verifiedChecklist
		
		// If all items were filtered out, mark as no vulnerability
		if len(verifiedChecklist) == 0 {
			result.HasVulnerability = false
			result.RiskLevel = "low"
			log.Printf("✅ All checklist items filtered as false positives")
		} else {
			log.Printf("✅ Verification completed: %d valid items (filtered %d)", 
				len(verifiedChecklist), len(result.SecurityChecklist)-len(verifiedChecklist))
		}
	}

	// Broadcast final result with verified checklist
	reportID := uuid.New().String()
	analyzer.WsHub.Broadcast(models.ReportDTO{
		Report: models.VulnerabilityReport{
			ID:             reportID,
			Timestamp:      time.Now(),
			AnalysisResult: *result,
		},
		RequestResponse: requestInfo,
	})
}

// verifyAndFilterChecklist synchronously verifies checklist items and filters out false positives
func (analyzer *GenkitSecurityAnalyzer) verifyAndFilterChecklist(
	checklist []models.SecurityCheckItem,
	requestInfo models.RequestResponseInfo,
) []models.SecurityCheckItem {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	validItems := make([]models.SecurityCheckItem, 0, len(checklist))

	for i, item := range checklist {
		// Generate hypothesis on the fly
		hypothesis := item.Action + " - " + item.Description

		// Create verification request
		verificationReq := &models.VerificationRequest{
			OriginalRequest: requestInfo,
			ChecklistItem:   item,
			MaxAttempts:     3,
		}

		// Execute verification
		verificationResult, err := genkit.Run(
			ctx, "verification", func() (*models.VerificationResponse, error) {
				return analyzer.verifyHypothesis(ctx, verificationReq, hypothesis)
			},
		)

		if err != nil {
			log.Printf("❌ Verification failed for item %d: %v", i, err)
			// On error, keep item as inconclusive
			item.VerificationStatus = "inconclusive"
			item.VerificationReason = fmt.Sprintf("Verification failed: %v", err)
			validItems = append(validItems, item)
			continue
		}

		// Update item with verification results
		item.VerificationStatus = verificationResult.Status
		item.ConfidenceScore = verificationResult.UpdatedConfidence
		item.VerificationReason = verificationResult.Reasoning
		item.RecommendedPOC = verificationResult.RecommendedPOC

		log.Printf("📋 Item %d: %s - Status: %s (confidence: %.2f)",
			i, item.Action, verificationResult.Status, verificationResult.UpdatedConfidence)

		// Filter: keep only verified, inconclusive, and manual_check
		// Drop likely_false items
		if verificationResult.Status == "likely_false" {
			log.Printf("🔴 Filtered out as false positive: %s", item.Action)
			continue
		}

		// Also filter by confidence - keep only if confidence > 0.3
		if verificationResult.UpdatedConfidence < 0.3 {
			log.Printf("🔴 Filtered out low confidence (%.2f): %s",
				verificationResult.UpdatedConfidence, item.Action)
			continue
		}

		validItems = append(validItems, item)
	}

	return validItems
}

// getOrCreateSiteContext получает или создает контекст для хоста.
func (analyzer *GenkitSecurityAnalyzer) getOrCreateSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.GetOrCreate(host)
}

func (analyzer *GenkitSecurityAnalyzer) prepareContentForLLM(content, contentType string) string {
	if len(content) == 0 {
		return "empty"
	}

	// Для HTML извлекаем только текст без тегов и разметки, чтобы модель поняла суть страницы
	if strings.Contains(contentType, "html") {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
		if err == nil {
			// Удаляем скрипты и стили, чтобы они не загромождали контекст
			doc.Find("script, style").Remove()
			// Возвращаем только текст из body
			textContent := doc.Find("body").Text()
			// Заменяем множественные пробелы и переносы строк на один пробел
			textContent = whitespaceRegex.ReplaceAllString(textContent, " ")
			return llm.TruncateString("HTML Text Content: "+textContent, 2000) // Ограничиваем до 2000 символов
		}
	}

	// Для JavaScript и JSON просто обрезаем, т.к. их структура важна
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		return llm.TruncateString(content, 2000) // Ограничиваем до 2000 символов
	}

	// Для всего остального (например, text/plain) тоже обрезаем
	return llm.TruncateString(content, 3500)
}

// shouldExtractData проверяет, нужно ли извлекать данные (только для HTML/JS)
func (analyzer *GenkitSecurityAnalyzer) shouldExtractData(contentType, body string) bool {
	// Извлекаем только для HTML и JavaScript
	isHTML := strings.Contains(contentType, "html") || strings.Contains(body, "<html") || strings.Contains(
		body, "<!DOCTYPE",
	)
	isJS := strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json")

	return isHTML || isJS
}

// Функции для работы с URL паттернами

// updateURLPattern обновляет паттерн URL с новой заметкой
func (analyzer *GenkitSecurityAnalyzer) updateURLPattern(
	siteContext *models.SiteContext, url, method string, urlNote *models.URLNote,
) {
	analyzer.contextManager.UpdateURLPattern(siteContext, url, method, urlNote)
}

// GenerateHypothesisForHost принудительно генерирует гипотезу для хоста
func (analyzer *GenkitSecurityAnalyzer) GenerateHypothesisForHost(host string) (*models.HypothesisResponse, error) {
	return analyzer.hypothesisGen.GenerateForHost(host)
}

// verifyHypothesis верифицирует гипотезу об уязвимости с помощью LLM
func (analyzer *GenkitSecurityAnalyzer) verifyHypothesis(
	ctx context.Context,
	req *models.VerificationRequest,
	hypothesis string,
) (*models.VerificationResponse, error) {
	log.Printf("🔬 Starting verification for: %s", hypothesis)

	// Шаг 1: LLM генерирует тестовые запросы на основе гипотезы
	prompt := analyzer.buildVerificationPrompt(req, hypothesis)

	llmResponse, err := analyzer.llmProvider.GenerateVerificationPlan(ctx, &models.VerificationPlanRequest{
		Hypothesis:      hypothesis,
		OriginalRequest: req.OriginalRequest,
		MaxAttempts:     req.MaxAttempts,
		TargetURL:       req.OriginalRequest.URL,
		AdditionalInfo:  prompt,
	})

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: 0.5,
			Reasoning:         fmt.Sprintf("Failed to generate verification plan: %v", err),
			TestAttempts:      []models.TestAttempt{},
		}, nil
	}

	// Шаг 2: Выполняем сгенерированные тестовые запросы
	var testAttempts []models.TestAttempt
	var successfulTests []models.TestAttempt

	for _, testReq := range llmResponse.TestRequests {
		// Конвертируем в формат verification client
		verificationReq := verification.TestRequest{
			URL:     testReq.URL,
			Method:  testReq.Method,
			Headers: testReq.Headers,
			Body:    testReq.Body,
		}

		// Выполняем запрос
		testResp, err := analyzer.verificationClient.MakeRequest(ctx, verificationReq)

		testAttempt := models.TestAttempt{
			RequestURL:    testReq.URL,
			RequestMethod: testReq.Method,
			Headers:       make(map[string]string),
		}

		if err != nil {
			testAttempt.Error = err.Error()
			testAttempt.StatusCode = 0
			log.Printf("❌ Test request failed: %s - %v", testReq.URL, err)
		} else {
			testAttempt.StatusCode = testResp.StatusCode
			testAttempt.ResponseSize = testResp.ResponseSize
			testAttempt.ResponseBody = testResp.ResponseBody
			testAttempt.Headers = testResp.Headers
			testAttempt.Duration = testResp.Duration.String()
			successfulTests = append(successfulTests, testAttempt)
			log.Printf("✅ Test request completed: %s - Status: %d", testReq.URL, testResp.StatusCode)
		}

		testAttempts = append(testAttempts, testAttempt)
	}

	// Шаг 3: LLM анализирует результаты и определяет статус верификации
	analysisResponse, err := analyzer.llmProvider.AnalyzeVerificationResults(ctx, &models.VerificationAnalysisRequest{
		Hypothesis:         hypothesis,
		OriginalConfidence: 0.5, // Default initial confidence
		TestResults:        successfulTests,
		OriginalRequest:    req.OriginalRequest,
	})

	if err != nil {
		return &models.VerificationResponse{
			Status:            "inconclusive",
			UpdatedConfidence: 0.5,
			Reasoning:         fmt.Sprintf("Failed to analyze verification results: %v", err),
			TestAttempts:      testAttempts,
		}, nil
	}

	log.Printf("🎯 Verification completed: %s - Status: %s", hypothesis, analysisResponse.Status)

	return &models.VerificationResponse{
		Status:            analysisResponse.Status,
		UpdatedConfidence: analysisResponse.UpdatedConfidence,
		Reasoning:         analysisResponse.Reasoning,
		TestAttempts:      testAttempts,
		RecommendedPOC:    analysisResponse.RecommendedPOC,
	}, nil
}

// buildVerificationPrompt создает промпт для LLM с контекстом верификации
func (analyzer *GenkitSecurityAnalyzer) buildVerificationPrompt(
	req *models.VerificationRequest,
	hypothesis string,
) string {
	return fmt.Sprintf(`You are a security verification assistant. Your task is to verify a security hypothesis by generating and analyzing test requests.

HYPOTHESIS TO VERIFY: %s
TARGET: %s

ORIGINAL REQUEST DETAILS:
- Method: %s
- URL: %s
- Status Code: %d
- Response Size: %d bytes

VERIFICATION REQUIREMENTS:
1. Generate %d test requests to verify this hypothesis
2. Each request should target the specific vulnerability type suggested
3. Focus on non-destructive testing that demonstrates the vulnerability
4. Include variations in parameters, payloads, or endpoints as appropriate
5. Consider both positive (vulnerable) and negative (secure) test cases

Generate targeted test requests that can definitively prove or disprove this security hypothesis.`,
		hypothesis,
		req.OriginalRequest.URL,
		req.OriginalRequest.Method,
		req.OriginalRequest.URL,
		req.OriginalRequest.StatusCode,
		len(req.OriginalRequest.RespBody),
		req.MaxAttempts)
}

// GetSiteContext возвращает контекст для хоста (для отладки)
func (analyzer *GenkitSecurityAnalyzer) GetSiteContext(host string) *models.SiteContext {
	return analyzer.contextManager.Get(host)
}
