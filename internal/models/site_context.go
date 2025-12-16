package models

import (
	"strings"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/limits"
)

// SiteContext хранит накопленную информацию о целевом сайте (только для LLM анализа)
type SiteContext struct {
	Host        string                 `json:"host" jsonschema:"description=The target host/domain"`
	URLPatterns map[string]*URLPattern `json:"url_patterns" jsonschema:"description=URL patterns with AI notes"`
	TechStack   *TechStack             `json:"tech_stack,omitempty" jsonschema:"description=Detected technology stack"`

	// Enhanced features for better LLM context
	RecentRequests []TimedRequest              `json:"recent_requests,omitempty"`
	Forms          map[string]*HTMLForm        `json:"forms,omitempty"`
	ResourceCRUD   map[string]*ResourceMapping `json:"resource_crud,omitempty"`
	RequestCount   int64                       `json:"request_count"`
	LastActivity   int64                       `json:"last_activity"`

	// Thread safety and management
	mutex       sync.RWMutex
	limiter     *limits.ContextLimiter
	lastCleanup int64
}

// NewSiteContext создает новый экземпляр контекста для сайта.
func NewSiteContext(host string) *SiteContext {
	return &SiteContext{
		Host:           host,
		URLPatterns:    make(map[string]*URLPattern),
		RecentRequests: make([]TimedRequest, 0, MaxRecentRequests),
		Forms:          make(map[string]*HTMLForm),
		ResourceCRUD:   make(map[string]*ResourceMapping),
		RequestCount:   0,
		LastActivity:   0,
		limiter:        limits.NewContextLimiter(nil),
		lastCleanup:    time.Now().Unix(),
	}
}

// NewSiteContextWithLimiter создает новый экземпляр контекста с кастомным лимитером
func NewSiteContextWithLimiter(host string, limiter *limits.ContextLimiter) *SiteContext {
	if limiter == nil {
		limiter = limits.NewContextLimiter(nil)
	}
	return &SiteContext{
		Host:           host,
		URLPatterns:    make(map[string]*URLPattern),
		RecentRequests: make([]TimedRequest, 0, MaxRecentRequests),
		Forms:          make(map[string]*HTMLForm),
		ResourceCRUD:   make(map[string]*ResourceMapping),
		RequestCount:   0,
		LastActivity:   0,
		limiter:        limiter,
		lastCleanup:    time.Now().Unix(),
	}
}

// URLPattern представляет паттерн URL с заметками (только для LLM)
type URLPattern struct {
	Pattern string    `json:"pattern" jsonschema:"description=URL pattern"`
	Method  string    `json:"method" jsonschema:"enum=GET,enum=POST,enum=PUT,enum=DELETE,enum=PATCH,enum=OPTIONS,enum=HEAD,description=HTTP method"`
	Purpose string    `json:"purpose" jsonschema:"description=Purpose of this endpoint (e.g., 'User profile viewing')"`
	Notes   []URLNote `json:"notes" jsonschema:"description=Historical notes about this URL pattern (max 100)"`
}

// URLNote содержит заметку LLM о URL (только для анализа)
type URLNote struct {
	Content    string  `json:"content" jsonschema:"description=Note content describing the URL purpose"`
	Suspicious bool    `json:"suspicious" jsonschema:"description=Whether this URL looks suspicious"`
	VulnHint   string  `json:"vuln_hint,omitempty" jsonschema:"description=Hint about potential vulnerability"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence level (0.0-1.0),minimum=0,maximum=1"`
}

// TechStack содержит список обнаруженных технологий (упрощенная версия для LLM)
type TechStack struct {
	Technologies []Technology `json:"technologies" jsonschema:"description=List of detected technologies"`
}

// Technology представляет обнаруженную технологию (упрощенная версия для LLM)
type Technology struct {
	Name       string  `json:"name" jsonschema:"description=Technology name with version (e.g., 'React 18.2', 'PostgreSQL 14')"`
	Reason     string  `json:"reason" jsonschema:"description=Why this technology was detected"`
	Confidence float64 `json:"confidence" jsonschema:"description=Confidence in detection (0.0-1.0),minimum=0,maximum=1"`
}

// SecurityHypothesis представляет гипотезу об уязвимости (только для LLM анализа)
type SecurityHypothesis struct {
	Title          string       `json:"title" jsonschema:"description=Hypothesis title"`
	Description    string       `json:"description" jsonschema:"description=Detailed description"`
	AttackVector   string       `json:"attack_vector" jsonschema:"description=Type of attack vector"`
	TargetURLs     []string     `json:"target_urls" jsonschema:"description=URLs to investigate for this hypothesis"`
	AttackSequence []AttackStep `json:"attack_sequence" jsonschema:"description=Step-by-step attack plan"`
	Confidence     float64      `json:"confidence" jsonschema:"description=Hypothesis confidence (0.0-1.0),minimum=0,maximum=1"`
	Impact         string       `json:"impact" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,description=Potential impact"`
	Effort         string       `json:"effort" jsonschema:"enum=low,enum=medium,enum=high,description=Effort required to exploit"`
}

// AttackStep описывает один шаг в атаке для пентестера
type AttackStep struct {
	Step        int    `json:"step" jsonschema:"description=Step number in sequence"`
	Action      string `json:"action" jsonschema:"description=Attack action name"`
	Description string `json:"description" jsonschema:"description=How to perform this step (specific HTTP request)"`
	Expected    string `json:"expected" jsonschema:"description=Expected result if vulnerable vs. if protected"`
}

// TimedRequest - lightweight request snapshot
type TimedRequest struct {
	ID         string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Method     string `json:"method"`
	Path       string `json:"path"` // Normalized path
	StatusCode int    `json:"status_code"`
	Referer    string `json:"referer,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Duration   int64  `json:"duration,omitempty"` // Response duration in ms
}

// HTMLForm - extracted security-relevant form data
type HTMLForm struct {
	FormID        string      `json:"form_id"` // SHA256 of action+method
	Action        string      `json:"action"`
	Method        string      `json:"method"`
	HasCSRFToken  bool        `json:"has_csrf_token"`
	CSRFTokenName string      `json:"csrf_token_name,omitempty"`
	Fields        []FormField `json:"fields,omitempty"`
	FirstSeen     int64       `json:"first_seen"`
}

type FormField struct {
	Name      string `json:"name"`
	Type      string `json:"type"`      // text, password, hidden, etc.
	Sensitive bool   `json:"sensitive"` // password, email, etc.
}

// ResourceMapping - CRUD operations detected for a resource
type ResourceMapping struct {
	ResourcePath string            `json:"resource_path"` // "/api/users/{id}"
	Operations   map[string]string `json:"operations"`    // "GET": "read", "POST": "create"
	Identifier   string            `json:"identifier"`    // parameter name
	RelatedPaths []string          `json:"related_paths"`
	DetectedAt   int64             `json:"detected_at"`
}

// Thread-safe methods for SiteContext

// AddRecentRequest добавляет новый запрос с thread-safety и лимитами
func (sc *SiteContext) AddRecentRequest(request TimedRequest) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.limiter.ShouldCleanup(request.Timestamp) {
		return nil // Не добавляем устаревшие запросы
	}

	sc.RecentRequests = append(sc.RecentRequests, request)

	// Проверяем лимиты
	limits := sc.limiter.GetLimits()
	if len(sc.RecentRequests) > limits.MaxRecentRequests {
		// Удаляем самые старые запросы
		sc.RecentRequests = sc.RecentRequests[len(sc.RecentRequests)-limits.MaxRecentRequests:]
	}

	sc.RequestCount++
	sc.LastActivity = time.Now().Unix()

	return nil
}

// AddForm добавляет новую форму с thread-safety и лимитами
func (sc *SiteContext) AddForm(form *HTMLForm) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.Forms == nil {
		sc.Forms = make(map[string]*HTMLForm)
	}

	// Проверяем лимиты
	limits := sc.limiter.GetLimits()
	if len(sc.Forms) >= limits.MaxForms {
		// Находим и удаляем самую старую форму
		var oldestKey string
		var oldestTime int64 = time.Now().Unix()

		for key, f := range sc.Forms {
			if f.FirstSeen < oldestTime {
				oldestTime = f.FirstSeen
				oldestKey = key
			}
		}

		if oldestKey != "" {
			delete(sc.Forms, oldestKey)
		}
	}

	sc.Forms[form.FormID] = form
	sc.LastActivity = time.Now().Unix()

	return nil
}

// AddResourceMapping добавляет новый ресурс с thread-safety и лимитами
func (sc *SiteContext) AddResourceMapping(key string, mapping *ResourceMapping) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.ResourceCRUD == nil {
		sc.ResourceCRUD = make(map[string]*ResourceMapping)
	}

	// Проверяем лимиты
	limits := sc.limiter.GetLimits()
	if len(sc.ResourceCRUD) >= limits.MaxResources {
		// Находим и удаляем самый старый ресурс
		var oldestKey string
		var oldestTime int64 = time.Now().Unix()

		for k, r := range sc.ResourceCRUD {
			if r.DetectedAt < oldestTime {
				oldestTime = r.DetectedAt
				oldestKey = k
			}
		}

		if oldestKey != "" {
			delete(sc.ResourceCRUD, oldestKey)
		}
	}

	sc.ResourceCRUD[key] = mapping
	sc.LastActivity = time.Now().Unix()

	return nil
}

// UpdateURLPattern обновляет паттерн URL с thread-safety и лимитами
func (sc *SiteContext) UpdateURLPattern(patternKey string, urlPattern *URLPattern, note *URLNote) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.URLPatterns == nil {
		sc.URLPatterns = make(map[string]*URLPattern)
	}

	// Проверяем лимиты
	limits := sc.limiter.GetLimits()
	if len(sc.URLPatterns) >= limits.MaxURLPatterns {
		// Простая очистка - удаляем старые паттерны без заметок
		for key, pattern := range sc.URLPatterns {
			if len(pattern.Notes) == 0 {
				delete(sc.URLPatterns, key)
				break
			}
		}
	}

	var pattern *URLPattern
	if existing, exists := sc.URLPatterns[patternKey]; exists {
		pattern = existing

		// Ограничиваем количество заметок
		if len(pattern.Notes) >= limits.MaxNotesPerURL {
			// Удаляем самые старые заметки
			pattern.Notes = pattern.Notes[1:]
		}
		pattern.Notes = append(pattern.Notes, *note)
	} else {
		pattern = urlPattern
		if urlPattern == nil {
			// Extract method from patternKey (format: "METHOD:/path")
			parts := strings.SplitN(patternKey, ":", 2)
			method := ""
			if len(parts) == 2 {
				method = parts[0]
			}

			pattern = &URLPattern{
				Pattern: patternKey,
				Method:  method,
				Notes:   []URLNote{*note},
			}
		}
		sc.URLPatterns[patternKey] = pattern
	}

	// Обновляем purpose если есть в заметке
	if note != nil && note.Content != "" {
		pattern.Purpose = note.Content
	}

	sc.LastActivity = time.Now().Unix()

	return nil
}

// CleanupOldData выполняет очистку устаревших данных
func (sc *SiteContext) CleanupOldData() error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	now := time.Now().Unix()
	limits := sc.limiter.GetLimits()

	// Очистка старых запросов
	var validRequests []TimedRequest
	for _, req := range sc.RecentRequests {
		if !sc.limiter.ShouldCleanup(req.Timestamp) {
			validRequests = append(validRequests, req)
		}
	}
	sc.RecentRequests = validRequests

	// Очистка старых форм
	if sc.Forms != nil {
		for key, form := range sc.Forms {
			if sc.limiter.ShouldCleanup(form.FirstSeen) {
				delete(sc.Forms, key)
			}
		}
	}

	// Очистка старых ресурсов
	if sc.ResourceCRUD != nil {
		for key, resource := range sc.ResourceCRUD {
			if sc.limiter.ShouldCleanup(resource.DetectedAt) {
				delete(sc.ResourceCRUD, key)
			}
		}
	}

	// Дополнительная очистка по лимитам
	if len(sc.RecentRequests) > limits.MaxRecentRequests {
		sc.RecentRequests = sc.RecentRequests[len(sc.RecentRequests)-limits.MaxRecentRequests:]
	}

	if len(sc.Forms) > limits.MaxForms {
		count := 0
		for k, _ := range sc.Forms {
			if count >= limits.MaxForms {
				delete(sc.Forms, k)
				continue
			}
			count++
		}
	}

	if len(sc.ResourceCRUD) > limits.MaxResources {
		count := 0
		for k, _ := range sc.ResourceCRUD {
			if count >= limits.MaxResources {
				delete(sc.ResourceCRUD, k)
				continue
			}
			count++
		}
	}

	sc.lastCleanup = now
	return nil
}

// GetMemoryUsage возвращает примерное использование памяти
func (sc *SiteContext) GetMemoryUsage() int64 {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	return sc.limiter.GetMemoryUsage()
}

// GetStats возвращает статистику по контексту
func (sc *SiteContext) GetStats() map[string]interface{} {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	return map[string]interface{}{
		"host":            sc.Host,
		"url_patterns":    len(sc.URLPatterns),
		"recent_requests": len(sc.RecentRequests),
		"forms":           len(sc.Forms),
		"resources":       len(sc.ResourceCRUD),
		"request_count":   sc.RequestCount,
		"last_activity":   sc.LastActivity,
		"last_cleanup":    sc.lastCleanup,
		"memory_estimate": sc.limiter.GetMemoryUsage(),
	}
}

// Memory limits
const (
	MaxRecentRequests = 50 // Per host
	MaxForms          = 20 // Per host
	MaxResources      = 30 // Per host
	MaxAgeHours       = 24 // Cleanup after 24h
)
