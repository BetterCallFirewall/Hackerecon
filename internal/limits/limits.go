package limits

import (
	"fmt"
	"time"
)

// ContextLimits определяет лимиты для хранения контекста
type ContextLimits struct {
	MaxRecentRequests int           `json:"max_recent_requests"`
	MaxForms          int           `json:"max_forms"`
	MaxResources      int           `json:"max_resources"`
	MaxAgeHours       time.Duration `json:"max_age_hours"`
	MaxURLPatterns    int           `json:"max_url_patterns"`
	MaxNotesPerURL    int           `json:"max_notes_per_url"`
}

// DefaultContextLimits возвращает лимиты по умолчанию
func DefaultContextLimits() *ContextLimits {
	return &ContextLimits{
		MaxRecentRequests: 50,
		MaxForms:          20,
		MaxResources:      30,
		MaxAgeHours:       24 * time.Hour,
		MaxURLPatterns:    100,
		MaxNotesPerURL:    100,
	}
}

// ContextLimiter предоставляет функциональность для контроля лимитов контекста
type ContextLimiter struct {
	limits *ContextLimits
}

// NewContextLimiter создает новый лимитер контекста
func NewContextLimiter(limits *ContextLimits) *ContextLimiter {
	if limits == nil {
		limits = DefaultContextLimits()
	}
	return &ContextLimiter{
		limits: limits,
	}
}

// GetLimits возвращает текущие лимиты
func (cl *ContextLimiter) GetLimits() *ContextLimits {
	return cl.limits
}

// UpdateLimits обновляет лимиты
func (cl *ContextLimiter) UpdateLimits(limits *ContextLimits) error {
	if limits.MaxRecentRequests <= 0 {
		return fmt.Errorf("MaxRecentRequests must be positive")
	}
	if limits.MaxForms <= 0 {
		return fmt.Errorf("MaxForms must be positive")
	}
	if limits.MaxResources <= 0 {
		return fmt.Errorf("MaxResources must be positive")
	}
	if limits.MaxAgeHours <= 0 {
		return fmt.Errorf("MaxAgeHours must be positive")
	}
	if limits.MaxURLPatterns <= 0 {
		return fmt.Errorf("MaxURLPatterns must be positive")
	}
	if limits.MaxNotesPerURL <= 0 {
		return fmt.Errorf("MaxNotesPerURL must be positive")
	}

	cl.limits = limits
	return nil
}

// ShouldCleanup проверяет, нуждается ли элемент в очистке по времени
func (cl *ContextLimiter) ShouldCleanup(timestamp int64) bool {
	cutoff := time.Now().Add(-cl.limits.MaxAgeHours).Unix()
	return timestamp < cutoff
}

// CleanupRequests очищает старые запросы, соблюдая лимит
func (cl *ContextLimiter) CleanupRequests(requests []interface{}) []interface{} {
	if len(requests) <= cl.limits.MaxRecentRequests {
		return requests
	}

	// Удаляем самые старые запросы
	return requests[len(requests)-cl.limits.MaxRecentRequests:]
}

// CleanupMap очищает map, соблюдая лимит
func (cl *ContextLimiter) CleanupMap(m map[string]interface{}) map[string]interface{} {
	if len(m) <= cl.limits.MaxForms && len(m) <= cl.limits.MaxResources {
		return m
	}

	maxSize := cl.limits.MaxForms
	if cl.limits.MaxResources < maxSize {
		maxSize = cl.limits.MaxResources
	}

	// Создаем новый map с последними элементами (упрощенная реализация)
	// В реальной реализации нужно учитывать время создания
	result := make(map[string]interface{})
	count := 0
	for k, v := range m {
		if count >= maxSize {
			break
		}
		result[k] = v
		count++
	}

	return result
}

// GetMemoryUsage возвращает примерное использование памяти в байтах
func (cl *ContextLimiter) GetMemoryUsage() int64 {
	// Базовый размер структуры
	baseSize := int64(1024) // 1KB для базовых полей

	// Расчет на основе лимитов
	requestsSize := int64(cl.limits.MaxRecentRequests * 200)                      // ~200 bytes per request
	formsSize := int64(cl.limits.MaxForms * 500)                                  // ~500 bytes per form
	resourcesSize := int64(cl.limits.MaxResources * 300)                          // ~300 bytes per resource
	urlPatternsSize := int64(cl.limits.MaxURLPatterns * 400)                      // ~400 bytes per URL pattern
	notesSize := int64(cl.limits.MaxURLPatterns * cl.limits.MaxNotesPerURL * 150) // ~150 bytes per note

	return baseSize + requestsSize + formsSize + resourcesSize + urlPatternsSize + notesSize
}

// ValidateLimits проверяет валидность лимитов
func (cl *ContextLimiter) ValidateLimits() error {
	if cl.limits.MaxRecentRequests > 1000 {
		return fmt.Errorf("MaxRecentRequests too large (> 1000)")
	}
	if cl.limits.MaxForms > 500 {
		return fmt.Errorf("MaxForms too large (> 500)")
	}
	if cl.limits.MaxResources > 500 {
		return fmt.Errorf("MaxResources too large (> 500)")
	}
	if cl.limits.MaxURLPatterns > 1000 {
		return fmt.Errorf("MaxURLPatterns too large (> 1000)")
	}
	if cl.limits.MaxNotesPerURL > 1000 {
		return fmt.Errorf("MaxNotesPerURL too large (> 1000)")
	}
	return nil
}
