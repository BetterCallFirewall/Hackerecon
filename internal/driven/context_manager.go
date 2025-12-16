package driven

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/limits"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// SiteContextManager управляет контекстами сайтов с thread-safety и очисткой
type SiteContextManager struct {
	contexts          map[string]*models.SiteContext
	mutex             sync.RWMutex
	cleanupTicker     *time.Ticker
	stopChan          chan struct{}
	limiter           *limits.ContextLimiter
	maxContexts       int
	lastGlobalCleanup int64
}

// SiteContextManagerOptions опции для создания менеджера
type SiteContextManagerOptions struct {
	MaxContexts     int
	CleanupInterval time.Duration
	Limits          *limits.ContextLimiter
}

// DefaultSiteContextManagerOptions возвращает опции по умолчанию
func DefaultSiteContextManagerOptions() *SiteContextManagerOptions {
	return &SiteContextManagerOptions{
		MaxContexts:     100,              // Максимум 100 контекстов
		CleanupInterval: 15 * time.Minute, // Очистка каждые 15 минут
		Limits:          limits.NewContextLimiter(nil),
	}
}

// NewSiteContextManager создает новый менеджер контекстов
func NewSiteContextManager() *SiteContextManager {
	return NewSiteContextManagerWithOptions(nil)
}

// NewSiteContextManagerWithOptions создает новый менеджер контекстов с опциями
func NewSiteContextManagerWithOptions(opts *SiteContextManagerOptions) *SiteContextManager {
	if opts == nil {
		opts = DefaultSiteContextManagerOptions()
	}

	manager := &SiteContextManager{
		contexts:          make(map[string]*models.SiteContext),
		stopChan:          make(chan struct{}),
		limiter:           opts.Limits,
		maxContexts:       opts.MaxContexts,
		lastGlobalCleanup: time.Now().Unix(),
	}

	// Запускаем периодическую очистку
	if opts.CleanupInterval > 0 {
		manager.startCleanupRoutine(opts.CleanupInterval)
	}

	return manager
}

// startCleanupRoutine запускает рутину очистки
func (m *SiteContextManager) startCleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	m.cleanupTicker = ticker
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.PerformGlobalCleanup()
			case <-m.stopChan:
				return
			}
		}
	}()
}

// Stop останавливает менеджер и cleanup routine
func (m *SiteContextManager) Stop() {
	if m.cleanupTicker != nil {
		close(m.stopChan)
		m.cleanupTicker.Stop()
		m.cleanupTicker = nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Очистка всех контекстов
	for host, context := range m.contexts {
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s: %v", host, err)
		}
	}
}

// GetOrCreate получает или создает контекст для хоста
func (m *SiteContextManager) GetOrCreate(host string) *models.SiteContext {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if context, exists := m.contexts[host]; exists {
		return context
	}

	// Проверяем лимит количества контекстов
	if len(m.contexts) >= m.maxContexts {
		m.evictOldestContext()
	}

	newContext := models.NewSiteContextWithLimiter(host, m.limiter)
	m.contexts[host] = newContext
	return newContext
}

// Get возвращает контекст для хоста
func (m *SiteContextManager) Get(host string) *models.SiteContext {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.contexts[host]
}

// evictOldestContext удаляет самый старый контекст
func (m *SiteContextManager) evictOldestContext() {
	var oldestHost string
	var oldestTime int64 = time.Now().Unix()

	for host, context := range m.contexts {
		stats := context.GetStats()
		if lastActivity, ok := stats["last_activity"].(int64); ok && lastActivity < oldestTime {
			oldestTime = lastActivity
			oldestHost = host
		}
	}

	if oldestHost != "" {
		delete(m.contexts, oldestHost)
		log.Printf("Evicted oldest context for host: %s", oldestHost)
	}
}

// UpdateURLPattern обновляет паттерн URL с новой заметкой
func (m *SiteContextManager) UpdateURLPattern(
	siteContext *models.SiteContext,
	url, method string,
	urlNote *models.URLNote,
) error {
	if siteContext == nil {
		return fmt.Errorf("siteContext cannot be nil")
	}

	if urlNote == nil {
		return fmt.Errorf("urlNote cannot be nil")
	}

	patternKey := fmt.Sprintf("%s:%s", method, url)

	urlPattern := &models.URLPattern{
		Pattern: url,
		Method:  method,
		Notes:   []models.URLNote{*urlNote},
	}

	// Если есть контент в заметке, используем его как purpose
	if urlNote.Content != "" {
		urlPattern.Purpose = urlNote.Content
	}

	return siteContext.UpdateURLPattern(patternKey, urlPattern, urlNote)
}

// PerformGlobalCleanup выполняет глобальную очистку всех контекстов
func (m *SiteContextManager) PerformGlobalCleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now().Unix()
	cleanupCount := 0
	evictionCount := 0

	// Очистка каждого контекста
	for host, context := range m.contexts {
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s: %v", host, err)
			continue
		}
		cleanupCount++

		// Проверяем, не нужно ли удалить контекст полностью
		stats := context.GetStats()
		if lastActivity, ok := stats["last_activity"].(int64); ok {
			if m.limiter.ShouldCleanup(lastActivity) {
				delete(m.contexts, host)
				evictionCount++
				log.Printf("Evicted inactive context for host: %s", host)
			}
		}
	}

	// Дополнительная проверка лимитов
	if len(m.contexts) > m.maxContexts {
		m.evictOldestContext()
		evictionCount++
	}

	m.lastGlobalCleanup = now

	if cleanupCount > 0 || evictionCount > 0 {
		log.Printf("Global cleanup completed: %d contexts cleaned, %d contexts evicted, %d total contexts",
			cleanupCount, evictionCount, len(m.contexts))
	}
}

// GetStats возвращает статистику менеджера
func (m *SiteContextManager) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	totalMemory := int64(0)
	totalRequests := int64(0)
	totalURLPatterns := 0
	totalForms := 0
	totalResources := 0

	for _, context := range m.contexts {
		stats := context.GetStats()
		if mem, ok := stats["memory_estimate"].(int64); ok {
			totalMemory += mem
		}
		if req, ok := stats["request_count"].(int64); ok {
			totalRequests += req
		}
		if patterns, ok := stats["url_patterns"].(int); ok {
			totalURLPatterns += patterns
		}
		if forms, ok := stats["forms"].(int); ok {
			totalForms += forms
		}
		if resources, ok := stats["resources"].(int); ok {
			totalResources += resources
		}
	}

	return map[string]interface{}{
		"total_contexts":      len(m.contexts),
		"max_contexts":        m.maxContexts,
		"total_memory_bytes":  totalMemory,
		"total_requests":      totalRequests,
		"total_url_patterns":  totalURLPatterns,
		"total_forms":         totalForms,
		"total_resources":     totalResources,
		"last_global_cleanup": m.lastGlobalCleanup,
	}
}

// GetAllHosts возвращает список всех хостов
func (m *SiteContextManager) GetAllHosts() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	hosts := make([]string, 0, len(m.contexts))
	for host := range m.contexts {
		hosts = append(hosts, host)
	}
	return hosts
}

// RemoveContext удаляет контекст для хоста
func (m *SiteContextManager) RemoveContext(host string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if context, exists := m.contexts[host]; exists {
		// Очистка перед удалением
		if err := context.CleanupOldData(); err != nil {
			log.Printf("Error cleaning up context for %s before removal: %v", host, err)
		}
		delete(m.contexts, host)
		log.Printf("Removed context for host: %s", host)
	}
}

// UpdateLimits обновляет лимиты для всех контекстов
func (m *SiteContextManager) UpdateLimits(limits *limits.ContextLimits) error {
	if err := m.limiter.UpdateLimits(limits); err != nil {
		return fmt.Errorf("failed to update limits: %w", err)
	}

	// Обновляем лимиты для всех существующих контекстов
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, context := range m.contexts {
		// В реальной реализации нужно обновить limiter в context
		// Это может потребовать изменения структуры SiteContext
		log.Printf("Updated limits for context: %s", context.Host)
	}

	return nil
}
