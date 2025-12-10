package utils

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Пакет-уровневые паттерны для оптимизации hot path
// Эти паттерны компилируются один раз при запуске программы,
// а не при каждом вызове функции, что значительно улучшает производительность
// при обработке больших объемов HTTP-запросов.
var (
	// uuidPattern - паттерн для UUID в формате RFC 4122
	// Например: 550e8400-e29b-41d4-a716-446655440000
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	// datePattern - паттерн для даты в формате YYYY-MM-DD
	// Например: 2024-01-15
	datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

	// idPattern - паттерн для slug-строк (для нормализации URL)
	// Содержит строчные буквы, цифры и дефисы, длина 3-50 символов
	slugPattern = regexp.MustCompile(`^[a-z0-9-]{3,50}$`)

	// hashPattern - паттерн для хешей и токенов
	// Hex-символы длиной 16-64 символов
	hashPattern = regexp.MustCompile(`^[a-z0-9]{16,64}$`)
)

// URLNormalizer отвечает за умную нормализацию URL в паттерны
type URLNormalizer struct {
	// Контекстно-зависимые правила нормализации
	contextRules []URLContextRule
}

// URLContextRule определяет правило для конкретного контекста URL
type URLContextRule struct {
	PathPattern  *regexp.Regexp // когда применять правило
	ParamPattern *regexp.Regexp // что искать
	Replacement  string         // на что заменять
	Priority     int            // приоритет
	Type         string         // тип параметра
}

// NewURLNormalizer создает новый нормализатор URL
func NewURLNormalizer() *URLNormalizer {
	return &URLNormalizer{
		contextRules: []URLContextRule{
			// UUID (самый высокий приоритет - должен проверяться первым)
			{
				PathPattern:  regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`),
				ParamPattern: regexp.MustCompile(`/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)`),
				Replacement:  "/{uuid}$2",
				Priority:     110,
				Type:         "uuid",
			},

			// API эндпоинты с ID (убираем $ чтобы работало с подпутями)
			{
				PathPattern:  regexp.MustCompile(`/api/(v\d+/)?(users|orders|products|posts|comments|files|documents|messages|notifications|sessions)/(\d+)(/|$)`),
				ParamPattern: regexp.MustCompile(`/api/(v\d+/)?(users|orders|products|posts|comments|files|documents|messages|notifications|sessions)/(\d+)(/|$)`),
				Replacement:  "/api/$1$2/{id}$4",
				Priority:     100,
				Type:         "api_id",
			},

			// API эндпоинты с username
			{
				PathPattern:  regexp.MustCompile(`/api/(v\d+/)?(profiles|accounts|blogs|channels)/([^/]+)(/|$)`),
				ParamPattern: regexp.MustCompile(`/api/(v\d+/)?(profiles|accounts|blogs|channels)/([^/]+)(/|$)`),
				Replacement:  "/api/$1$2/{username}$4",
				Priority:     95,
				Type:         "api_username",
			},

			// Профили пользователей в вебе
			// НЕ срабатывает на /profile/images, /profile/settings и т.д. (статичные пути)
			{
				PathPattern:  regexp.MustCompile(`/(users?|profiles?|accounts?)/([^/]+)$`),
				ParamPattern: regexp.MustCompile(`/(users?|profiles?|accounts?)/([^/]+)$`),
				Replacement:  "/$1/{username}",
				Priority:     90,
				Type:         "web_username",
			}, // Статьи, посты со слагами
			{
				PathPattern:  regexp.MustCompile(`/(articles?|posts?|blog|news|tutorials)/([a-z0-9-]+-[a-z0-9-]+)(/|$)`),
				ParamPattern: regexp.MustCompile(`/(articles?|posts?|blog|news|tutorials)/([a-z0-9-]+-[a-z0-9-]+)(/|$)`),
				Replacement:  "/$1/{slug}$3",
				Priority:     85,
				Type:         "slug",
			},

			// Числовые ID в контексте ресурсов (не в конце пути)
			{
				PathPattern:  regexp.MustCompile(`/(users?|orders?|items?|products?|files?|comments?|posts?|messages?|notifications?)/(\d+)(/|$)`),
				ParamPattern: regexp.MustCompile(`/(users?|orders?|items?|products?|files?|comments?|posts?|messages?|notifications?)/(\d+)(/|$)`),
				Replacement:  "/$1/{id}$3",
				Priority:     80,
				Type:         "resource_id",
			},

			// Даты в URL
			{
				PathPattern:  regexp.MustCompile(`/(archives?|calendar|schedule|reports?|log)/(\d{4}-\d{2}-\d{2})(/|$)`),
				ParamPattern: regexp.MustCompile(`/(archives?|calendar|schedule|reports?|log)/(\d{4}-\d{2}-\d{2})(/|$)`),
				Replacement:  "/$1/{date}$3",
				Priority:     70,
				Type:         "date",
			},

			// Хеши и токены (16-64 hex символов)
			{
				PathPattern:  regexp.MustCompile(`/([a-f0-9]{16,64})(/|$)`),
				ParamPattern: regexp.MustCompile(`/([a-f0-9]{16,64})(/|$)`),
				Replacement:  "/{hash}$2",
				Priority:     60,
				Type:         "hash",
			},

			// Имена пользователей в специальных контекстах
			{
				PathPattern:  regexp.MustCompile(`/(u|@|user)/([a-zA-Z0-9_-]{3,20})(/|$)`),
				ParamPattern: regexp.MustCompile(`/(u|@|user)/([a-zA-Z0-9_-]{3,20})(/|$)`),
				Replacement:  "/$1/{username}$3",
				Priority:     75,
				Type:         "explicit_username",
			},
		},
	}
}

// NormalizeURL нормализует URL в паттерн с учетом контекста
func (un *URLNormalizer) NormalizeURL(rawURL string) string {
	// Парсим URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // Возвращаем как есть если не удалось распарсить
	}

	// Работаем только с путем
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Список статичных путей, которые НЕ должны нормализоваться
	// Исключаем "api" из списка, т.к. он блокирует нормализацию API эндпоинтов
	staticPaths := []string{
		"images", "css", "js", "static", "assets", "public",
		"settings", "preferences", "config", "help", "about",
		"login", "logout", "register", "signup", "signin",
		"search", "docs", "documentation",
	}

	// Проверяем, является ли ПОСЛЕДНИЙ сегмент статичным файлом
	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathSegments) > 0 {
		lastSegment := strings.ToLower(pathSegments[len(pathSegments)-1])

		// Проверяем на расширения файлов
		if strings.Contains(lastSegment, ".") {
			ext := lastSegment[strings.LastIndex(lastSegment, ".")+1:]
			staticExts := []string{"css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot"}
			for _, staticExt := range staticExts {
				if ext == staticExt {
					if parsedURL.Scheme != "" && parsedURL.Host != "" {
						return parsedURL.Scheme + "://" + parsedURL.Host + path
					}
					return path
				}
			}
		}

		// Проверяем на статичные директории (только если это часть пути)
		for _, segment := range pathSegments {
			for _, staticPath := range staticPaths {
				if segment == staticPath {
					if parsedURL.Scheme != "" && parsedURL.Host != "" {
						return parsedURL.Scheme + "://" + parsedURL.Host + path
					}
					return path
				}
			}
		}
	}

	// Проверяем на специальные значения, которые не нужно нормализовать
	specialValues := []string{"/me", "/current", "/self", "/admin", "/settings"}
	for _, special := range specialValues {
		if strings.Contains(path, special) {
			// Не нормализуем пути со специальными значениями
			pathParts := strings.Split(strings.Trim(path, "/"), "/")
			for _, part := range pathParts {
				if part == "me" || part == "current" || part == "self" {
					if parsedURL.Scheme != "" && parsedURL.Host != "" {
						return parsedURL.Scheme + "://" + parsedURL.Host + path
					}
					return path
				}
			}
		}
	}

	// Сортируем правила по приоритету (высший приоритет первым)
	sortedRules := make([]URLContextRule, len(un.contextRules))
	copy(sortedRules, un.contextRules)
	for i := 0; i < len(sortedRules)-1; i++ {
		for j := i + 1; j < len(sortedRules); j++ {
			if sortedRules[i].Priority < sortedRules[j].Priority {
				sortedRules[i], sortedRules[j] = sortedRules[j], sortedRules[i]
			}
		}
	}

	// Ищем подходящее правило по контексту
	for _, rule := range sortedRules {
		if rule.PathPattern.MatchString(path) {
			// Применяем правило если контекст совпадает
			normalizedPath := rule.ParamPattern.ReplaceAllString(path, rule.Replacement)

			// Убираем множественные слэши
			for strings.Contains(normalizedPath, "//") {
				normalizedPath = strings.ReplaceAll(normalizedPath, "//", "/")
			}

			// ИСПРАВЛЕНИЕ: Не используем normalizedURL.String(), т.к. оно кодирует {}
			// Вместо этого возвращаем только нормализованный путь
			if parsedURL.Scheme != "" && parsedURL.Host != "" {
				return parsedURL.Scheme + "://" + parsedURL.Host + normalizedPath
			}
			return normalizedPath
		}
	}

	// Если ни одно правило не подошло, возвращаем оригинальный путь
	if parsedURL.Scheme != "" && parsedURL.Host != "" {
		return parsedURL.Scheme + "://" + parsedURL.Host + path
	}
	return path
}

// ExtractURLComponents извлекает компоненты из URL для контекста
func (un *URLNormalizer) ExtractURLComponents(rawURL string) map[string]string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return map[string]string{}
	}

	components := map[string]string{
		"scheme": parsedURL.Scheme,
		"host":   parsedURL.Host,
		"path":   parsedURL.Path,
	}

	// Извлекаем компоненты из пути
	pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

	for i, part := range pathParts {
		if part == "" {
			continue
		}

		// Проверяем на различные типы данных
		key := "part_" + strconv.Itoa(i+1)

		switch {
		case isNumeric(part):
			components[key+"_type"] = "numeric_id"
			components[key] = "{id}"
		case isUUID(part):
			components[key+"_type"] = "uuid"
			components[key] = "{uuid}"
		case isDate(part):
			components[key+"_type"] = "date"
			components[key] = "{date}"
		case isSlug(part):
			components[key+"_type"] = "slug"
			components[key] = "{slug}"
		case isHash(part):
			components[key+"_type"] = "hash"
			components[key] = "{hash}"
		default:
			components[key+"_type"] = "string"
			components[key] = "{" + part + "}"
		}
	}

	// Извлекаем query параметры
	if parsedURL.RawQuery != "" {
		queryParams := parsedURL.Query()
		components["query_params"] = strings.Join(getQueryParamKeys(queryParams), ",")
	}

	return components
}

// ContextAwareNormalizer учитывает контекст сайта при нормализации
type ContextAwareNormalizer struct {
	*URLNormalizer

	// Исторические данные о URL паттернах
	knownPatterns map[string]string // normalized -> example
	patternCounts map[string]int    // normalized -> count
}

// NewContextAwareNormalizer создает новый контекстно-зависимый нормализатор
func NewContextAwareNormalizer() *ContextAwareNormalizer {
	return &ContextAwareNormalizer{
		URLNormalizer: NewURLNormalizer(),
		knownPatterns: make(map[string]string),
		patternCounts: make(map[string]int),
	}
}

// NormalizeWithContext нормализует URL с учетом контекста
func (can *ContextAwareNormalizer) NormalizeWithContext(rawURL string) string {
	normalized := can.NormalizeURL(rawURL)

	// Обновляем статистику
	can.patternCounts[normalized]++

	// Сохраняем первый пример для обратной совместимости
	// Теперь примеры хранятся в SiteContext.URLPatterns
	if can.patternCounts[normalized] == 1 {
		can.knownPatterns[normalized] = rawURL
	}

	return normalized
}

// GetPatternExamples возвращает примеры для данного паттерна
func (can *ContextAwareNormalizer) GetPatternExamples(normalizedPattern string, limit int) []string {
	var examples []string

	// Ищем похожие паттерны
	for knownPattern, example := range can.knownPatterns {
		if arePatternsSimilar(normalizedPattern, knownPattern) {
			examples = append(examples, example)
			if len(examples) >= limit {
				break
			}
		}
	}

	return examples
}

// Вспомогательные функции

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func isUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

func isDate(s string) bool {
	return datePattern.MatchString(s)
}

func isSlug(s string) bool {
	return slugPattern.MatchString(s) && strings.Contains(s, "-")
}

func isHash(s string) bool {
	return hashPattern.MatchString(s) && len(s) >= 16
}

func getQueryParamKeys(queryParams url.Values) []string {
	keys := make([]string, 0, len(queryParams))
	for key := range queryParams {
		keys = append(keys, key)
	}
	return keys
}

func arePatternsSimilar(pattern1, pattern2 string) bool {
	// Простая проверка на схожесть паттернов
	// В реальном приложении здесь может быть более сложная логика

	parts1 := strings.Split(strings.Trim(pattern1, "/"), "/")
	parts2 := strings.Split(strings.Trim(pattern2, "/"), "/")

	if len(parts1) != len(parts2) {
		return false
	}

	// Проверяем что структура паттернов совпадает (игнорируя конкретные значения)
	for i := 0; i < len(parts1); i++ {
		if parts1[i] == "" || parts2[i] == "" {
			continue
		}

		// Если оба имеют вид {что-то}, они совпадают
		if strings.HasPrefix(parts1[i], "{") && strings.HasSuffix(parts1[i], "}") &&
			strings.HasPrefix(parts2[i], "{") && strings.HasSuffix(parts2[i], "}") {
			continue
		}

		// Иначе если они не одинаковы, паттерны разные
		if parts1[i] != parts2[i] {
			return false
		}
	}

	return true
}
