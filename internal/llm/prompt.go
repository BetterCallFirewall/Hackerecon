package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// BuildSecurityAnalysisPrompt создаёт детальный промпт для анализа безопасности
// Это универсальная функция, которую могут использовать все провайдеры
func BuildSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	extractedDataJson, _ := json.MarshalIndent(req.ExtractedData, "", "  ")

	return fmt.Sprintf(
		`
Ты — элитный специалист по кибербезопасности, специализирующийся на поиске уязвимостей в бизнес-логике и определении технологий по HTTP трафику.

### ТЕКУЩИЙ HTTP-ОБМЕН:
URL: %s
Метод: %s
Headers: %v
Content-Type: %s

Request Body (truncated):
%s

Response Body (truncated):
%s

### ИЗВЛЕЧЕННЫЕ ДАННЫЕ:
%s

### КОНТЕКСТ СЕССИИ (%s):
%s

### ТВОИ ЗАДАЧИ:

1.  **ОПРЕДЕЛЕНИЕ ТЕХНОЛОГИЙ (КРИТИЧЕСКИ ВАЖНО!):**
    *   **База данных:** Ищи следы PostgreSQL, MySQL, MongoDB, Redis в:
        - Error messages ("pq:", "mysql_", "mongo", "SQLSTATE")
        - Response headers (X-Database, X-Powered-By)
        - Query syntax в параметрах (WHERE id = $1 → PostgreSQL, WHERE id = ? → MySQL)
        - Stack traces с именами драйверов
    *   **Backend Framework:** Express.js, Django, Flask, Spring Boot, Laravel - ищи в:
        - Headers: Server, X-Powered-By, X-Framework
        - Cookies: sessionid, csrftoken, express.sid
        - Error traces и stack traces
        - URL patterns (Django: /api/v1/, Flask: /admin/, Spring: /actuator/)
    *   **Frontend:** React, Vue, Angular - ищи в JavaScript, HTML comments
    *   **Структура запросов (БД hints):**
        - JSON body с filters/where → ORM (Django, Prisma) ИЛИ NoSQL (MongoDB)
        - JSON с вложенными объектами → вероятно MongoDB/NoSQL
        - Query params ?id=123 → REST API (SQL БД)
        - GraphQL queries → GraphQL + любая БД
        - Form data → традиционный backend (SQL)
    *   **ЕСЛИ НАШЕЛ** → укажи в поле "identified_tech_stack" в формате:
        {"database": "PostgreSQL", "backend": "Express.js", "confidence": 0.9}

2.  **АНАЛИЗ СТРУКТУРЫ ЗАПРОСА (важно для понимания БД и уязвимостей):**
    *   **Формат идентификаторов:**
        - URL: /users/123 → числовой ID (SQL БД, IDOR риск!)
        - URL: /users/507f1f77bcf86cd799439011 → MongoDB ObjectId (24 hex символа)
        - URL: /users/uuid-123-456 → UUID (SQL/NoSQL, меньше риск IDOR)
        - URL: /users/@username → username в URL
    *   **Формат фильтров и тела запроса:**
        - Query params: ?filter[status]=active&filter[role]=admin → ORM (Rails, Laravel, Prisma) + SQL
        - JSON body: {"where": {"status": "active"}} → ORM (Prisma, Sequelize) + SQL
        - JSON с $operators: {"status": {"$eq": "active"}} → MongoDB (NoSQL Injection риск!)
        - JSON вложенные объекты: {"user": {"profile": {"age": 25}}} → вероятно MongoDB
        - GraphQL: {users(filter: {status: "active"})} → GraphQL + любая БД
        - SQL-like: ?q=SELECT * FROM users → ОПАСНО! SQL Injection candidate
    *   **Порядок параметров:**
        - /api/v1/users/{user_id}/orders/{order_id} → иерархия (проверить owner check!)
        - Параметры в body vs URL → где передается ID владельца?
    *   **Анализируй на IDOR:**
        - Есть ли owner_id/user_id в запросе? Или только целевой ID?
        - Можно ли подменить ID и получить чужие данные?

3.  **АНАЛИЗ БИЗНЕС-ЛОГИКИ (Рассуждай по шагам - Chain of Thought):**
    *   **Шаг 1: Каково назначение этого запроса?** Опиши бизнес-операцию ("обновление профиля", "просмотр заказа", "удаление пользователя").
    *   **Шаг 2: Сопоставь с контекстом.** Есть ли аномалии?
        - Пользователь с ролью 'user' → админский endpoint '/api/v1/users/delete'?
        - Манипуляция ID (order_id не принадлежит user)?
        - Неожиданное изменение состояния?
    *   **Шаг 3: Сформулируй гипотезы уязвимостей** (IDOR, Broken Access Control, Race Conditions, SQL/NoSQL Injection в фильтрах).

3.  **ПОИСК ТЕХНИЧЕСКИХ УЯЗВИМОСТЕЙ:**
    *   **SQL Injection** (если SQL БД: PostgreSQL, MySQL) - WHERE, ORDER BY, LIMIT
    *   **NoSQL Injection** (если MongoDB) - $operators ($eq, $ne, $gt, $regex), JSON injection
    *   XSS, CSRF, Command Injection, Path Traversal
    *   Отсутствие заголовков безопасности (CSP, HSTS, X-Frame-Options)
    *   Критичность найденных секретов и API keys

4.  **ОБОГАЩЕНИЕ КОНТЕКСТА:**
    *   **identified_user_role**: роль пользователя ('guest', 'user', 'admin', 'service')
    *   **identified_data_objects**: объекты данных с полями (например: [{"name": "order", "fields": ["id", "user_id", "total"]}])
    *   **identified_tech_stack**: обнаруженные технологии ({"database": "PostgreSQL", "backend": "Express", "confidence": 0.8})

5.  **ИТОГОВЫЙ ВЕРДИКТ (Строго в формате JSON):**
    *   **risk_level**: СТРОГО одно из: "low", "medium", "high", "critical" (маленькими буквами)
    *   **ai_comment**: Объясни ход мыслей (на русском) - что нашел, почему это уязвимость, как эксплуатировать
    *   **security_checklist**: 2-4 шага для ПЕНТЕСТЕРА (как проверить/эксплуатировать уязвимость). Формат:
        [
          {"action": "Подмена user_id", "description": "Заменить ID в запросе: GET /api/orders/123 → GET /api/orders/456", "expected": "Если уязвима: 200 OK + чужие данные. Если защищена: 403 Forbidden"},
          {"action": "SQL Injection тест", "description": "Добавить ' в параметр: ?id=123' OR '1'='1", "expected": "Если уязвима: ошибка SQL или обход логики. Если защищена: 400 Bad Request"}
        ]
        ⚠️ ВАЖНО: 
        - "action" = что делает ПЕНТЕСТЕР (название атаки)
        - "description" = КАК выполнить атаку (конкретные шаги)
        - "expected" = ЧТО произойдёт если уязвимость есть VS если защита работает

ПРИОРИТЕТЫ:
✅ Бизнес-логика > технические уязвимости
✅ Определение БД и технологий - критически важно для контекста!
⚠️  Понижай риск если нужен brute-force ключей
⚠️  HTTP вместо HTTPS - не критично

ОТВЕТ СТРОГО В JSON согласно схеме (все текстовые поля на русском).
`,
		req.URL,
		req.Method,
		req.Headers,
		req.ContentType,
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		string(extractedDataJson),
		req.SiteContext.Host,
		string(contextJson),
	)
}

// TruncateString обрезает строку до указанной длины
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// BuildURLAnalysisPrompt создает промпт для быстрой оценки URL
func BuildURLAnalysisPrompt(req *models.URLAnalysisRequest) string {
	techStackInfo := "не определен"
	if req.SiteContext.TechStack != nil {
		techStackInfo = formatTechStackCompact(req.SiteContext.TechStack)
	}

	// Подготовка короткого фрагмента ответа для анализа
	responsePreview := TruncateString(req.ResponseBody, 300)

	return fmt.Sprintf(
		`
Ты - эксперт по веб-безопасности и анализу технологий. Быстро оцени этот эндпоинт.

### ЗАПРОС:
%s %s
Content-Type: %s
Response preview (300 символов): %s

### ТЕКУЩИЙ СТЕК ТЕХНОЛОГИЙ:
%s

### ТВОИ ЗАДАЧИ:

1. **ОПРЕДЕЛИ ТЕХНОЛОГИИ** (критически важно для контекста):
   - База данных: ищи PostgreSQL, MySQL, MongoDB, Redis в headers, error messages, query syntax ($1/$2 → PostgreSQL, ? → MySQL)
   - Backend: Node.js/Express, Django, Flask, Spring, Laravel - headers, cookies, error traces
   - Frontend: React, Vue, Angular - HTML, JavaScript bundles
   - **Структура запроса (БД hints):**
     * JSON filters: {"where": {...}} → ORM + SQL (Prisma, Sequelize)
     * JSON с $operators: {"$eq": ...} → MongoDB (NoSQL)
     * MongoDB ObjectId (24 hex): 507f1f77bcf86cd799439011 → точно MongoDB
     * Query params: ?filter[status]=active → Rails/Laravel + SQL
     * GraphQL queries → GraphQL + любая БД
   - Если нашел - укажи в "context": "MongoDB (ObjectId + $operators), Express. NoSQL Injection риск!"

2. **ОЦЕНИ НАЗНАЧЕНИЕ ЭНДПОИНТА**:
   - Бизнес-логика (авторизация, CRUD операции, платежи) → should_analyze: true, priority: high
   - API эндпоинты с данными → should_analyze: true
   - Статика, аналитика, health checks → should_analyze: false, priority: low

3. **ПРОВЕРЬ ПОДОЗРИТЕЛЬНОСТЬ (с правильным приоритетом)**:

   **ВЫСОКИЙ ПРИОРИТЕТ (критичные уязвимости):**
   - ✅ Числовой ID в URL (/users/123, /orders/456) → IDOR с высоким риском!
   - ✅ Отсутствие проверки владельца (owner_id в ответе != текущий user)
   - ✅ JSON с $operators (MongoDB) → NoSQL Injection
   - ✅ SQL-like фильтры → SQL Injection
   - ✅ Админские операции доступные обычным пользователям
   
   **СРЕДНИЙ ПРИОРИТЕТ:**
   - ⚠️ MongoDB ObjectId (24 hex) - IDOR возможен, но требует знания формата
   - ⚠️ Отсутствие rate limiting на sensitive операциях
   - ⚠️ Чувствительные данные в ответе
   
   **НИЗКИЙ ПРИОРИТЕТ (малореальные атаки):**
   - ⬇️ UUID в URL (/users/550e8400-...) - практически невозможен brute-force
   - ⬇️ Длинные хеши (64+ символа) - требуют утечки или перебора
   - ⬇️ HTTP вместо HTTPS - не критично для локальных тестов
   
   ⚠️ НЕ выдумывай параметры! Используй ТОЛЬКО то, что есть в запросе!

ПРИМЕРЫ ХОРОШИХ ОТВЕТОВ:

Пример 1 - Админский endpoint:
{
    "url_note": {
        "content": "Управление пользователями (admin)",
        "suspicious": true,
        "vuln_hint": "Возможен Broken Access Control",
        "confidence": 0.9,
        "context": "Обнаружено: PostgreSQL (X-DB header), Express (cookies). Админская операция."
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 2 - IDOR кандидат с числовым ID:
{
    "url_note": {
        "content": "Просмотр заказа по ID",
        "suspicious": true,
        "vuln_hint": "IDOR - числовой ID, нет owner check",
        "confidence": 0.9,
        "context": "Обнаружено: MySQL (error message). Числовой {id} - высокий риск IDOR!"
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 3 - MongoDB с операторами:
{
    "url_note": {
        "content": "Поиск пользователей с фильтрами",
        "suspicious": true,
        "vuln_hint": "NoSQL Injection - MongoDB $operators",
        "confidence": 0.85,
        "context": "MongoDB (ObjectId 507f...). Использует $eq оператор. NoSQL Injection риск!"
    },
    "should_analyze": true,
    "priority": "high"
}

⚠️ ВАЖНО ДЛЯ "context":
- НЕ вставляй JSON примеры в поле context! Только текст!
- НЕ используй кавычки внутри значений
- Описывай данные словами: "MongoDB ObjectId найден", "используются $operators"
- ПЛОХО: "context": "JSON: {\"path\": \"/9j/...\"}"
- ХОРОШО: "context": "MongoDB ObjectId в _id, поле path содержит base64 изображение"

Пример 4 - SQL фильтры:
{
    "url_note": {
        "content": "Список пользователей с фильтрами",
        "suspicious": true,
        "vuln_hint": "SQL Injection в filter параметрах",
        "confidence": 0.75,
        "context": "PostgreSQL (headers). Query params: ?filter[status]=active - ORM style. Проверить экранирование."
    },
    "should_analyze": true,
    "priority": "high"
}

Пример 4 - Статика:
{
    "url_note": {
        "content": "JavaScript bundle",
        "suspicious": false,
        "confidence": 1.0,
        "context": "Статический ресурс"
    },
    "should_analyze": false,
    "priority": "low"
}

**КРИТИЧЕСКИ ВАЖНО:** В поле "context" ОБЯЗАТЕЛЬНО укажи НАЙДЕННЫЕ ТЕХНОЛОГИИ (БД, framework), если обнаружил!

ОТВЕТ СТРОГО В JSON (все текстовые поля на русском):
`,
		req.Method,
		req.NormalizedURL,
		req.ContentType,
		responsePreview,
		techStackInfo,
	)
}

// BuildFullSecurityAnalysisPrompt создает промпт для полного анализа (с заметкой)
func BuildFullSecurityAnalysisPrompt(req *models.SecurityAnalysisRequest, urlNote *models.URLNote) string {
	contextJson, _ := json.MarshalIndent(req.SiteContext, "", "  ")
	extractedDataJson, _ := json.MarshalIndent(req.ExtractedData, "", "  ")

	urlNoteJson, _ := json.MarshalIndent(urlNote, "", "  ")

	return fmt.Sprintf(
		`
ПОЛНЫЙ АНАЛИЗ БЕЗОПАСНОСТИ

### ЗАМЕЧАНИЕ ПО URL:
%s

### КОНТЕКСТ СЕССИИ ДЛЯ ХОСТА %s:
%s

### ТЕКУЩИЙ HTTP-ОБМЕН:
- URL: %s
- Метод: %s
- Заголовки: %v
- Тело запроса: %s
- Тело ответа: %s
- Content-Type: %s

### ИЗВЛЕЧЕННЫЕ ДАННЫЕ:
%s

### ЗАДАЧИ:

1. **АНАЛИЗ С УЧЕТОМ ЗАМЕТКИ:**
   - Используй заметку о назначении URL для фокусировки анализа
   - Проверь именно те уязвимости, которые актуальны для этого типа эндпоинта

2. **БИЗНЕС-ЛОГИКА:**
   - Проверь на IDOR, Broken Access Control, Race Conditions
   - Проанализируй соответствие роли пользователя и прав доступа

3. **ТЕХНИЧЕСКИЕ УЯЗВИМОСТИ:**
   - SQLi, XSS, CSRF, Command Injection
   - Отсутствие заголовков безопасности

4. **ИТОГОВЫЙ ВЕРДИКТ (JSON):**
   - Заполни все поля согласно схеме
   - Учитывай заметку о подозрительной активности
   - ai_comment на русском языке

Ответ строго в JSON формате.
`,
		string(urlNoteJson),
		req.SiteContext.Host,
		string(contextJson),
		req.URL,
		req.Method,
		req.Headers,
		TruncateString(req.RequestBody, 500),
		TruncateString(req.ResponseBody, 1000),
		req.ContentType,
		string(extractedDataJson),
	)
}

// BuildHypothesisPrompt создает промпт для генерации гипотезы
func BuildHypothesisPrompt(req *models.HypothesisRequest) string {
	// Конвертируем map в slice для фильтрации
	allPatterns := make([]*models.URLPattern, 0, len(req.SiteContext.URLPatterns))
	for _, p := range req.SiteContext.URLPatterns {
		allPatterns = append(allPatterns, p)
	}

	// Фильтруем только высококачественные паттерны (confidence >= 0.7)
	highQualityPatterns := filterHighQualityPatterns(allPatterns)

	// Группируем паттерны по типу возможной атаки
	groupedPatterns := groupPatternsByAttackType(highQualityPatterns)

	// Форматируем подозрительные паттерны более структурировано
	suspiciousText := formatSuspiciousPatterns(req.SuspiciousPatterns)

	previousHypothesisText := "Нет предыдущей гипотезы"
	if req.PreviousHypothesis != nil {
		previousHypothesisText = fmt.Sprintf(
			"Предыдущая гипотеза: %s\nВектор атаки: %s\nConfidence: %.2f\nStatus: %s",
			req.PreviousHypothesis.Title,
			req.PreviousHypothesis.AttackVector,
			req.PreviousHypothesis.Confidence,
			req.PreviousHypothesis.Status,
		)
	}

	// Форматируем стек технологий
	techStackDesc := "Стек технологий не определен"
	if req.SiteContext.TechStack != nil {
		techStackDesc = fmt.Sprintf(
			"Frontend: %s, Backend: %s, Database: %s",
			formatTechList(req.SiteContext.TechStack.Frontend),
			formatTechList(req.SiteContext.TechStack.Backend),
			formatTechList(req.SiteContext.TechStack.Database),
		)
	}

	return fmt.Sprintf(
		`
ГЕНЕРАЦИЯ ГЛАВНОЙ ГИПОТЕЗЫ УЯЗВИМОСТИ

Ты - эксперт по пентесту с опытом анализа сложных бизнес-логик. На основе накопленных данных сформируй ГЛАВНУЮ гипотезу уязвимости.

### ОБНАРУЖЕННЫЙ СТЕК ТЕХНОЛОГИЙ:
%s

### ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ (высокая уверенность >= 0.7):
%s

### ИЗВЕСТНЫЕ УЯЗВИМОСТИ ТЕХНОЛОГИЙ:
%v

### СГРУППИРОВАННЫЕ ПАТТЕРНЫ ПО ТИПУ АТАКИ:
%s

### ПРЕДЫДУЩАЯ ГИПОТЕЗА:
%s

### КРИТИЧЕСКИ ВАЖНО - ПРИОРИТИЗАЦИЯ:

**1. Используй ТОЛЬКО реальные данные:**
- ✅ Берём ТОЛЬКО паттерны из "ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ" с confidence >= 0.7
- ✅ Проверяем, что endpoint реально существует в списке
- ❌ НЕ выдумывай параметры, которых нет в запросах
- ❌ НЕ придумывай URL паттерны "по аналогии"

**2. Правильная оценка риска:**
- 🔴 ВЫСОКИЙ: Числовой ID + отсутствие owner check → IDOR
- 🔴 ВЫСОКИЙ: NoSQL/SQL Injection в фильтрах
- 🟡 СРЕДНИЙ: MongoDB ObjectId IDOR (требует знания формата)
- 🟢 НИЗКИЙ: UUID IDOR (практически невозможен)
- 🟢 НИЗКИЙ: Хеш >32 символов (требует утечки)

**3. Фокус на эксплуатируемых уязвимостях:**
- Если есть /users/123 И /orders/456 → это IDOR кандидат!
- Если есть MongoDB $operators → NoSQL Injection!
- Если только UUID → упомяни, но не делай основной гипотезой

**4. Проверка данных:**
- Есть ли в ответе owner_id/user_id?
- Совпадает ли с текущим пользователем?
- Можно ли подменить ID и получить чужие данные?

### ТВОЯ ЗАДАЧА:
Сформируй НАИБОЛЕЕ ВЕРОЯТНУЮ гипотезу уязвимости, которую можно протестировать.

АНАЛИЗ (рассуждай по шагам):

1. **ФИЛЬТРУЙ низкоприоритетные находки:**
   - ❌ ИГНОРИРУЙ UUID в URL (невозможен brute-force)
   - ❌ ИГНОРИРУЙ длинные хеши >32 символов
   - ❌ ИГНОРИРУЙ несуществующие параметры из других URL
   - ✅ ФОКУС на числовых ID, MongoDB ObjectId, SQL/NoSQL Injection

2. **Определи паттерн атаки из РЕАЛЬНЫХ данных:** 
   - IDOR с числовым ID (GET /users/123 → GET /users/124)
   - IDOR с MongoDB ObjectId (требует знания формата, средний риск)
   - NoSQL Injection (если видишь $operators в запросах)
   - SQL Injection (если SQL БД + фильтры в параметрах)
   - Broken Access Control (admin endpoints без проверки роли)

3. **Проверь эксплуатируемость:**
   - Есть ли owner_id в ответе? Отличается от user_id?
   - Можно ли просто подменить ID и получить доступ?
   - Нужны ли дополнительные знания (формат ObjectId, хеш)?

4. **Учитывай технологии:**
   - PostgreSQL/MySQL → SQLi возможна
   - MongoDB → NoSQL injection
   - Express/Node.js → prototype pollution
   - Django → ORM injection

5. **Найди связи между эндпоинтами:**
   - Есть ли CRUD операции над одним объектом?
   - Видны ли admin и user endpoints для одних данных?
   - Есть ли последовательности (create → view → delete)?

6. **Сравни с предыдущей гипотезой:**
   - Подтверждается или опровергается?
   - Нужно изменить вектор атаки?

7. **СФОРМИРУЙ 2-4 ВЕКТОРА АТАКИ:**
   - Сортируй по убыванию приоритета (самый вероятный первым)
   - Каждый вектор должен быть независимым и эксплуатируемым
   - Укажи разные типы атак (IDOR + SQL Injection, или IDOR на разные ресурсы)

⚠️ ВАЖНО ДЛЯ "attack_sequence":
- Это шаги для ПЕНТЕСТЕРА (как эксплуатировать уязвимость)
- "action" = что делает атакующий (название шага)
- "description" = КАК выполнить атаку (конкретный HTTP запрос)
- "expected" = ЧТО ожидается при успехе атаки VS при наличии защиты

ПРИМЕР ПРАВИЛЬНОГО ОТВЕТА (НЕСКОЛЬКО ВЕКТОРОВ):
{
    "attack_vectors": [
        {
            "id": "idor_orders_001",
            "title": "IDOR в просмотре заказов через числовой ID",
            "description": "Endpoint /api/orders/{id} позволяет получить любой заказ, подменив числовой {id}. Проверка владения отсутствует.",
            "attack_vector": "IDOR (Insecure Direct Object Reference)",
            "target_urls": ["/api/orders/{id}", "/api/orders/{id}/details"],
            "attack_sequence": [
                {"step": 1, "action": "Авторизация как user", "description": "POST /api/login", "expected": "Получить JWT токен"},
                {"step": 2, "action": "Получить свой заказ", "description": "GET /api/orders/100", "expected": "200 OK, свои данные"},
                {"step": 3, "action": "IDOR атака", "description": "GET /api/orders/101", "expected": "Если уязвимость: 200 OK + чужие данные. Защита: 403"}
            ],
            "required_role": "user",
            "prereqs": ["аутентификация"],
            "confidence": 0.9,
            "impact": "high",
            "effort": "low",
            "status": "active"
        },
        {
            "id": "nosql_injection_001",
            "title": "NoSQL Injection в фильтрах поиска",
            "description": "Endpoint /api/search принимает MongoDB $operators в JSON, что может позволить инъекцию.",
            "attack_vector": "NoSQL Injection",
            "target_urls": ["/api/search", "/api/users/search"],
            "attack_sequence": [
                {"step": 1, "action": "Тестовый запрос", "description": "POST /api/search {\"status\": \"active\"}", "expected": "Список активных"},
                {"step": 2, "action": "Инъекция $ne", "description": "POST /api/search {\"status\": {\"$ne\": null}}", "expected": "Если уязвимость: все записи. Защита: ошибка"}
            ],
            "required_role": "user",
            "prereqs": ["аутентификация"],
            "confidence": 0.75,
            "impact": "high",
            "effort": "medium",
            "status": "active"
        },
        {
            "id": "idor_profiles_002",
            "title": "IDOR в профилях через MongoDB ObjectId",
            "description": "Endpoint /api/profile/{hash} использует MongoDB ObjectId. Требует знания формата.",
            "attack_vector": "IDOR (MongoDB ObjectId)",
            "target_urls": ["/api/profile/{hash}"],
            "attack_sequence": [
                {"step": 1, "action": "Получить свой ObjectId", "description": "GET /api/profile/me", "expected": "ObjectId в ответе"},
                {"step": 2, "action": "Генерация соседних ID", "description": "Инкремент последних байт ObjectId", "expected": "Список кандидатов"},
                {"step": 3, "action": "IDOR атака", "description": "GET /api/profile/{другой_objectid}", "expected": "Если уязвимость: чужой профиль"}
            ],
            "required_role": "user",
            "prereqs": ["знание формата ObjectId", "timestamp примерного создания"],
            "confidence": 0.6,
            "impact": "medium",
            "effort": "high",
            "status": "active"
        }
    ],
    "reasoning": "Найдены 3 независимых вектора атаки: 1) IDOR с числовым ID (высокий приоритет, легко эксплуатировать), 2) NoSQL Injection через $operators (высокий impact), 3) IDOR через ObjectId (средний приоритет, требует знаний). Приоритизировал по простоте эксплуатации."
}

ОТВЕТ СТРОГО В JSON (все текстовые поля на русском):
`,
		techStackDesc,
		suspiciousText,
		req.TechVulnerabilities,
		groupedPatterns,
		previousHypothesisText,
	)
}

// filterHighQualityPatterns фильтрует паттерны с высоким confidence
func filterHighQualityPatterns(patterns []*models.URLPattern) []*models.URLPattern {
	filtered := make([]*models.URLPattern, 0)
	for _, pattern := range patterns {
		if pattern.LastNote != nil && pattern.LastNote.Confidence >= 0.7 {
			filtered = append(filtered, pattern)
		}
	}
	return filtered
}

// groupPatternsByAttackType группирует паттерны по возможному типу атаки
func groupPatternsByAttackType(patterns []*models.URLPattern) string {
	idorPatterns := make([]string, 0)
	sqlPatterns := make([]string, 0)
	authPatterns := make([]string, 0)
	otherPatterns := make([]string, 0)

	for _, p := range patterns {
		patternStr := fmt.Sprintf("- %s (confidence: %.2f)", p.Pattern, p.LastNote.Confidence)
		if p.LastNote != nil {
			patternStr += fmt.Sprintf(" - %s", p.LastNote.Content)
		}

		// Классифицируем по вероятному типу атаки
		if strings.Contains(p.Pattern, "{") || strings.Contains(strings.ToLower(p.Pattern), "id") {
			idorPatterns = append(idorPatterns, patternStr)
		} else if strings.Contains(strings.ToLower(p.Pattern), "admin") || strings.Contains(strings.ToLower(p.Pattern), "auth") {
			authPatterns = append(authPatterns, patternStr)
		} else if p.LastNote != nil && (strings.Contains(strings.ToLower(p.LastNote.VulnHint), "sql") || strings.Contains(strings.ToLower(p.LastNote.VulnHint), "injection")) {
			sqlPatterns = append(sqlPatterns, patternStr)
		} else {
			otherPatterns = append(otherPatterns, patternStr)
		}
	}

	var result strings.Builder

	if len(idorPatterns) > 0 {
		result.WriteString("\n**Возможный IDOR:**\n")
		result.WriteString(strings.Join(idorPatterns, "\n"))
	}

	if len(authPatterns) > 0 {
		result.WriteString("\n\n**Возможный Broken Access Control:**\n")
		result.WriteString(strings.Join(authPatterns, "\n"))
	}

	if len(sqlPatterns) > 0 {
		result.WriteString("\n\n**Возможный SQL/NoSQL Injection:**\n")
		result.WriteString(strings.Join(sqlPatterns, "\n"))
	}

	if len(otherPatterns) > 0 {
		result.WriteString("\n\n**Другие подозрительные паттерны:**\n")
		result.WriteString(strings.Join(otherPatterns, "\n"))
	}

	if result.Len() == 0 {
		return "Нет сгруппированных паттернов"
	}

	return result.String()
}

// formatSuspiciousPatterns форматирует подозрительные паттерны для промпта
func formatSuspiciousPatterns(patterns []*models.URLPattern) string {
	if len(patterns) == 0 {
		return "Не найдено подозрительных паттернов с высокой уверенностью"
	}

	var result strings.Builder
	for i, p := range patterns {
		if p.LastNote == nil || p.LastNote.Confidence < 0.7 {
			continue // Пропускаем низкокачественные
		}

		result.WriteString(fmt.Sprintf("\n%d. URL Pattern: %s\n", i+1, p.Pattern))
		result.WriteString(fmt.Sprintf("   Заметка: %s\n", p.LastNote.Content))
		result.WriteString(fmt.Sprintf("   Подозрительность: %v (confidence: %.2f)\n", p.LastNote.Suspicious, p.LastNote.Confidence))
		if p.LastNote.VulnHint != "" {
			result.WriteString(fmt.Sprintf("   Подсказка: %s\n", p.LastNote.VulnHint))
		}
		result.WriteString(fmt.Sprintf("   Контекст: %s\n", p.LastNote.Context))
	}

	if result.Len() == 0 {
		return "Не найдено подозрительных паттернов с confidence >= 0.7"
	}

	return result.String()
}

// Вспомогательные функции

func formatTechList(techs []models.Technology) string {
	if len(techs) == 0 {
		return "не определено"
	}

	names := make([]string, 0, len(techs))
	for _, tech := range techs {
		if tech.Version != "" {
			names = append(names, fmt.Sprintf("%s v%s", tech.Name, tech.Version))
		} else {
			names = append(names, tech.Name)
		}
	}

	return strings.Join(names, ", ")
}

func formatTechStackCompact(techStack *models.TechStack) string {
	if techStack == nil {
		return "не определен"
	}

	var technologies []string

	if len(techStack.Frontend) > 0 {
		for _, tech := range techStack.Frontend {
			technologies = append(technologies, tech.Name)
		}
	}
	if len(techStack.Backend) > 0 {
		for _, tech := range techStack.Backend {
			technologies = append(technologies, tech.Name)
		}
	}
	if len(techStack.Database) > 0 {
		for _, tech := range techStack.Database {
			technologies = append(technologies, tech.Name)
		}
	}

	if len(technologies) == 0 {
		return "не определен"
	}

	// Возвращаем первые 5 технологий
	if len(technologies) > 5 {
		technologies = technologies[:5]
	}

	return strings.Join(technologies, ", ")
}
