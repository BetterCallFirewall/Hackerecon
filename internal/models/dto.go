package models

type ReportDTO struct {
	Report          VulnerabilityReport `json:"report"`
	RequestResponse RequestResponseInfo `json:"request_response"`
}

type RequestResponseInfo struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	StatusCode  int               `json:"status_code"`
	ReqHeaders  map[string]string `json:"request_headers"`
	RespHeaders map[string]string `json:"response_headers"`
	ReqBody     string            `json:"request_body,omitempty"`
	RespBody    string            `json:"response_body,omitempty"`
}

// HypothesisDTO используется для отправки гипотезы через API
type HypothesisDTO struct {
	Type string          `json:"type"`
	Data *HypothesisData `json:"data"`
}

// HypothesisData содержит данные гипотезы
type HypothesisData struct {
	// Новый формат: список векторов атаки
	AttackVectors  []*SecurityHypothesis `json:"attack_vectors"`
	MainHypothesis *SecurityHypothesis   `json:"main_hypothesis,omitempty"` // Первый вектор (наиболее вероятный)
	TechStack      *TechStack            `json:"tech_stack,omitempty"`

	// Старый формат (обратная совместимость)
	Hypothesis *SecurityHypothesis `json:"hypothesis,omitempty"`
}
