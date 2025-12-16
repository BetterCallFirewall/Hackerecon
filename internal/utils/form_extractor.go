package utils

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/PuerkitoBio/goquery"
)

type FormExtractor struct {
	csrfPatterns []*regexp.Regexp
}

func NewFormExtractor() *FormExtractor {
	return &FormExtractor{
		csrfPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(csrf[_-]?token|_token|authenticity_token)`),
			regexp.MustCompile(`(?i)(x-csrf-token|csrf)`),
		},
	}
}

// ExtractForms finds and extracts security-relevant forms from HTML
func (fe *FormExtractor) ExtractForms(htmlContent string) []*models.HTMLForm {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}

	var forms []*models.HTMLForm

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET"
		}

		// Skip forms without action
		if action == "" || action == "#" {
			return
		}

		form := &models.HTMLForm{
			FormID: fe.generateFormID(action, method),
			Action: action,
			Method: strings.ToUpper(method),
			Fields: []models.FormField{},
		}

		// Extract fields
		s.Find("input, select, textarea").Each(func(j int, field *goquery.Selection) {
			fieldType, _ := field.Attr("type")
			if fieldType == "" {
				fieldType = "text"
			}

			name, _ := field.Attr("name")
			if name == "" {
				return
			}

			// Check for CSRF token
			if !form.HasCSRFToken {
				for _, pattern := range fe.csrfPatterns {
					if pattern.MatchString(name) {
						form.HasCSRFToken = true
						form.CSRFTokenName = name
					}
				}
			}

			// Check if sensitive field
			sensitive := fe.isSensitiveField(fieldType, name)

			form.Fields = append(form.Fields, models.FormField{
				Name:      name,
				Type:      fieldType,
				Sensitive: sensitive,
			})
		})

		// Only keep forms with CSRF tokens or sensitive fields
		if form.HasCSRFToken || fe.hasSensitiveFields(form.Fields) {
			forms = append(forms, form)
		}
	})

	return forms
}

func (fe *FormExtractor) generateFormID(action, method string) string {
	hash := sha256.Sum256([]byte(action + "|" + method))
	return fmt.Sprintf("%x", hash)[:16]
}

func (fe *FormExtractor) isSensitiveField(fieldType, name string) bool {
	name = strings.ToLower(name)
	fieldType = strings.ToLower(fieldType)

	// Check field type
	if fieldType == "password" || fieldType == "email" || fieldType == "tel" {
		return true
	}

	// Check field name
	sensitivePatterns := []string{"password", "pass", "secret", "token", "key", "ssn", "credit"}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	return false
}

func (fe *FormExtractor) hasSensitiveFields(fields []models.FormField) bool {
	for _, field := range fields {
		if field.Sensitive {
			return true
		}
	}
	return false
}
