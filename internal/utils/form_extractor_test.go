package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFormExtractor_ExtractForms_LoginForm(t *testing.T) {
	html := `
    <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="hidden" name="csrf_token" value="abc123">
        </form>
    </body></html>`

	extractor := NewFormExtractor()
	forms := extractor.ExtractForms(html)

	assert.Len(t, forms, 1)
	assert.Equal(t, "/login", forms[0].Action)
	assert.Equal(t, "POST", forms[0].Method)
	assert.True(t, forms[0].HasCSRFToken)
	assert.Equal(t, "csrf_token", forms[0].CSRFTokenName)
	assert.Len(t, forms[0].Fields, 3)
}

func TestFormExtractor_ExtractForms_NoSecurityForms(t *testing.T) {
	html := `
    <html><body>
        <form action="/search" method="GET">
            <input type="text" name="query">
        </form>
    </body></html>`

	extractor := NewFormExtractor()
	forms := extractor.ExtractForms(html)

	// Should return nil because no CSRF/sensitive fields
	assert.Nil(t, forms)
}

func TestFormExtractor_ExtractForms_SensitiveFieldOnly(t *testing.T) {
	html := `
    <html><body>
        <form action="/register" method="POST">
            <input type="text" name="email">
            <input type="password" name="secret_pass">
        </form>
    </body></html>`

	extractor := NewFormExtractor()
	forms := extractor.ExtractForms(html)

	assert.Len(t, forms, 1)
	assert.False(t, forms[0].HasCSRFToken)
	assert.Len(t, forms[0].Fields, 2)

	// Check that sensitive field is detected
	sensitiveFields := 0
	for _, field := range forms[0].Fields {
		if field.Sensitive {
			sensitiveFields++
		}
	}
	assert.Greater(t, sensitiveFields, 0)
}

func TestFormExtractor_IsSensitiveField(t *testing.T) {
	extractor := NewFormExtractor()

	assert.True(t, extractor.isSensitiveField("password", "pass"))
	assert.True(t, extractor.isSensitiveField("text", "secret_key"))
	assert.True(t, extractor.isSensitiveField("email", "email"))
	assert.True(t, extractor.isSensitiveField("tel", "phone"))
	assert.False(t, extractor.isSensitiveField("text", "username"))
	assert.False(t, extractor.isSensitiveField("text", "name"))
}

func TestFormExtractor_GenerateFormID(t *testing.T) {
	extractor := NewFormExtractor()

	id1 := extractor.generateFormID("/login", "POST")
	id2 := extractor.generateFormID("/login", "POST")
	id3 := extractor.generateFormID("/login", "GET")

	// Same action+method should generate same ID
	assert.Equal(t, id1, id2)
	// Different method should generate different ID
	assert.NotEqual(t, id1, id3)
	// Should be 16 characters
	assert.Len(t, id1, 16)
}
