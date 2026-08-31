package audit

import (
	"regexp"
)

var (
	bearerRegex    = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9_\-\.]{16,}`)
	openaiKeyRegex = regexp.MustCompile(`sk-[a-zA-Z0-9_\-]{20,}`)
	anthropicKey   = regexp.MustCompile(`sk-ant-[a-zA-Z0-9_\-]{20,}`)
	genericKey     = regexp.MustCompile(`(?i)(api[_-]?key|secret|password)["']?\s*[:=]\s*["']?([^"'\s]{8,})["']?`)
)

// RedactSensitiveText replaces discovered API keys and credentials with redaction markers.
func RedactSensitiveText(input string) string {
	if input == "" {
		return ""
	}

	result := bearerRegex.ReplaceAllString(input, "Bearer [REDACTED]")
	result = openaiKeyRegex.ReplaceAllString(result, "[REDACTED_OPENAI_KEY]")
	result = anthropicKey.ReplaceAllString(result, "[REDACTED_ANTHROPIC_KEY]")
	result = genericKey.ReplaceAllString(result, "$1: [REDACTED]")

	return result
}
