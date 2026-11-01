package insights

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Defense in depth, not a universal PII detector. UI requires consent and asks
// users not to include private data. Questions are never saved in the ledger.
var secretQuestion = regexp.MustCompile(`(?i)(bearer\s+\S+|github_pat_|gh[pousr]_|gsk_|AIza|-----BEGIN|(?:password|api[_ -]?key|token|secret)\s*[:=]\s*\S+|[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}|https?://)`)

func ValidQuestion(s string) bool {
	if !utf8.ValidString(s) || len(s) > 1000 || secretQuestion.MatchString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return s == "" || strings.TrimSpace(s) != ""
}
