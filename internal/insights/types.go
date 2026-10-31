// Package insights defines the deliberately small evidence boundary for SIEM AI.
// It contains no credentials, arbitrary questions, raw events or config bodies.
package insights

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var ErrSearch = errors.New("siem_search_unavailable")
var ErrEvidence = errors.New("invalid_siem_evidence")
var ErrProvider = errors.New("siem_ai_unavailable")

type Rule struct{ ID, Topic, Severity, Description string }

var Rules = []Rule{
	{"collection_failures", "connection_health", "warning", "Three or more consecutive failed/degraded collections in the sampled window."},
	{"mapping_rejections", "connection_health", "warning", "Collected records failed common-schema mapping in the sampled window."},
	{"high_severity_events", "security_findings", "high", "The source reported high/critical events; this is source severity, not an independently confirmed incident."},
	{"authentication_failures", "security_findings", "warning", "At least five authentication-failure events in 24 hours; no user/IP correlation or confirmed attack is implied."},
	{"kev_catalog_entries", "security_findings", "info", "Recently dated KEV catalog entries; presence in a feed does not establish deployment exposure."},
}

func RuleByID(id string) (Rule, bool) {
	for _, rule := range Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
func Topic(s string) bool  { return s == "connection_health" || s == "security_findings" }
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

type Finding struct {
	ID         string    `json:"id"`
	Connector  string    `json:"connector"`
	Generation string    `json:"generation"`
	Rule       string    `json:"rule"`
	Severity   string    `json:"severity"`
	Category   string    `json:"category"`
	Count      int64     `json:"count"`
	ObservedAt time.Time `json:"observed_at"`
}
type Snapshot struct {
	Connector       string    `json:"connector"`
	Generation      string    `json:"generation"`
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
	RunSampleCapped bool      `json:"run_sample_capped"`
	Findings        []Finding `json:"findings"`
}

// Fact is the ONLY customer-derived type permitted across the model boundary.
// Evidence IDs are request-local ordinal labels, not customer/database IDs.
type Fact struct {
	ID       string `json:"id"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Count    int64  `json:"count"`
}
type Evidence struct {
	Topic           string `json:"topic"`
	WindowHours     int    `json:"window_hours"`
	RunSampleCapped bool   `json:"run_sample_capped"`
	Facts           []Fact `json:"facts"`
}

func Category(s string) bool {
	switch s {
	case "collection_failed", "auth_failed", "credential_missing", "credential_incomplete", "credential_binding_mismatch", "destination_denied", "response_too_large", "collection_limit", "timeout", "rate_limited", "vendor_http_failed", "storage_failed", "incremental_filter_not_respected", "mapping_rejections", "source_high_severity", "authentication_failure", "public_kev_catalog":
		return true
	}
	return false
}
func (e Evidence) Validate() error {
	if !Topic(e.Topic) || e.WindowHours != 24 || len(e.Facts) == 0 || len(e.Facts) > 20 {
		return ErrEvidence
	}
	for i, f := range e.Facts {
		r, ok := RuleByID(f.Rule)
		if !ok || r.Topic != e.Topic || f.ID != fmt.Sprintf("e%d", i+1) || f.Severity != r.Severity || !Category(f.Category) || f.Count < 1 || f.Count > 1_000_000_000 {
			return ErrEvidence
		}
	}
	return nil
}

type Usage struct {
	Known  bool  `json:"known"`
	Input  int64 `json:"input_tokens"`
	Output int64 `json:"output_tokens"`
	Total  int64 `json:"total_tokens"`
}

func (u Usage) Valid() bool {
	return u.Known && u.Input >= 0 && u.Output >= 0 && u.Total == u.Input+u.Output && u.Total > 0 && u.Total <= 1_000_000
}

type Answer struct {
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids"`
	NextChecks  []string `json:"next_checks"`
}

var Checks = map[string]string{
	"credential_permissions": "Check credential expiry and permissions through your vendor's controls.",
	"mapping":                "Review the mapping against the vendor's documented response shape.",
	"vendor_status":          "Review vendor availability and collection run history.",
	"event_review":           "Review the original events locally before deciding whether an incident occurred.",
	"authentication_review":  "Investigate authentication events locally, including expected activity and user/IP correlation.",
	"kev_applicability":      "Verify affected product versions and deployment applicability before remediation.",
	"rate_limits":            "Review the vendor's rate limit and Retry-After behavior.",
	"network_policy":         "Review the approved host, TLS certificate and destination policy.",
}

func (a Answer) Validate(e Evidence) error {
	if len(a.Summary) < 1 || len(a.Summary) > 2000 || len(a.EvidenceIDs) < 1 || len(a.EvidenceIDs) > len(e.Facts) || len(a.NextChecks) > 5 {
		return ErrEvidence
	}
	allowed := map[string]bool{}
	for _, f := range e.Facts {
		allowed[f.ID] = true
	}
	for _, id := range a.EvidenceIDs {
		if !allowed[id] {
			return ErrEvidence
		}
		delete(allowed, id)
	}
	seen := map[string]bool{}
	for _, check := range a.NextChecks {
		if Checks[check] == "" || seen[check] {
			return ErrEvidence
		}
		seen[check] = true
	}
	// Explanations never supply executable commands, hyperlinks or markup.
	if regexp.MustCompile(`(?i)https?://|<|>|\x00`).MatchString(a.Summary) {
		return ErrEvidence
	}
	return nil
}
