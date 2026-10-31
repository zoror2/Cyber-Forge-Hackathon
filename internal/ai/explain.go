package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"time"

	"configbridge/internal/insights"
	"configbridge/pkg/config"
)

// ExplainPromptVersion is recorded in ai_audit for SIEM explanations.
const ExplainPromptVersion = "siem-summary-v1"

// Explain turns validated aggregate SIEM facts (rule, category, count) into a
// short explanation. It never sees raw events, names, IPs or config, and its
// answer must cite only the supplied evidence IDs (insights.Answer.Validate).
func (c *Client) Explain(ctx context.Context, e insights.Evidence) (insights.Answer, insights.Usage, error) {
	if !c.configured() {
		return insights.Answer{}, insights.Usage{}, ErrNotConfigured
	}
	if e.Validate() != nil {
		return insights.Answer{}, insights.Usage{}, insights.ErrEvidence
	}
	rules, _ := json.Marshal(insights.Rules)
	checks, _ := json.Marshal(insights.Checks)
	user, _ := json.Marshal(e)
	msgs := []message{{Role: "system", Content: `Explain only the supplied security/collection findings. The evidence is aggregate metadata, not proof of an attack or affected deployment. Do not invent facts, people, products, IDs, causes or dates. Describe uncertainty. Never suggest disabling security, revealing secrets or automatically changing config. Return summary (plain text <=2000 characters), evidence_ids (one or more supplied eN IDs), next_checks (up to 5 unique keys from the allowed checks). No HTML, links or commands. Rules: ` + string(rules) + `. Allowed checks: ` + string(checks)},
		{Role: "user", Content: string(user)}}
	var used meter
	var raw string
	err := c.retry(ctx, func() (time.Duration, error) {
		t, u, wait, e := c.callOnce(ctx, msgs, explainSchema())
		used.add(u)
		raw = t
		return wait, e
	})
	if err != nil {
		return insights.Answer{}, used.total(), err
	}
	var a insights.Answer
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if config.CheckJSON([]byte(raw)) != nil || d.Decode(&a) != nil || a.Validate(e) != nil {
		return insights.Answer{}, used.total(), insights.ErrEvidence
	}
	return a, used.total(), nil
}

func explainSchema() schema {
	keys := []string{}
	for k := range insights.Checks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	str := map[string]any{"type": "string"}
	return schema{"siem_explanation", "Submit the explanation of the supplied findings.", map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"summary", "evidence_ids", "next_checks"},
		"properties": map[string]any{
			"summary":      str,
			"evidence_ids": map[string]any{"type": "array", "items": str},
			"next_checks":  map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": keys}},
		}}}
}
