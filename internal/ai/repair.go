package ai

import (
	"bytes"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"time"
)

// The model chooses from locally tested conversions. No paths, URLs, raw
// records, customer identifiers, credentials or config bodies leave the backend.
type RepairOption struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Accepted  int    `json:"accepted"`
	Rejected  int    `json:"rejected"`
}

func (c *Client) ChooseRepair(ctx context.Context, options []RepairOption) (string, insights.Usage, error) {
	if !c.configured() {
		return "", insights.Usage{}, ErrNotConfigured
	}
	if len(options) == 0 || len(options) > 20 {
		return "", insights.Usage{}, insights.ErrEvidence
	}
	ids := []string{"no_safe_fix"}
	for _, o := range options {
		ids = append(ids, o.ID)
	}
	body, _ := json.Marshal(options)
	msgs := []message{{Role: "system", Content: "Select one of the supplied locally tested type-conversion repairs, or no_safe_fix. Choose only a repair with zero rejected and positive accepted records. These counts describe a bounded sample, not a guarantee for all future data. Never invent mappings or settings. Return only the selected id."}, {Role: "user", Content: string(body)}}
	shape := schema{"config_repair", "Select a locally tested conversion.", map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string", "enum": ids}}}}
	var used meter
	var raw string
	err := c.retry(ctx, func() (time.Duration, error) {
		var u insights.Usage
		var wait time.Duration
		var e error
		raw, u, wait, e = c.callOnce(ctx, msgs, shape)
		used.add(u)
		return wait, e
	})
	if err != nil {
		return "", used.total(), err
	}
	var out struct {
		ID string `json:"id"`
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if config.CheckJSON([]byte(raw)) != nil || d.Decode(&out) != nil {
		return "", used.total(), insights.ErrEvidence
	}
	for _, id := range ids {
		if out.ID == id {
			return id, used.total(), nil
		}
	}
	return "", used.total(), insights.ErrEvidence
}
