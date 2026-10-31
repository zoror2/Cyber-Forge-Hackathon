package tests

import (
	"configbridge/internal/aidraft"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"context"
	"encoding/json"
	"testing"
)

type meteredDraftProvider struct{ draftProvider }

func (p *meteredDraftProvider) GenerateMetered(ctx context.Context, s aidraft.Source) ([]byte, insights.Usage, error) {
	raw, e := p.Generate(ctx, s)
	return raw, insights.Usage{Known: true, Input: 11, Output: 22, Total: 33}, e
}
func TestDraftUsageCountsValidatedAndRejectedOutputs(t *testing.T) {
	e := setup(t)
	p := &meteredDraftProvider{draftProvider: draftProvider{output: userDraftPlan}}
	draftAPI(t, e, p, 3)
	body := []byte(`{"source_id":"github_members","connector_id":"metered_draft","external_ai_consent":true}`)
	e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 200)
	p.output = `{"mapping":{},"pagination":{"type":"none"}}`
	e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 422)
	var usage store.AIConsumption
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage); err != nil || usage.ReportedTokens != 66 || usage.Requests != 2 || usage.UnreportedReserved != 0 {
		t.Fatal("rejected output usage was lost", usage, err)
	}
}
