package ai

import (
	"configbridge/internal/insights"
	"context"
	"os"
	"testing"
	"time"
)

// Public synthetic aggregates only. This makes real hosted requests when
// explicitly enabled; returned prose needs human semantic review as well.
func TestLiveExplanationEvidence(t *testing.T) {
	if os.Getenv("CB_LIVE_EXPLANATION") != "1" {
		t.Skip("opt-in hosted explanation test")
	}
	c := liveClient(t)
	e := insights.Evidence{Topic: "security_findings", WindowHours: 24, Facts: []insights.Fact{
		{ID: "e1", Rule: "authentication_failures", Severity: "warning", Category: "authentication_failure", Count: 6},
		{ID: "e2", Rule: "high_severity_events", Severity: "high", Category: "source_high_severity", Count: 1},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 160*time.Second)
	defer cancel()
	started := time.Now()
	a, u, err := c.Explain(ctx, e)
	if err != nil {
		t.Fatal("live explanation:", err)
	}
	if a.Validate(e) != nil {
		t.Fatal("invalid live evidence citations/checks")
	}
	t.Logf("provider=%s model=%s duration=%s usage_known=%v tokens=%d citations=%v checks=%v", c.Provider(), c.ModelID(), time.Since(started).Round(time.Millisecond), u.Known, u.Total, a.EvidenceIDs, a.NextChecks)
	t.Log("synthetic-evidence answer for review:", a.Summary)
}
