//go:build live

package ai

import (
	"configbridge/internal/insights"
	"context"
	"os"
	"testing"
	"time"
)

// Explicit, small live smoke: public/synthetic aggregates only; never reads DB.
func TestLiveDemoPaths(t *testing.T) {
	if os.Getenv("CB_LIVE_DEMO") != "1" {
		t.Skip("explicit live opt-in required")
	}
	c := New(os.Getenv("GROQ_API_KEY"), os.Getenv("CB_AI_MODEL"))
	c.MaxWait = time.Second
	if !c.configured() || c.Model == "" {
		t.Fatal("provider settings missing")
	}
	t.Run("repair", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		start := time.Now()
		id, u, e := c.ChooseRepair(ctx, []RepairOption{{ID: "r1", Operation: "string", Accepted: 10, Rejected: 0}})
		if e != nil {
			t.Fatal(e)
		}
		if id != "r1" {
			t.Fatal("provider declined verified fixture", id)
		}
		t.Logf("PASS repair model=%s elapsed=%s known=%v tokens=%d", c.Model, time.Since(start), u.Known, u.Total)
	})
	t.Run("question", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		start := time.Now()
		evidence := insights.Evidence{Topic: "security_findings", Question: "What does an exact KEV match mean, and what should I verify next?", WindowHours: 24, Facts: []insights.Fact{{ID: "e1", Rule: "kev_exact_matches", Severity: "high", Category: "exact_cve_match", Count: 2}}}
		answer, u, e := c.Explain(ctx, evidence)
		if e != nil {
			t.Fatal(e)
		}
		if answer.Validate(evidence) != nil {
			t.Fatal("invalid answer")
		}
		t.Logf("PASS explanation model=%s elapsed=%s known=%v tokens=%d", c.Model, time.Since(start), u.Known, u.Total)
	})
}
