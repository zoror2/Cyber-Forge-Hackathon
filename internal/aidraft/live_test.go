package aidraft

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Explicit opt-in only. Ordinary unit/race tests never spend tokens or use a key.
func TestLiveGroqPublicDrafts(t *testing.T) {
	if os.Getenv("CB_TEST_LIVE_GROQ") != "1" {
		t.Skip("explicit live Groq check not enabled")
	}
	g, err := NewGroq(os.Getenv("GROQ_API_KEY"), os.Getenv("CB_AI_MODEL"))
	if err != nil {
		t.Fatal("private Groq key required")
	}
	for _, id := range []string{"github_members", "cisa_kev"} {
		t.Run(id, func(t *testing.T) {
			source := sources(t)[id]
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			raw, err := g.Generate(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			c, err := Assemble(raw, source, "demo_"+id, "Public source demo")
			if err != nil {
				t.Fatal("live draft did not pass validation")
			}
			// Safe local evidence for human review: source is public and auth is a name.
			if os.Getenv("CB_AI_EVIDENCE_DIR") != "" {
				b, _ := json.MarshalIndent(c, "", "  ")
				if err = os.WriteFile(os.Getenv("CB_AI_EVIDENCE_DIR")+"/"+id+".json", b, 0600); err != nil {
					t.Fatal("could not save evidence")
				}
			}
			t.Logf("PASS provider=%s model=%s source=%s prompt=%s; valid config, all public fixture rows mapped, schedule disabled", g.Name(), g.Model(), id, PromptVersion)
		})
	}
}
