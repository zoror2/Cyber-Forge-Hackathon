package ai

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
)

// CB_LIVE_SPECS=1 go test -run TestLiveSpecRegistry -v ./internal/ai
// Downloads every reviewed spec through the production reader and parser.
// LIVE_SPEC_URLS="name=url;..." checks candidates instead of the registry.
func TestLiveSpecRegistry(t *testing.T) {
	if os.Getenv("CB_LIVE_SPECS") != "1" {
		t.Skip("set CB_LIVE_SPECS=1")
	}
	entries := specRegistry
	if raw := os.Getenv("LIVE_SPEC_URLS"); raw != "" {
		entries = map[string]string{}
		for _, kv := range strings.Split(raw, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
				entries[k] = v
			}
		}
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	c := &Client{}
	for _, k := range keys {
		sp, e := c.loadSpec(context.Background(), []string{entries[k]})
		if e != nil {
			t.Errorf("BROKEN %s %s: %v", k, entries[k], e)
			continue
		}
		t.Logf("OK %s %s servers=%v list_ops=%d", k, sp.version, sp.servers, len(sp.listOps()))
	}
}
