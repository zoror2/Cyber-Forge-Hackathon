package incremental

import (
	"configbridge/pkg/config"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWindowBoundariesOverlapAndClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start.Add(10*time.Minute + 900*time.Millisecond)
	hash := strings.Repeat("a", 64)
	c := config.Config{Incremental: &config.Incremental{Type: "time_window", StartTime: start.Format(time.RFC3339), SinceParam: "modified_since", UntilParam: "modified_before", UpdatedAtPath: "updated", SafetyLagSeconds: 5, OverlapSeconds: 30}}
	w, err := Begin(c, hash, nil, now)
	if err != nil || !w.Since.Equal(start) || !w.Until.Equal(start.Add(595*time.Second)) {
		t.Fatal(w, err)
	}
	cp := &Checkpoint{Version: 1, ConfigHash: hash, Through: w.Until}
	next, err := Begin(c, hash, cp, now.Add(time.Minute))
	if err != nil || !next.Since.Equal(cp.Through.Add(-30*time.Second)) {
		t.Fatal(next, err)
	}
	// Backwards clocks cannot rewind the saved boundary.
	back, err := Begin(c, hash, cp, start.Add(time.Minute))
	if err != nil || !back.Until.Equal(cp.Through) {
		t.Fatal(back, err)
	}
	changed, err := Begin(c, "new-hash", cp, now)
	if err != nil || !changed.Reset || !changed.Since.Equal(start) {
		t.Fatal(changed, err)
	}
	cp.Through = start.Add(10 * time.Second)
	clamped, err := Begin(c, hash, cp, now)
	if err != nil || !clamped.Since.Equal(start) {
		t.Fatal(clamped, err)
	}
	if _, err = Begin(c, hash, nil, start.Add(-time.Minute)); !errors.Is(err, ErrNotReady) {
		t.Fatal("future initial boundary accepted", err)
	}
	if _, err = Begin(c, hash, &Checkpoint{Version: 99, ConfigHash: hash, Through: now}, now); !errors.Is(err, ErrState) {
		t.Fatal("corrupt state accepted")
	}
	c.Request.Params = map[string]string{"other": "value"}
	connector := c.Connector("tenant-a")
	resolved := Apply(connector, c.Incremental, w)
	if len(connector.Request.Params) != 1 || resolved.Request.Params["modified_since"] != start.Format(time.RFC3339) {
		t.Fatal("query construction mutated saved config")
	}
	for _, row := range []map[string]any{{"updated": start.Format(time.RFC3339Nano)}, {"updated": w.Until.Add(-time.Nanosecond).Format(time.RFC3339Nano)}, {"updated": start.In(time.FixedZone("offset", 19800)).Format(time.RFC3339Nano)}} {
		if bad, e := CheckRow(row, c.Incremental, w, 0); bad != nil || e != nil {
			t.Fatal("valid timestamp refused", bad, e)
		}
	}
	for _, at := range []time.Time{start.Add(-time.Nanosecond), w.Until, w.Until.Add(time.Second)} {
		if _, e := CheckRow(map[string]any{"updated": at.Format(time.RFC3339Nano)}, c.Incremental, w, 0); !errors.Is(e, ErrOutsideWindow) {
			t.Fatal("out-of-window timestamp accepted")
		}
	}
	for _, row := range []map[string]any{{}, {"updated": nil}, {"updated": 123}, {"updated": "PRIVATE-BAD-DATE"}} {
		bad, e := CheckRow(row, c.Incremental, w, 7)
		if e != nil || bad == nil || bad.Index != 7 || strings.Contains(bad.Reason, "PRIVATE") {
			t.Fatal("invalid timestamp not quarantined safely")
		}
	}
}
