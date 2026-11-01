//go:build live

// Live evaluation of the drafter across many vendors and API styles.
// Costs real model calls, so it only runs with the build tag and a key:
//
//	GROQ_API_KEY=... go test -tags live -run TestLiveEval -v -timeout 60m ./internal/ai/
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"configbridge/pkg/config"
)

// Each case names classes that are a correct "main dataset" for the product.
var evalCases = []struct {
	Product string
	Want    []string
}{
	// identity
	{"Okta", []string{"user_inventory"}},
	{"Microsoft Entra ID", []string{"user_inventory"}},
	{"Google Workspace", []string{"user_inventory"}},
	{"Auth0", []string{"user_inventory"}},
	{"Duo Security", []string{"user_inventory", "authentication"}},
	{"JumpCloud", []string{"user_inventory"}},
	// endpoint / device
	{"CrowdStrike Falcon", []string{"inventory_info", "detection_finding"}},
	{"SentinelOne", []string{"inventory_info", "detection_finding"}},
	{"Jamf Pro", []string{"inventory_info"}},
	{"Microsoft Intune", []string{"inventory_info"}},
	{"Tanium", []string{"inventory_info"}},
	// vulnerability / threat intel
	{"AbuseIPDB", []string{"vulnerability_finding", "detection_finding"}},
	{"Tenable.io", []string{"vulnerability_finding"}},
	{"Qualys VMDR", []string{"vulnerability_finding"}},
	{"Snyk", []string{"vulnerability_finding"}},
	{"VirusTotal", []string{"vulnerability_finding", "detection_finding"}},
	{"NVD", []string{"vulnerability_finding"}},
	// alerts / SaaS / dev
	{"PagerDuty", []string{"detection_finding"}},
	{"Microsoft Defender for Endpoint", []string{"detection_finding", "inventory_info"}},
	{"Wiz", []string{"vulnerability_finding", "detection_finding"}},
	{"Jira", []string{"detection_finding", "vulnerability_finding"}},
	{"Slack", []string{"user_inventory"}},
	{"GitHub", []string{"user_inventory", "vulnerability_finding", "detection_finding"}},
	{"Cloudflare", []string{"detection_finding", "inventory_info"}},
}

func TestLiveEval(t *testing.T) {
	var c *Client
	switch {
	case os.Getenv("CB_AI_PROVIDER") == "gemini" && os.Getenv("GEMINI_API_KEY") != "":
		c = NewGemini(os.Getenv("GEMINI_API_KEY"), os.Getenv("CB_AI_MODEL"))
		c.Resolve = LookupDNS
	case os.Getenv("GROQ_API_KEY") != "":
		c = New(os.Getenv("GROQ_API_KEY"), os.Getenv("CB_AI_MODEL"))
	default:
		t.Skip("set CB_AI_PROVIDER=gemini + GEMINI_API_KEY, or GROQ_API_KEY")
	}
	only := os.Getenv("EVAL_ONLY")
	pass, total := 0, 0
	rows := []string{}
	for _, tc := range evalCases {
		if only != "" && !strings.Contains(strings.ToLower(only), strings.ToLower(tc.Product)) {
			continue
		}
		total++
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		start := time.Now()
		d, err := c.Draft(ctx, Request{Product: tc.Product, Data: "auto"}, nil)
		cancel()
		var bad *InvalidDraft
		switch {
		case errors.As(err, &bad):
			rows = append(rows, fmt.Sprintf("FAIL %-32s invalid after repairs: %v", tc.Product, bad.Issues))
			continue
		case err != nil:
			rows = append(rows, fmt.Sprintf("ERR  %-32s %v", tc.Product, err))
			continue
		}
		var cfg config.Config
		json.Unmarshal(d.Config, &cfg)
		classOK := false
		for _, w := range tc.Want {
			classOK = classOK || d.Data == w
		}
		minimal := len(d.Needed) <= 2
		vendor := cfg.Vendor != ""
		ok := classOK && minimal && vendor
		if ok {
			pass++
		}
		mark := "PASS"
		if !ok {
			mark = "WEAK"
		}
		rows = append(rows, fmt.Sprintf("%s %-32s class=%-22s auth=%-26s page=%-6s host=%-34s vendor=%-14q needed=%d also=%v rounds=%d %s",
			mark, tc.Product, d.Data, cfg.Auth.Type, cfg.Pagination.Type, hostOf(cfg.Request.URL), cfg.Vendor, len(d.Needed), d.AlsoAvailable, d.Rounds, time.Since(start).Round(time.Second)))
	}
	for _, r := range rows {
		t.Log(r)
	}
	t.Logf("%d/%d strong (valid config, sensible class, <=2 needed items, vendor set)", pass, total)
}
func hostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		return u[:i]
	}
	return u
}
