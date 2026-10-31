// Package ai drafts connector configs with an LLM (Groq, OpenAI-compatible API).
//
// Rules this package enforces:
//   - The model only ever writes a CONFIG. Records are always produced by the
//     deterministic mapper, so no data is invented by the model.
//   - The model never sees secret values, only secret names and hosts.
//   - Every draft goes through config.Decode (the same validator as POST /configs);
//     validation issues are fed back for at most MaxRepairs rounds.
//   - The draft is returned unsaved: a human loads it, tests it and makes it live.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"configbridge/internal/engine"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
)

const MaxRepairs = 2

// ErrNotConfigured: no API key, so the feature is off.
var ErrNotConfigured = errors.New("ai_not_configured")

// ErrUpstream: the model provider failed or returned unusable output.
var ErrUpstream = errors.New("ai_provider_failed")

type Client struct {
	Key   string // GROQ_API_KEY; empty disables the drafter
	Model string // CB_AI_MODEL
	URL   string // chat completions endpoint
	HTTP  *http.Client
	// Tenants may use the drafter; empty = every tenant. CB_AI_ENABLED_TENANTS.
	Tenants map[string]bool
	// DailyLimit drafts per tenant per UTC day, counted in Postgres (shared by
	// replicas, survives restarts). Each draft is up to 1+MaxRepairs model calls.
	DailyLimit int
	// TokenLimit: provider-reported tokens per tenant per UTC day, shared by
	// drafts and SIEM explanations (CB_AI_DAILY_TOKEN_LIMIT). Each call
	// reserves store.AIReservation until the provider reports real usage.
	TokenLimit int64
	// MaxWait caps how long one call waits for a provider Retry-After
	// (default 30 s, so a browser request doesn't hang for minutes).
	MaxWait time.Duration
	// Bedrock, when set, is used instead of the Groq HTTP API (CB_AI_PROVIDER=bedrock).
	Bedrock Converser
	// gemini: Gemini API with a Google Search research step (NewGemini).
	gemini bool
	geminiCache
	// Resolve, when set, rejects drafts whose API/token host does not exist
	// and drops doc links that don't resolve (LookupDNS in production).
	Resolve func(ctx context.Context, host string) error
}

// Provider names the backend for ai_audit.
func (c *Client) Provider() string {
	switch {
	case c != nil && c.Bedrock != nil:
		return "bedrock"
	case c != nil && c.gemini:
		return "gemini"
	}
	return "groq"
}

// ModelID is the configured model, recorded with every metered call.
func (c *Client) ModelID() string { return c.Model }

func (c *Client) configured() bool { return c != nil && (c.Key != "" || c.Bedrock != nil) }

func (c *Client) maxWait() time.Duration {
	if c.MaxWait > 0 {
		return c.MaxWait
	}
	return 30 * time.Second
}

// Allowed reports whether a tenant may draft.
func (c *Client) Allowed(tenant string) bool {
	return c.configured() && (len(c.Tenants) == 0 || c.Tenants[tenant])
}

// New reads nothing from the environment itself; cmd/api passes values in.
func New(key, model string) *Client {
	return &Client{Key: key, Model: model, URL: "https://api.groq.com/openai/v1/chat/completions",
		HTTP: &http.Client{Timeout: 90 * time.Second}}
}

type Request struct {
	Product string `json:"product"` // "Okta", "AbuseIPDB", ...
	Data    string `json:"data"`    // OCSF class name, or "auto"/"" to let the model pick the main dataset
	Details string `json:"details"` // optional: pasted API docs, company domain, notes
}

// Secret is what the model may know about a stored credential.
type Secret struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

type Draft struct {
	Config   json.RawMessage `json:"config"`   // validated, unsaved
	Notes    []string        `json:"notes"`    // why each choice was made
	Needed   []string        `json:"needed"`   // the minimum a human must supply: the key (and tenant address if any)
	Optional []string        `json:"optional"` // may be tuned later; never needed to connect
	Sources  []string        `json:"sources"`  // official doc pages the draft is based on (https only)
	// Data is the OCSF class this draft collects (what "auto" resolved to).
	Data string `json:"data"`
	// AlsoAvailable: other datasets this product's API offers, each one more
	// source (OCSF class names, never including Data).
	AlsoAvailable []string `json:"also_available"`
	// TenantHint names what replaces "your-tenant" (e.g. "Okta domain",
	// "GitHub enterprise slug", "firewall address"); "" when nothing does.
	TenantHint string `json:"tenant_hint"`
	Rounds     int    `json:"rounds"` // model calls used
	// Credential: the exact fields and hosts to ask the human for, derived
	// from the config itself (the model's "needed" text is only a hint).
	Credential *engine.CredentialSpec `json:"credential"`
	// Usage: tokens the provider reported for every call this draft made.
	Usage insights.Usage `json:"-"`
}

// Issues returned when the model could not produce a valid config.
type InvalidDraft struct {
	Issues []config.Issue
	Last   json.RawMessage
	Usage  insights.Usage
}

func (e *InvalidDraft) Error() string { return "ai_draft_invalid" }

func (r Request) Check() error {
	if len(strings.TrimSpace(r.Product)) < 2 || len(r.Product) > 100 {
		return errors.New("product: 2-100 characters")
	}
	if _, ok := ocsf.Lookup(r.Data); !ok && !r.Auto() {
		return errors.New("data: auto or an OCSF class")
	}
	if len(r.Details) > 20000 {
		return errors.New("details: at most 20000 characters")
	}
	return nil
}

// Auto: the model chooses the product's main dataset.
func (r Request) Auto() bool { return r.Data == "" || r.Data == "auto" }

// Draft asks the model for a config and repairs it against our validator.
func (c *Client) Draft(ctx context.Context, r Request, secrets []Secret) (*Draft, error) {
	if !c.configured() {
		return nil, ErrNotConfigured
	}
	msgs := []message{{Role: "system", Content: systemPrompt()}, {Role: "user", Content: userPrompt(r, secrets)}}
	var used meter
	if c.gemini {
		facts, e := c.research(ctx, r, &used)
		if e != nil {
			return nil, e
		}
		msgs[1].Content += researchBlock(facts)
	}
	var last json.RawMessage
	var issues []config.Issue
	for round := 1; round <= 1+MaxRepairs; round++ {
		out, e := c.call(ctx, msgs, &used)
		if e != nil {
			return nil, e
		}
		cfg, decoded := []byte(out.ConfigJSON), config.Config{}
		decoded, issues = config.Decode(cfg)
		last = json.RawMessage(cfg)
		if !json.Valid(cfg) {
			last = nil
			issues = []config.Issue{{Field: "config_json", Message: "not valid JSON"}}
		}
		if len(issues) == 0 {
			issues = c.checkHosts(ctx, decoded.Request.URL, decoded.Auth.TokenURL)
		}
		// Auto must work for every customer: a premium-only endpoint is redone
		// (last round accepted, so a product with only premium APIs still drafts)
		if len(issues) == 0 && r.Auto() && out.Plan == "premium" && round <= MaxRepairs {
			issues = []config.Issue{{Field: "plan", Message: "auto needs an endpoint on the standard plan; draft the best standard-plan dataset and put this one in also_available"}}
		}
		if len(issues) == 0 {
			norm, e := json.MarshalIndent(decoded, "", "  ")
			if e != nil {
				return nil, ErrUpstream
			}
			return &Draft{Config: norm, Notes: out.Notes, Needed: out.Needed, Optional: out.Optional, Sources: c.liveLinks(ctx, httpsOnly(out.Sources)),
				Data: decoded.Destination.Class, AlsoAvailable: alsoAvailable(out.Also, decoded.Destination.Class), Rounds: round, TenantHint: strings.TrimSpace(trunc(out.TenantHint, 60)),
				Credential: engine.Credential(decoded.Auth, decoded.Request.URL), Usage: used.total()}, nil
		}
		// feed our validator's verdict back; the model fixes its own config
		b, _ := json.Marshal(issues)
		msgs = append(msgs, message{Role: "assistant", Content: mustJSON(out)},
			message{Role: "user", Content: "The platform validator rejected config_json with these issues:\n" + string(b) +
				"\nReturn the corrected full config in config_json. Keep everything that was valid."})
	}
	return nil, &InvalidDraft{Issues: issues, Last: last, Usage: used.total()}
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type modelOutput struct {
	ConfigJSON string   `json:"config_json"`
	Notes      []string `json:"notes"`
	Needed     []string `json:"needed"`
	Optional   []string `json:"optional"`
	Sources    []string `json:"sources"`
	Also       []string `json:"also_available"`
	TenantHint string   `json:"tenant_hint"`
	Plan       string   `json:"plan"`
}

// alsoAvailable keeps known OCSF classes other than the drafted one, deduped.
func alsoAvailable(in []string, drafted string) []string {
	out, seen := []string{}, map[string]bool{drafted: true}
	for _, c := range in {
		if _, ok := ocsf.Lookup(c); ok && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// httpsOnly keeps plain https URLs (shown as links in the console); anything
// else (javascript:, data:, http:) from the model is dropped.
func httpsOnly(in []string) []string {
	out := []string{}
	for _, s := range in {
		u, e := url.Parse(strings.TrimSpace(s))
		if e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(s) < 300 && len(out) < 5 {
			out = append(out, u.String())
		}
	}
	return out
}

// outputSchema: strict structured output. The config travels as a JSON string
// because its mapping keys are open-ended (strict mode needs closed objects).
var outputSchema = map[string]any{
	"type": "object", "additionalProperties": false,
	"required": []string{"config_json", "notes", "needed", "optional", "sources", "also_available", "tenant_hint", "plan"},
	"properties": map[string]any{
		"config_json": map[string]any{"type": "string", "description": "the complete connector config as a JSON document"},
		"notes":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"needed":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"optional":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"sources":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"plan": map[string]any{"type": "string", "enum": []string{"standard", "premium", "unknown"},
			"description": "premium if the drafted endpoint needs an enterprise/premium tier or add-on license"},
		"tenant_hint": map[string]any{"type": "string", "description": "what the customer types in place of your-tenant, 2-6 words (e.g. Okta domain, GitHub organization name, Microsoft tenant ID or domain, firewall address); empty if no your-tenant"},
		"also_available": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": ocsf.Classes()},
			"description": "other OCSF classes this product's API also offers, excluding the one drafted"},
	},
}

// schema names one strict structured output (a JSON schema; for Bedrock, the
// input schema of the single forced tool).
type schema struct {
	name, desc string
	body       map[string]any
}

var draftSchema = schema{"connector_draft", "Submit the connector config draft and its notes.", outputSchema}

// meter sums provider-reported tokens over a request's calls. One call with
// no usage makes the total unknown: a partial sum would under-report.
type meter struct {
	u       insights.Usage
	missing bool
}

func (m *meter) add(u insights.Usage) {
	if !u.Valid() {
		m.missing = true
		return
	}
	m.u.Input += u.Input
	m.u.Output += u.Output
	m.u.Total += u.Total
}
func (m *meter) total() insights.Usage {
	if m.missing || m.u.Total == 0 {
		return insights.Usage{}
	}
	return insights.Usage{Known: true, Input: m.u.Input, Output: m.u.Output, Total: m.u.Total}
}

// call asks the model for a draft; retryable failures are retried (see retry).
func (c *Client) call(ctx context.Context, msgs []message, used *meter) (*modelOutput, error) {
	var out *modelOutput
	e := c.retry(ctx, func() (time.Duration, error) {
		raw, u, wait, e := c.callOnce(ctx, msgs, draftSchema)
		used.add(u)
		if e != nil {
			return wait, e
		}
		var o modelOutput
		if json.Unmarshal([]byte(raw), &o) != nil {
			return time.Second, fmt.Errorf("%w: output not in schema", ErrUpstream)
		}
		out = &o
		return 0, nil
	})
	return out, e
}

// retry runs f; a retryable failure (rate limit, bad structured output)
// is tried at most 2 more times, waiting what the provider asked (<= maxWait).
func (c *Client) retry(ctx context.Context, f func() (time.Duration, error)) error {
	wait, e := f()
	for try := 0; try < 2 && e != nil && wait > 0 && wait <= c.maxWait(); try++ {
		select {
		case <-ctx.Done():
			return ErrUpstream
		case <-time.After(wait):
		}
		wait, e = f()
	}
	return e
}

// checkHosts: a host that doesn't exist is a made-up endpoint. Hosts with the
// customer placeholder can't be checked until the customer fills them in.
func (c *Client) checkHosts(ctx context.Context, urls ...string) []config.Issue {
	if c.Resolve == nil {
		return nil
	}
	var out []config.Issue
	for i, raw := range urls {
		u, e := url.Parse(raw)
		if e != nil || u.Hostname() == "" || strings.Contains(u.Hostname(), "your-tenant") {
			continue
		}
		if c.Resolve(ctx, u.Hostname()) != nil {
			field := []string{"request.url", "auth.token_url"}[min(i, 1)]
			out = append(out, config.Issue{Field: field, Message: "host " + u.Hostname() + " does not exist (DNS lookup failed): use the vendor's real documented host, or your-tenant if it is customer-specific"})
		}
	}
	return out
}

// liveLinks drops doc links whose host does not resolve.
func (c *Client) liveLinks(ctx context.Context, in []string) []string {
	if c.Resolve == nil {
		return in
	}
	out := []string{}
	for _, s := range in {
		if u, e := url.Parse(s); e == nil && c.Resolve(ctx, u.Hostname()) == nil {
			out = append(out, s)
		}
	}
	return out
}

// callOnce makes one structured-output call and returns the model's JSON text
// plus the tokens the provider reported (Known=false when it reported none).
func (c *Client) callOnce(ctx context.Context, msgs []message, s schema) (string, insights.Usage, time.Duration, error) {
	if c.Bedrock != nil {
		return c.bedrockOnce(ctx, msgs, s)
	}
	if c.gemini {
		return c.geminiOnce(ctx, msgs, s)
	}
	none := insights.Usage{}
	body, _ := json.Marshal(map[string]any{
		"model": c.Model, "messages": msgs, "temperature": 0.2,
		"response_format": map[string]any{"type": "json_schema",
			"json_schema": map[string]any{"name": s.name, "strict": true, "schema": s.body}},
	})
	req, e := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(body))
	if e != nil {
		return "", none, 0, ErrUpstream
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	res, e := c.HTTP.Do(req)
	if e != nil {
		return "", none, 0, fmt.Errorf("%w: unreachable", ErrUpstream) // never wrap e: it may echo the URL/headers
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil {
		return "", none, 0, ErrUpstream
	}
	if res.StatusCode == 429 {
		secs, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		return "", none, time.Duration(max(secs, 2)) * time.Second, fmt.Errorf("%w: provider rate limit, try again in a minute", ErrUpstream)
	}
	// Groq answers 400 json_validate_failed when the model's own output broke
	// the strict schema. That is random, not our request: try again.
	if res.StatusCode == 400 && bytes.Contains(raw, []byte(`"json_validate_failed"`)) {
		return "", none, time.Second, fmt.Errorf("%w: model output did not fit the schema", ErrUpstream)
	}
	if res.StatusCode != 200 {
		return "", none, 0, fmt.Errorf("%w: HTTP %d", ErrUpstream, res.StatusCode) // body not echoed
	}
	var cr struct {
		Usage *struct {
			Input  int64 `json:"prompt_tokens"`
			Output int64 `json:"completion_tokens"`
			Total  int64 `json:"total_tokens"`
		} `json:"usage"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &cr) != nil || len(cr.Choices) == 0 {
		return "", none, 0, fmt.Errorf("%w: unexpected response", ErrUpstream)
	}
	u := none
	if cr.Usage != nil {
		u = insights.Usage{Known: true, Input: cr.Usage.Input, Output: cr.Usage.Output, Total: cr.Usage.Total}
	}
	return cr.Choices[0].Message.Content, u, 0, nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// trunc caps model text shown in the console.
func trunc(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
