package aidraft

import (
	"bytes"
	"configbridge/internal/egress"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const GroqEndpoint = "https://api.groq.com/openai/v1/chat/completions"
const DefaultModel = "qwen/qwen3.8-27b"

// ProviderStatusError contains only a status code, never a vendor error body.
type ProviderStatusError struct{ Code int }

func (e *ProviderStatusError) Error() string { return fmt.Sprintf("ai_provider_http_%d", e.Code) }
func (e *ProviderStatusError) Unwrap() error { return ErrProvider }

type Groq struct {
	key      func() string // keep the key out of accidental struct formatting
	model    string
	client   *http.Client
	endpoint string
}

func NewGroq(key, model string) (*Groq, error) {
	if model == "" {
		model = DefaultModel
	}
	if len(key) < 16 || len(key) > 512 || strings.ContainsAny(key, " \r\n\t") || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/._-]{0,127}$`).MatchString(model) {
		return nil, ErrProvider
	}
	return &Groq{key: func() string { return key }, model: model, client: (egress.Policy{}).Client(45 * time.Second), endpoint: GroqEndpoint}, nil
}
func (*Groq) Name() string    { return "groq" }
func (g *Groq) Model() string { return g.model }
func (g *Groq) Generate(ctx context.Context, source Source) ([]byte, error) {
	raw, _, err := g.GenerateMetered(ctx, source)
	return raw, err
}
func (g *Groq) GenerateMetered(ctx context.Context, source Source) ([]byte, insights.Usage, error) {
	if source.Validate() != nil {
		return nil, insights.Usage{}, ErrSource
	}
	public, _ := json.Marshal(source)
	return g.complete(ctx, prompt(source), string(public), 4096)
}
func (g *Groq) complete(ctx context.Context, system, user string, maxTokens int) ([]byte, insights.Usage, error) {
	usage := insights.Usage{}
	if len(system)+len(user) > 32<<10 {
		return nil, usage, ErrOutput
	}
	payload := map[string]any{"model": g.model, "temperature": 0, "max_completion_tokens": maxTokens, "stream": false,
		"response_format": map[string]string{"type": "json_object"},
		"messages":        []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}}
	raw, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, usage, ErrProvider
	}
	req.Header.Set("Authorization", "Bearer "+g.key())
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, usage, ErrProvider
	}
	defer resp.Body.Close()
	// Error bodies may echo prompts/credentials. Never read them into diagnostics.
	if resp.StatusCode != http.StatusOK {
		return nil, usage, &ProviderStatusError{Code: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10+1))
	if err != nil || len(body) > 128<<10 || config.CheckJSON(body) != nil {
		return nil, usage, ErrProvider
	}
	var envelope struct {
		Usage *struct {
			Input  int64 `json:"prompt_tokens"`
			Output int64 `json:"completion_tokens"`
			Total  int64 `json:"total_tokens"`
		} `json:"usage"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string `json:"content"`
				Refusal   any    `json:"refusal"`
				ToolCalls []any  `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, usage, ErrProvider
	}
	if u := envelope.Usage; u != nil {
		usage = insights.Usage{Known: true, Input: u.Input, Output: u.Output, Total: u.Total}
		if !usage.Valid() {
			return nil, insights.Usage{}, ErrProvider
		}
	}
	if len(envelope.Choices) != 1 {
		return nil, usage, ErrProvider
	}
	choice := envelope.Choices[0]
	if choice.FinishReason != "stop" || choice.Message.Refusal != nil || len(choice.Message.ToolCalls) > 0 || len(choice.Message.Content) == 0 || len(choice.Message.Content) > 32<<10 {
		return nil, usage, ErrOutput
	}
	return []byte(choice.Message.Content), usage, nil
}

// Explain accepts only validated counts and enumerated categories. Unlike the
// public-source drafter this is customer-derived metadata, requiring separate
// operator enablement and request consent at the SIEM API boundary.
func (g *Groq) Explain(ctx context.Context, e insights.Evidence) (a insights.Answer, u insights.Usage, err error) {
	if e.Validate() != nil {
		return a, u, insights.ErrEvidence
	}
	rules, _ := json.Marshal(insights.Rules)
	checks, _ := json.Marshal(insights.Checks)
	system := `Explain only the supplied security/collection findings. The evidence is aggregate metadata, not proof of an attack or affected deployment. Do not invent facts, people, products, IDs, causes or dates. Describe uncertainty. Never suggest disabling security, revealing secrets or automatically changing config. Return JSON only with summary (plain text <=2000 characters), evidence_ids (one or more supplied eN IDs), next_checks (up to 5 unique keys from the allowed checks). No HTML, links, commands or other fields. Rules: ` + string(rules) + `. Allowed checks: ` + string(checks)
	user, _ := json.Marshal(e)
	raw, u, err := g.complete(ctx, system, string(user), 2048)
	if err != nil {
		return a, u, err
	}
	if strict(raw, &a) != nil || a.Validate(e) != nil {
		return insights.Answer{}, u, insights.ErrEvidence
	}
	return a, u, nil
}
