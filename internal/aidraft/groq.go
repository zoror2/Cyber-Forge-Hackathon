package aidraft

import (
	"bytes"
	"configbridge/internal/egress"
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
	if source.Validate() != nil {
		return nil, ErrSource
	}
	public, _ := json.Marshal(source)
	payload := map[string]any{"model": g.model, "temperature": 0, "max_completion_tokens": 4096, "stream": false,
		"response_format": map[string]string{"type": "json_object"},
		"messages":        []map[string]string{{"role": "system", "content": prompt(source)}, {"role": "user", "content": string(public)}}}
	raw, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrProvider
	}
	req.Header.Set("Authorization", "Bearer "+g.key())
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, ErrProvider
	}
	defer resp.Body.Close()
	// Error bodies may echo prompts/credentials. Never read them into diagnostics.
	if resp.StatusCode != http.StatusOK {
		return nil, &ProviderStatusError{Code: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10+1))
	if err != nil || len(body) > 128<<10 || config.CheckJSON(body) != nil {
		return nil, ErrProvider
	}
	var envelope struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string `json:"content"`
				Refusal   any    `json:"refusal"`
				ToolCalls []any  `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Choices) != 1 {
		return nil, ErrProvider
	}
	choice := envelope.Choices[0]
	if choice.FinishReason != "stop" || choice.Message.Refusal != nil || len(choice.Message.ToolCalls) > 0 || len(choice.Message.Content) == 0 || len(choice.Message.Content) > 32<<10 {
		return nil, ErrOutput
	}
	return []byte(choice.Message.Content), nil
}
