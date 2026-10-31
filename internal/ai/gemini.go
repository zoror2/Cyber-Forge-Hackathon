package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewGemini drafts with the Gemini API. Every draft first researches the
// vendor's CURRENT docs with Google Search, then writes the config from those
// facts with strict JSON output (two calls: search and strict schema output
// are kept apart so neither depends on the other being supported together).
func NewGemini(key, model string) *Client {
	return &Client{Key: key, Model: model, URL: "https://generativelanguage.googleapis.com/v1beta/models/",
		HTTP: &http.Client{Timeout: 120 * time.Second}, gemini: true}
}

// LookupDNS fails only when the host does not exist (NXDOMAIN). A resolver
// outage is not the model's fault, so it never blocks a draft.
func LookupDNS(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, e := net.DefaultResolver.LookupHost(ctx, host)
	var de *net.DNSError
	if errors.As(e, &de) && de.IsNotFound {
		return e
	}
	return nil
}

// research asks Gemini (with Google Search) for the facts a config needs.
func (c *Client) research(ctx context.Context, r Request) (string, error) {
	data := "its main security dataset (users, devices, logins or findings, whichever the product is mainly about)"
	if !r.Auto() {
		data = "OCSF class " + r.Data
	}
	q := "Product: " + r.Product + "\nData wanted: " + data + "\n"
	if strings.TrimSpace(r.Details) != "" {
		q += "Customer notes: " + r.Details + "\n"
	}
	q += `Search the vendor's CURRENT official API documentation and report, briefly and factually:
0. If the name is a company with several products that each have their own API, list them in one line each (product, API host, cloud or on-prem) and research the one a security team would mean by this name; say which one you picked.
1. Where the API runs: vendor cloud (exact host, regional hosts) or on the customer's own appliance/tenant (what part is customer-specific).
2. The current recommended auth (not deprecated ones): scheme, EVERY credential value the customer must create, token URL and token request parameters (audience/scope) if OAuth.
3. The REST GET endpoint that LISTS those records (path), and if logs/events are only available by streaming/export (syslog, S3, SIEM forwarders), say so.
4. Pagination: request parameters and the response field or header that gives the next page; the JSON path of the records array.
5. Key record fields (id, name/email, status, timestamps).
6. The exact official documentation URLs you used.
Say "unknown" for anything the docs do not state. Do not guess.`
	body := map[string]any{
		"contents": []map[string]any{{"role": "user", "parts": []map[string]any{{"text": q}}}},
		"tools":    []map[string]any{{"google_search": map[string]any{}}},
	}
	var text string
	e := c.retry(ctx, func() (time.Duration, error) {
		t, wait, e := c.geminiCall(ctx, body)
		text = t
		return wait, e
	})
	if len(text) > 12000 {
		text = text[:12000]
	}
	return text, e
}

// geminiOnce: one strict-JSON drafting call.
func (c *Client) geminiOnce(ctx context.Context, msgs []message) (*modelOutput, time.Duration, error) {
	body := map[string]any{"generationConfig": map[string]any{
		"responseMimeType": "application/json", "responseJsonSchema": outputSchema, "temperature": 0.2}}
	var contents []map[string]any
	for _, m := range msgs {
		part := []map[string]any{{"text": m.Content}}
		switch m.Role {
		case "system":
			body["systemInstruction"] = map[string]any{"parts": part}
		case "assistant":
			contents = append(contents, map[string]any{"role": "model", "parts": part})
		default:
			contents = append(contents, map[string]any{"role": "user", "parts": part})
		}
	}
	body["contents"] = contents
	text, wait, e := c.geminiCall(ctx, body)
	if e != nil {
		return nil, wait, e
	}
	var out modelOutput
	if json.Unmarshal([]byte(text), &out) != nil {
		return nil, time.Second, fmt.Errorf("%w: model output did not fit the schema", ErrUpstream)
	}
	return &out, 0, nil
}

// geminiCall posts one generateContent request and returns the answer text.
func (c *Client) geminiCall(ctx context.Context, body map[string]any) (string, time.Duration, error) {
	raw, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, "POST", c.URL+url.PathEscape(c.Model)+":generateContent", bytes.NewReader(raw))
	if e != nil {
		return "", 0, ErrUpstream
	}
	req.Header.Set("x-goog-api-key", c.Key) // header, never the URL: URLs get logged
	req.Header.Set("Content-Type", "application/json")
	res, e := c.HTTP.Do(req)
	if e != nil {
		return "", 0, fmt.Errorf("%w: unreachable", ErrUpstream) // e may echo the URL
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if e != nil {
		return "", 0, ErrUpstream
	}
	switch {
	case res.StatusCode == 429:
		return "", 10 * time.Second, fmt.Errorf("%w: provider rate limit, try again in a minute", ErrUpstream)
	case res.StatusCode == 503 || res.StatusCode == 500:
		return "", 5 * time.Second, fmt.Errorf("%w: provider busy", ErrUpstream)
	case res.StatusCode == 401 || res.StatusCode == 403:
		return "", 0, fmt.Errorf("%w: Gemini key rejected", ErrUpstream)
	case res.StatusCode != 200:
		return "", 0, fmt.Errorf("%w: HTTP %d", ErrUpstream, res.StatusCode) // body not echoed
	}
	var gr struct {
		Candidates []struct {
			FinishReason string `json:"finishReason"`
			Content      struct {
				Parts []struct {
					Text    string `json:"text"`
					Thought bool   `json:"thought"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(b, &gr) != nil || len(gr.Candidates) == 0 {
		return "", 0, fmt.Errorf("%w: no answer", ErrUpstream)
	}
	var sb strings.Builder
	for _, p := range gr.Candidates[0].Content.Parts {
		if !p.Thought {
			sb.WriteString(p.Text)
		}
	}
	if gr.Candidates[0].FinishReason == "MAX_TOKENS" {
		return "", 0, fmt.Errorf("%w: model output too long", ErrUpstream)
	}
	if sb.Len() == 0 {
		return "", time.Second, fmt.Errorf("%w: empty answer", ErrUpstream)
	}
	return sb.String(), 0, nil
}
