package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"configbridge/configs"
)

// fake answers with the given config_json strings in order and records requests.
func fake(t *testing.T, answers ...string) (*Client, *[]string) {
	seen := []string{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(401)
			return
		}
		out, _ := json.Marshal(map[string]any{"config_json": answers[min(n, len(answers)-1)], "notes": []string{"n"}, "needed": []string{"key"}, "optional": []string{}, "sources": []string{"https://docs.github.com/rest", "javascript:alert(1)", "http://x.example"}, "also_available": []string{"user_inventory", "detection_finding", "nope", "detection_finding"}})
		n++
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(out)}}}})
	}))
	t.Cleanup(srv.Close)
	c := New("test-key", "")
	c.URL = srv.URL
	return c, &seen
}

func TestDraftRepairsAgainstValidator(t *testing.T) {
	bad := strings.Replace(string(configs.GitHubMembers), `"https://`, `"http://`, 1) // validator rejects http
	c, seen := fake(t, bad, string(configs.GitHubMembers))
	d, e := c.generate(context.Background(), Request{Product: "FixtureVendor", Data: "user_inventory"}, []Secret{{"github_token", "api.github.com"}})
	if e != nil || d.Rounds != 2 || !json.Valid(d.Config) {
		t.Fatal("repair loop", e, d)
	}
	if d.Data != "user_inventory" || len(d.AlsoAvailable) != 1 || d.AlsoAvailable[0] != "detection_finding" {
		t.Fatal("data / also_available not resolved and filtered", d.Data, d.AlsoAvailable)
	}
	if len(d.Sources) != 1 || d.Sources[0] != "https://docs.github.com/rest" {
		t.Fatal("sources not filtered to https", d.Sources)
	}
	if len(*seen) != 2 || !strings.Contains((*seen)[1], "validator rejected") {
		t.Fatal("issues not fed back")
	}
	if !strings.Contains((*seen)[0], `"strict":true`) || !strings.Contains((*seen)[0], "github_token -\\u003e api.github.com") {
		t.Fatal("strict schema / secret names missing", (*seen)[0][:200])
	}
}

func TestDraftGivesUpWithIssues(t *testing.T) {
	c, seen := fake(t, `{"version":1,"id":"BAD ID"}`)
	_, e := c.generate(context.Background(), Request{Product: "Okta", Data: "user_inventory"}, nil)
	var bad *InvalidDraft
	if !errors.As(e, &bad) || len(bad.Issues) == 0 || len(*seen) != 1+MaxRepairs {
		t.Fatal("should stop after repairs with issues", e, len(*seen))
	}
}

func TestProviderKeysNeverFollowRedirects(t *testing.T) {
	for _, makeClient := range []func(string, string) *Client{New, NewGemini} {
		hits := 0
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
		redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
		c := makeClient("SYNTHETIC_PROVIDER_KEY", "fixture")
		req, _ := http.NewRequest("GET", redirect.URL, nil)
		req.Header.Set("x-goog-api-key", c.Key)
		res, e := c.HTTP.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		redirect.Close()
		target.Close()
		if res.StatusCode != 302 || hits != 0 {
			t.Fatal("provider redirect followed")
		}
	}
}
func TestDraftPreservesTheSelectedClass(t *testing.T) {
	c, _ := fake(t, string(configs.GitHubMembers))
	_, e := c.generate(context.Background(), Request{Product: "FixtureVendor", Data: "vulnerability_finding"}, nil)
	var bad *InvalidDraft
	if !errors.As(e, &bad) || len(bad.Issues) != 1 || bad.Issues[0].Field != "destination.class" {
		t.Fatal("changed requested class", e)
	}
}

func TestDraftNotConfiguredAndProviderErrors(t *testing.T) {
	if _, e := New("", "").Draft(context.Background(), Request{Product: "X", Data: "user_inventory"}, nil); !errors.Is(e, ErrNotConfigured) {
		t.Fatal(e)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal detail with key test-key"))
	}))
	defer srv.Close()
	c := New("test-key", "")
	c.URL = srv.URL
	_, e := c.generate(context.Background(), Request{Product: "X", Data: "user_inventory"}, nil)
	if !errors.Is(e, ErrUpstream) || strings.Contains(e.Error(), "test-key") || strings.Contains(e.Error(), "internal detail") {
		t.Fatal("provider error leaked body or key:", e)
	}
}

func TestRequestCheck(t *testing.T) {
	for _, a := range []string{"auto", ""} {
		if (Request{Product: "GitHub", Data: a}).Check() != nil {
			t.Fatal("auto rejected", a)
		}
	}
	for _, r := range []Request{{Product: "", Data: "user_inventory"}, {Product: "Okta", Data: "nope"}, {Product: "Okta", Data: "user_inventory", Details: strings.Repeat("x", 20001)}} {
		if r.Check() == nil {
			t.Fatal("accepted", r.Product, r.Data)
		}
	}
	if (Request{Product: "GitHub", Data: "user_inventory"}).Check() != nil {
		t.Fatal("valid request rejected")
	}
}
