package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestGeminiResearchesThenDraftsAndChecksHosts(t *testing.T) {
	cfg, err := os.ReadFile("../../configs/github_members.json")
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("x-goog-api-key") != "k" || strings.Contains(r.URL.RawQuery, "key=") {
			t.Error("key must travel in the header only")
		}
		text := "API host api.github.com, bearer token, Link paging. Docs: https://docs.github.com/rest"
		if !strings.Contains(string(b), "google_search") {
			calls = append(calls, "draft")
			if !strings.Contains(string(b), "Link paging") || !strings.Contains(string(b), "responseJsonSchema") {
				t.Error("draft call must carry the research and the strict schema")
			}
			o, _ := json.Marshal(map[string]any{"config_json": string(cfg), "notes": []string{}, "needed": []string{}, "optional": []string{},
				"sources": []string{"https://docs.github.com/rest", "https://made-up.invalid/docs"}, "also_available": []string{}})
			text = string(o)
		} else {
			calls = append(calls, "research")
		}
		json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"finishReason": "STOP",
			"content": map[string]any{"parts": []any{map[string]any{"text": text}}}}}})
	}))
	defer srv.Close()
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	resolved := 0
	c.Resolve = func(_ context.Context, h string) error {
		resolved++
		if strings.HasSuffix(h, ".invalid") {
			return errors.New("nxdomain")
		}
		return nil
	}
	d, err := c.Draft(context.Background(), Request{Product: "GitHub", Data: "auto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "research,draft" || c.Provider() != "gemini" {
		t.Fatalf("calls %v", calls)
	}
	if len(d.Sources) != 1 || d.Sources[0] != "https://docs.github.com/rest" || resolved == 0 {
		t.Fatalf("dead doc link kept: %v", d.Sources)
	}
}

func TestCheckHostsRejectsMadeUpHost(t *testing.T) {
	c := &Client{Resolve: func(_ context.Context, h string) error {
		if h == "api.fake-vendor.com" {
			return errors.New("nxdomain")
		}
		return nil
	}}
	is := c.checkHosts(context.Background(), "https://api.fake-vendor.com/v1/x", "https://your-tenant.zslogin.net/t")
	if len(is) != 1 || is[0].Field != "request.url" {
		t.Fatal(is)
	}
}

func TestGeminiResearchCachedWithoutNotes(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": "facts"}}}}}})
	}))
	defer srv.Close()
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	for _, r := range []Request{{Product: "Okta"}, {Product: " okta ", Data: "auto"}, {Product: "Okta", Details: "private notes"}} {
		if _, err := c.research(context.Background(), r, &meter{}); err != nil {
			t.Fatal(err)
		}
	}
	if n != 2 { // second is a cache hit; notes always search
		t.Fatalf("searches %d", n)
	}
}
