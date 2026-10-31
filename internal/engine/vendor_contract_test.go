package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSophosClientSecretPostAndCursorContract(t *testing.T) {
	tokens, pages := 0, 0
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth/token" {
			tokens++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "sophos-id" || r.Form.Get("client_secret") != secretValue || r.Form.Get("scope") != "token" || r.Form.Get("grant_type") != "client_credentials" {
				t.Error("OAuth form contract violated")
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"access_token":"synthetic-access","token_type":"bearer","expires_in":3600}`)
			return
		}
		pages++
		if r.Header.Get("Authorization") != "Bearer synthetic-access" || r.Header.Get("X-Tenant-ID") != "sophos-tenant" {
			t.Error("API headers incorrect")
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("pageFromKey") == "" {
			fmt.Fprint(w, `{"items":[{"id":"endpoint-1","hostname":"one"}],"pages":{"nextKey":"cursor-2"}}`)
		} else {
			if r.URL.Query().Get("pageFromKey") != "cursor-2" {
				t.Error("wrong cursor")
			}
			fmt.Fprint(w, `{"items":[{"id":"endpoint-2","hostname":"two"}],"pages":{}}`)
		}
	})
	c := h.conn("/endpoint/v1/endpoints")
	c.Auth = Auth{Type: "oauth2_client_credentials", Secret: "tok", ClientID: "sophos-id", TokenURL: h.srv.URL + "/oauth/token", ClientAuthMethod: "client_secret_post", Scopes: []string{"token"}}
	c.Request.Headers = map[string]string{"X-Tenant-ID": "sophos-tenant"}
	c.ItemsPath = "items"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "pageFromKey", CursorPath: "pages.nextKey"}
	for i := 0; i < 2; i++ {
		res, items, err := h.fetch(c)
		if err != nil || len(items) != 2 || res.Pages != 2 {
			t.Fatal(res, len(items), err)
		}
	}
	if tokens != 1 || pages != 4 {
		t.Fatal("token caching/paging wrong", tokens, pages)
	}
	if strings.Contains(h.logs.String(), secretValue) || strings.Contains(h.logs.String(), "synthetic-access") {
		t.Fatal("credential logged")
	}
	c.Auth.ClientAuthMethod = "invented"
	if c.Validate() == nil {
		t.Fatal("unsupported client authentication accepted")
	}
}

func TestResponseChecksRejectHTTP200FailuresBeforeEmit(t *testing.T) {
	for _, body := range []string{`{"items":[{"id":1}],"timed_out":true,"_shards":{"failed":0}}`, `{"items":[{"id":1}],"timed_out":false,"_shards":{"failed":1}}`, `{"items":[{"id":1}],"timed_out":false}`} {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		c := h.conn("/search")
		c.ItemsPath = "items"
		c.ResponseChecks = []ResponseCheck{{Path: "timed_out", Equals: false}, {Path: "_shards.failed", Equals: 0}}
		res, items, err := h.fetch(c)
		if err == nil || len(items) != 0 || res.Pages != 0 {
			t.Fatal("incomplete response emitted", res, items, err)
		}
	}
}

func TestJSONNextURLPaginationContractsAndSecurity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		next  any
		pages int
		fail  bool
	}{
		{"relative", "/alerts?after=second", 2, false},
		{"no more pages", nil, 1, false},
		{"empty last link", "", 1, false},
		{"malformed object", map[string]string{"href": "/alerts"}, 1, true},
		{"other host", "https://attacker.example/steal", 1, true},
		{"scheme downgrade", "http://127.0.0.1/steal", 1, true},
		{"credentials in URL", "https://user:password@127.0.0.1/steal", 1, true},
		{"cycle", "/alerts", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				next := tc.next
				if r.URL.Query().Get("after") == "second" {
					next = nil
				}
				json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]string{"id": "one"}}, "links": map[string]any{"next": next}})
			})
			c := h.conn("/alerts")
			c.ItemsPath = "items"
			c.Pagination = Pagination{Type: "next_url", NextURLPath: "links.next"}
			res, _, err := h.fetch(c)
			if (err != nil) != tc.fail || res.Pages != tc.pages {
				t.Fatal(res, err)
			}
		})
	}
	t.Run("empty intermediate page is not final", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery == "" {
				fmt.Fprint(w, `{"items":[],"nextLink":"?after=second"}`)
			} else {
				fmt.Fprint(w, `{"items":[{"id":1}],"nextLink":null}`)
			}
		})
		c := h.conn("/alerts")
		c.ItemsPath = "items"
		c.Pagination = Pagination{Type: "next_url", NextURLPath: "nextLink"}
		res, items, err := h.fetch(c)
		if err != nil || res.Pages != 2 || len(items) != 1 {
			t.Fatal(res, items, err)
		}
		c.Limits.MaxPages = 1
		if _, _, err = h.fetch(c); !errors.Is(err, ErrPageLimit) {
			t.Fatal("page bound bypassed", err)
		}
	})
}
