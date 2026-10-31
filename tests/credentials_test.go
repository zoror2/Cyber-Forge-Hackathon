package tests

import (
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/pkg/secrets"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestMultiFieldCredentialsReachOnlyBoundHosts(t *testing.T) {
	e := setup(t)
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key-ID") != "synthetic-id" || r.Header.Get("Authorization") != "synthetic-secret" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `[{"id":"one"}]`)
	}))
	defer vendor.Close()
	host := strings.TrimPrefix(vendor.URL, "https://")
	body, _ := json.Marshal(map[string]any{"fields": map[string]string{"key_id": "synthetic-id", "key": "synthetic-secret"}, "allowed_hosts": []string{"second.example.com", host}})
	e.request(t, "tenant-a", "PUT", "/secrets/multipart", body, 204)
	secret, err := e.svc.Get(context.Background(), "tenant-a", "multipart")
	if err != nil || secret.ID() == "" || len(secret.AllowedHosts()) != 2 {
		t.Fatal("bad credential", err)
	}
	policy := egress.Policy{RootCAs: vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	requestEngine := engine.New(e.svc, policy, nil)
	c := userConfig("multipart", vendor.URL)
	c.Auth = engine.Auth{Type: "static", Secret: "multipart", Headers: []engine.HeaderTemplate{{Name: "X-Key-ID", Value: "{{secret.key_id}}"}, {Name: "Authorization", Value: "{{secret.key}}"}}}
	result, err := requestEngine.Fetch(context.Background(), c.Connector("tenant-a"), func(engine.Page) error { return nil })
	if err != nil || result.Items != 1 {
		t.Fatal(result, err)
	}
	if _, err = e.svc.Get(context.Background(), "tenant-b", "multipart"); err == nil {
		t.Fatal("cross-tenant credential")
	}
	e.request(t, "tenant-a", "PUT", "/secrets/multipart", []byte(`{"value":"new","allowed_hosts":["evil.example"]}`), 409)
	out := e.request(t, "tenant-a", "GET", "/secrets", nil, 200)
	if strings.Contains(string(out), "synthetic-secret") || strings.Contains(string(out), "synthetic-id") || strings.Contains(string(out), `"fields"`) {
		t.Fatal("credential values exposed")
	}
	// Both input formats remain supported; ambiguous or unsafe input is refused.
	for _, in := range []secrets.Input{
		{Value: "x", Fields: map[string]string{"key": "x"}, Host: host},
		{Value: "x", Host: host, Hosts: []string{host}},
		{Value: "x", Hosts: []string{host, host}},
		{Fields: map[string]string{"key": "x\r\nInjected: header"}, Host: host},
		{Fields: map[string]string{"key": ""}, Host: host},
		{Value: strings.Repeat("x", 32769), Host: host},
	} {
		if _, _, err = in.Normalize(); err == nil {
			t.Fatal("unsafe credential input accepted")
		}
	}
}
