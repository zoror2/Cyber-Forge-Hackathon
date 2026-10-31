package engine

// Tests for multi-field secrets, the "static" auth type and placeholders:
//   - TestStaticAuthMultiHeader: Cortex-style two-header auth from two fields
//   - TestStaticAuthMissingField: missing field fails before anything is sent
//   - TestStaticAuthHeaderInjection: secret containing CR/LF is refused
//   - TestStaticAuthValidation: bad templates are refused at validation
//   - TestOAuthFieldsAndExtraParams: client_id/secret from fields, audience sent
//   - TestMultiFieldSecretNeverPrints: no field value leaks via fmt/json

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func staticConn(h *harness, headers ...HeaderTemplate) Connector {
	c := h.conn("/x")
	c.Auth = Auth{Type: "static", Secret: "cortex", Headers: headers}
	return c
}

func TestStaticAuthMultiHeader(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-xdr-auth-id") != "42" || r.Header.Get("Authorization") != secretValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 3))
	})
	h.eng.Secrets = fakeSecrets{"t1/cortex": NewSecretFields(map[string]string{"key_id": "42", "key": secretValue}, h.host)}
	c := staticConn(h,
		HeaderTemplate{"x-xdr-auth-id", "{{secret.key_id}}"},
		HeaderTemplate{"Authorization", "{{ secret.key }}"})
	if _, items, err := h.fetch(c); err != nil || len(items) != 3 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
}

func TestStaticAuthMissingField(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	h.eng.Secrets = fakeSecrets{"t1/cortex": NewSecretFields(map[string]string{"key": secretValue}, h.host)}
	_, _, err := h.fetch(staticConn(h, HeaderTemplate{"x-xdr-auth-id", "{{secret.key_id}}"}))
	if err == nil || !strings.Contains(err.Error(), `"key_id"`) {
		t.Fatalf("want missing-field error naming key_id, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("nothing may be sent with an incomplete credential")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatal("error leaked a secret value")
	}
}

func TestStaticAuthHeaderInjection(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	h.eng.Secrets = fakeSecrets{"t1/cortex": NewSecretFields(map[string]string{"key": "abc\r\nX-Evil: 1"}, h.host)}
	if _, _, err := h.fetch(staticConn(h, HeaderTemplate{"Authorization", "{{secret.key}}"})); err == nil {
		t.Fatal("secret with CR/LF must be refused")
	}
	if hits.Load() != 0 {
		t.Fatal("request must not be sent")
	}
}

func TestStaticAuthValidation(t *testing.T) {
	cases := map[string][]HeaderTemplate{
		"no headers":         nil,
		"no placeholder":     {{"Authorization", "hardcoded"}},
		"wrong namespace":    {{"Authorization", "{{env.HOME}}"}},
		"typo":               {{"Authorization", "{{secrt.key}}"}},
		"bad header name":    {{"Bad Header", "{{secret.key}}"}},
		"host header":        {{"Host", "{{secret.key}}"}},
		"duplicate":          {{"A", "{{secret.key}}"}, {"a", "{{secret.key}}"}},
		"newline in literal": {{"A", "x\n{{secret.key}}"}},
		"too many":           {{"A", "{{secret.k}}"}, {"B", "x"}, {"C", "x"}, {"D", "x"}, {"E", "x"}, {"F", "x"}},
	}
	for name, hs := range cases {
		c := Connector{TenantID: "t1", ID: "x", Request: Request{URL: "https://api.example.com/x"},
			Auth: Auth{Type: "static", Secret: "s", Headers: hs}}
		if c.Validate() == nil {
			t.Errorf("%s: should be refused", name)
		}
	}
	ok := Connector{TenantID: "t1", ID: "x", Request: Request{URL: "https://api.example.com/x"},
		Auth: Auth{Type: "static", Secret: "s", Headers: []HeaderTemplate{{"Authorization", "Token {{secret.value}}"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid static auth refused: %v", err)
	}
}

func TestOAuthFieldsAndExtraParams(t *testing.T) {
	var gotAudience, gotUser, gotPass atomic.Value
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			r.ParseForm()
			u, p, _ := r.BasicAuth()
			gotUser.Store(u)
			gotPass.Store(p)
			gotAudience.Store(r.PostForm.Get("audience"))
			fmt.Fprint(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 1))
	})
	h.eng.Secrets = fakeSecrets{"t1/wiz": NewSecretFields(map[string]string{"client_id": "cid", "client_secret": secretValue}, h.host)}
	c := h.conn("/x")
	c.Auth = Auth{Type: "oauth2_client_credentials", Secret: "wiz", TokenURL: h.srv.URL + "/token",
		ExtraParams: map[string]string{"audience": "wiz-api"}}
	if _, _, err := h.fetch(c); err != nil {
		t.Fatal(err)
	}
	if gotUser.Load() != "cid" || gotPass.Load() != secretValue || gotAudience.Load() != "wiz-api" {
		t.Fatalf("token request: user=%v audience=%v", gotUser.Load(), gotAudience.Load())
	}

	// Secret-looking or reserved extra params are refused.
	for _, k := range []string{"client_secret", "grant_type", "api_key"} {
		c.Auth.ExtraParams = map[string]string{k: "x"}
		if c.Validate() == nil {
			t.Errorf("extra_params.%s should be refused", k)
		}
	}
}

func TestMultiFieldSecretNeverPrints(t *testing.T) {
	s := NewSecretFields(map[string]string{"client_id": "cid", "client_secret": secretValue}, "a.example.com")
	holder := struct{ S Secret }{s}
	b, _ := json.Marshal(holder)
	for _, out := range []string{fmt.Sprintf("%v %+v %#v %s", s, holder, holder, s), string(b)} {
		if strings.Contains(out, secretValue) || strings.Contains(out, "cid") {
			t.Fatalf("leaked: %s", out)
		}
	}
	// Changing the caller's map afterwards must not change the secret.
	m := map[string]string{"value": "a"}
	s2 := NewSecretFields(m, "a.example.com")
	m["value"] = "b"
	if s2.value() != "a" {
		t.Fatal("secret must own a copy of its fields")
	}
	if _, err := renderSecret("{{secret.value}}", Secret{}); err == nil {
		t.Fatal("zero Secret must have no fields")
	}
}
