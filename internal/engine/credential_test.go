package engine

// Tests that every credential problem is classified correctly and tagged with
// the credential ID, so the platform can tell the right owner what to fix.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"configbridge/internal/egress"
)

// authStatus runs the connector and returns the AuthError (fails if none).
func authStatus(t *testing.T, h *harness, c Connector) *AuthError {
	t.Helper()
	_, _, err := h.fetch(c)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("want *AuthError, got %v", err)
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatal("auth error leaked the secret")
	}
	return ae
}

func TestCredentialStatuses(t *testing.T) {
	status := http.StatusOK
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, itemsJSON(1, 1))
	})
	cred := NewSecret(secretValue, h.host).WithID("cred_ravi")

	// missing: not in the store at all
	h.eng.Secrets = fakeSecrets{}
	if ae := authStatus(t, h, h.conn("/x")); ae.Status != StatusMissing || ae.Secret != "tok" {
		t.Errorf("missing: got %+v", ae)
	}

	// needs_reauth: vendor 401
	h.eng.Secrets = fakeSecrets{"t1/tok": cred}
	status = http.StatusUnauthorized
	if ae := authStatus(t, h, h.conn("/x")); ae.Status != StatusNeedsReauth || ae.CredentialID != "cred_ravi" {
		t.Errorf("401: got %+v", ae)
	}

	// insufficient_permissions: vendor 403, still a *StatusError underneath
	status = http.StatusForbidden
	ae := authStatus(t, h, h.conn("/x"))
	var se *StatusError
	if ae.Status != StatusInsufficientPermissions || !errors.As(ae, &se) || se.Code != 403 {
		t.Errorf("403: got %+v", ae)
	}

	// binding_mismatch: secret bound elsewhere; still an egress block
	h.eng.Secrets = fakeSecrets{"t1/tok": NewSecret(secretValue, "api.github.com").WithID("cred_x")}
	status = http.StatusOK
	ae = authStatus(t, h, h.conn("/x"))
	if ae.Status != StatusBindingMismatch || ae.CredentialID != "cred_x" || !errors.Is(ae, egress.ErrBlocked) {
		t.Errorf("binding: got %+v", ae)
	}

	// incomplete: static auth needs a field the secret doesn't have
	h.eng.Secrets = fakeSecrets{"t1/tok": cred}
	c := h.conn("/x")
	c.Auth = Auth{Type: "static", Secret: "tok", Headers: []HeaderTemplate{{"x-id", "{{secret.key_id}}"}}}
	if ae := authStatus(t, h, c); ae.Status != StatusIncomplete || ae.CredentialID != "cred_ravi" {
		t.Errorf("incomplete: got %+v", ae)
	}
}

// A missing secret fails at once: no retry, no backoff wait.
func TestMissingSecretIsNotRetried(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, itemsJSON(1, 1)) })
	h.eng.Secrets = fakeSecrets{}
	waits := 0
	h.eng.sleep = func(context.Context, time.Duration) error { waits++; return nil }
	c := h.conn("/x")
	c.Retry.MaxAttempts = 4
	if ae := authStatus(t, h, c); ae.Status != StatusMissing {
		t.Fatalf("got %+v", ae)
	}
	if waits != 0 {
		t.Fatalf("missing secret was retried %d times", waits)
	}
}

// A wrong OAuth client secret is reported as needs_reauth whether the token
// endpoint answers 400 or 401 (vendors differ, RFC 6749 allows both).
func TestOAuthTokenEndpointRefusal(t *testing.T) {
	for _, code := range []int{400, 401} {
		h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.WriteHeader(code)
				fmt.Fprint(w, `{"error":"invalid_client"}`)
				return
			}
			fmt.Fprint(w, itemsJSON(1, 1))
		})
		h.eng.Secrets = fakeSecrets{"t1/oa": NewSecretFields(
			map[string]string{"client_id": "c", "client_secret": secretValue}, h.host).WithID("cred_oa")}
		c := h.conn("/x")
		c.Auth = Auth{Type: "oauth2_client_credentials", Secret: "oa", TokenURL: h.srv.URL + "/token"}
		if ae := authStatus(t, h, c); ae.Status != StatusNeedsReauth || ae.CredentialID != "cred_oa" {
			t.Errorf("token %d: got %+v", code, ae)
		}
	}
}

// Server errors are NOT credential problems (nobody should rotate a key
// because the vendor is down).
func TestServerErrorIsNotCredentialProblem(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	_, _, err := h.fetch(h.conn("/x"))
	var ae *AuthError
	if err == nil || errors.As(err, &ae) {
		t.Fatalf("503 must fail without an AuthError, got %v", err)
	}
}

// The log line for a credential problem carries credential_id + auth_status.
func TestAuthFailureLogEvent(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	h.eng.Secrets = fakeSecrets{"t1/tok": NewSecret(secretValue, h.host).WithID("cred_ravi")}
	h.fetch(h.conn("/x"))
	var entry map[string]any
	if err := json.Unmarshal(h.logs.Bytes(), &entry); err != nil {
		t.Fatalf("log: %v\n%s", err, h.logs.String())
	}
	if entry["event"] != "auth_failed" || entry["credential_id"] != "cred_ravi" ||
		entry["auth_status"] != StatusNeedsReauth || entry["tenant"] != "t1" {
		t.Fatalf("unexpected log entry: %v", entry)
	}
	if strings.Contains(h.logs.String(), secretValue) {
		t.Fatal("secret leaked into logs")
	}
}
