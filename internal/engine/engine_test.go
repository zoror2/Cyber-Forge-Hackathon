package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"configbridge/internal/egress"
)

const secretValue = "tok-SUPERSECRET-123"

type fakeSecrets map[string]Secret

func (f fakeSecrets) Get(_ context.Context, name string) (Secret, error) {
	s, ok := f[name]
	if !ok {
		return Secret{}, errors.New("not found")
	}
	return s, nil
}

type harness struct {
	srv    *httptest.Server
	eng    *Engine
	host   string
	sleeps []time.Duration
	logs   *bytes.Buffer
}

// newHarness starts a local TLS vendor. Loopback is allowed ONLY here, via the
// dev/test policy fields; production uses the zero Policy.
func newHarness(t *testing.T, h http.HandlerFunc) *harness {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hs := &harness{srv: srv, host: strings.TrimPrefix(srv.URL, "https://"), logs: &bytes.Buffer{}}
	policy := egress.Policy{
		AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		RootCAs:      pool,
	}
	hs.eng = New(fakeSecrets{"tok": NewSecret(secretValue, hs.host)}, policy, slog.New(slog.NewJSONHandler(hs.logs, nil)))
	hs.eng.sleep = func(_ context.Context, d time.Duration) error {
		hs.sleeps = append(hs.sleeps, d)
		return nil
	}
	return hs
}

func (h *harness) conn(path string) Connector {
	return Connector{ID: "test", Request: Request{URL: h.srv.URL + path}, Auth: Auth{Type: "bearer", Secret: "tok"}}
}

func (h *harness) fetch(c Connector) (Result, []any, error) {
	var items []any
	res, err := h.eng.Fetch(context.Background(), c, func(p Page) error {
		items = append(items, p.Items...)
		return nil
	})
	return res, items, err
}

func itemsJSON(from, n int) string {
	parts := make([]string, n)
	for i := range n {
		parts[i] = fmt.Sprintf(`{"id":%d}`, from+i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func pageOf(total, start, size int) (int, int) {
	if start >= total {
		return start, 0
	}
	return start, min(size, total-start)
}

func assertSleeps(t *testing.T, got []time.Duration, want ...time.Duration) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sleeps = %v, want %v", got, want)
	}
}

// ---- Auth and secret binding ----

func TestBearerSentOnlyToBoundHost(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+secretValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 1))
	})
	if _, items, err := h.fetch(h.conn("/x")); err != nil || len(items) != 1 {
		t.Fatalf("bound host should work: items=%d err=%v", len(items), err)
	}

	h.eng.Secrets = fakeSecrets{"tok": NewSecret(secretValue, "api.github.com")}
	_, _, err := h.fetch(h.conn("/x"))
	if !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("secret bound elsewhere must be refused, got %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("refused request must never reach the server, hits=%d", hits.Load())
	}
}

func TestAPIKeyAndBasic(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, basic := r.BasicAuth()
		okKey := r.URL.Path == "/key" && r.Header.Get("X-API-Key") == secretValue
		okBasic := r.URL.Path == "/basic" && basic && user == "me@corp.com" && pass == secretValue
		if !okKey && !okBasic {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 1))
	})
	c := h.conn("/key")
	c.Auth = Auth{Type: "api_key", Header: "X-API-Key", Secret: "tok"}
	if _, _, err := h.fetch(c); err != nil {
		t.Fatalf("api_key: %v", err)
	}
	c = h.conn("/basic")
	c.Auth = Auth{Type: "basic", Username: "me@corp.com", Secret: "tok"}
	if _, _, err := h.fetch(c); err != nil {
		t.Fatalf("basic: %v", err)
	}
}

func TestOAuthClientCredentialsCachesToken(t *testing.T) {
	var tokenHits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenHits.Add(1)
			id, sec, ok := r.BasicAuth()
			if r.Method != http.MethodPost || !ok || id != "client-1" || sec != secretValue || r.FormValue("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start, n := pageOf(15, (page-1)*10, 10)
		fmt.Fprint(w, itemsJSON(start, n))
	})
	c := h.conn("/data")
	c.Auth = Auth{Type: "oauth2_client_credentials", Secret: "tok", TokenURL: h.srv.URL + "/token", ClientID: "client-1"}
	c.Pagination = Pagination{Type: "page", PageParam: "page", SizeParam: "limit", PageSize: 10}
	_, items, err := h.fetch(c)
	if err != nil || len(items) != 15 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	if tokenHits.Load() != 1 {
		t.Fatalf("token should be fetched once and cached, got %d", tokenHits.Load())
	}
}

// ---- Retries and rate limits ----

func TestServerErrorBackoffThenFail(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, _, err := h.fetch(h.conn("/x"))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
	if hits.Load() != 4 {
		t.Fatalf("want 4 attempts, got %d", hits.Load())
	}
	assertSleeps(t, h.sleeps, time.Second, 2*time.Second, 4*time.Second)
}

func TestServerErrorRecovers(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 3))
	})
	_, items, err := h.fetch(h.conn("/x"))
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	assertSleeps(t, h.sleeps, time.Second, 2*time.Second)
}

func TestRateLimitHonoursRetryAfter(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, itemsJSON(1, 1))
	})
	if _, _, err := h.fetch(h.conn("/x")); err != nil {
		t.Fatal(err)
	}
	assertSleeps(t, h.sleeps, 5*time.Second)
}

func TestRateLimitTooLongGivesUp(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "999")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if _, _, err := h.fetch(h.conn("/x")); err == nil {
		t.Fatal("expected failure")
	}
	if hits.Load() != 1 || len(h.sleeps) != 0 {
		t.Fatalf("must not wait 999s: hits=%d sleeps=%v", hits.Load(), h.sleeps)
	}
}

func TestUnauthorizedIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, _, err := h.fetch(h.conn("/x"))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 || hits.Load() != 1 || len(h.sleeps) != 0 {
		t.Fatalf("err=%v hits=%d sleeps=%v", err, hits.Load(), h.sleeps)
	}
}

func TestTimeoutIsRetried(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	c := h.conn("/hang")
	c.Request.TimeoutSeconds = 1
	c.Retry.MaxAttempts = 2
	if _, _, err := h.fetch(c); err == nil {
		t.Fatal("expected timeout failure")
	}
	if hits.Load() != 2 {
		t.Fatalf("want 2 attempts, got %d", hits.Load())
	}
	assertSleeps(t, h.sleeps, time.Second)
}

func TestOversizedResponseRefused(t *testing.T) {
	var hits atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, itemsJSON(1, 200))
	})
	c := h.conn("/x")
	c.Limits.MaxResponseBytes = 100
	_, _, err := h.fetch(c)
	if !errors.Is(err, ErrTooLarge) || hits.Load() != 1 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

// ---- Pagination ----

func TestPagePagination(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		start, n := pageOf(25, (page-1)*size, size)
		fmt.Fprint(w, itemsJSON(start, n))
	})
	c := h.conn("/users")
	c.Pagination = Pagination{Type: "page", PageParam: "page", SizeParam: "per_page", PageSize: 10}
	res, items, err := h.fetch(c)
	if err != nil || len(items) != 25 || res.Pages != 3 {
		t.Fatalf("pages=%d items=%d err=%v", res.Pages, len(items), err)
	}
}

func TestOffsetPagination(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		at, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
		size, _ := strconv.Atoi(r.URL.Query().Get("maxResults"))
		start, n := pageOf(25, at, size)
		fmt.Fprintf(w, `{"startAt":%d,"total":25,"issues":%s}`, at, itemsJSON(start, n))
	})
	c := h.conn("/issues")
	c.ItemsPath = "issues"
	c.Pagination = Pagination{Type: "offset", OffsetParam: "startAt", SizeParam: "maxResults", PageSize: 10}
	res, items, err := h.fetch(c)
	if err != nil || len(items) != 25 || res.Pages != 3 {
		t.Fatalf("pages=%d items=%d err=%v", res.Pages, len(items), err)
	}
}

func TestLinkPagination(t *testing.T) {
	var srvURL string
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		start, n := pageOf(25, (page-1)*10, 10)
		if start+n < 25 {
			w.Header().Set("Link", fmt.Sprintf(`<%s/users?page=%d>; rel="next", <%s/users?page=3>; rel="last"`, srvURL, page+1, srvURL))
		}
		fmt.Fprint(w, itemsJSON(start, n))
	})
	srvURL = h.srv.URL
	c := h.conn("/users")
	c.Pagination = Pagination{Type: "link"}
	res, items, err := h.fetch(c)
	if err != nil || len(items) != 25 || res.Pages != 3 {
		t.Fatalf("pages=%d items=%d err=%v", res.Pages, len(items), err)
	}
}

func TestLinkToAnotherHostIsBlocked(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		fmt.Fprint(w, itemsJSON(1, 10))
	})
	c := h.conn("/users")
	c.Pagination = Pagination{Type: "link"}
	res, _, err := h.fetch(c)
	if !errors.Is(err, egress.ErrBlocked) || res.Pages != 1 {
		t.Fatalf("pages=%d err=%v", res.Pages, err)
	}
}

func TestCursorPagination(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "":
			fmt.Fprintf(w, `{"data":%s,"meta":{"next":"c2"}}`, itemsJSON(1, 10))
		case "c2":
			fmt.Fprintf(w, `{"data":%s,"meta":{"next":""}}`, itemsJSON(11, 4))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	c := h.conn("/events")
	c.ItemsPath = "data"
	c.Pagination = Pagination{Type: "cursor", CursorParam: "after", CursorPath: "meta.next"}
	res, items, err := h.fetch(c)
	if err != nil || len(items) != 14 || res.Pages != 2 {
		t.Fatalf("pages=%d items=%d err=%v", res.Pages, len(items), err)
	}
}

func TestPageLimitStopsRunaway(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, itemsJSON(1, 10)) // always a full page: never ends on its own
	})
	c := h.conn("/x")
	c.Pagination = Pagination{Type: "page", PageParam: "page", SizeParam: "n", PageSize: 10}
	c.Limits.MaxPages = 3
	res, _, err := h.fetch(c)
	if !errors.Is(err, ErrPageLimit) || res.Pages != 3 {
		t.Fatalf("pages=%d err=%v", res.Pages, err)
	}
}

// ---- Validation and leak prevention ----

func TestValidateRejectsSecretsOutsideAuth(t *testing.T) {
	c := Connector{
		ID: "x",
		Request: Request{
			URL:     "http://api.example.com/x",
			Headers: map[string]string{"Authorization": "Bearer raw", "Accept": "application/json"},
			Params:  map[string]string{"api_key": "raw", "limit": "10"},
		},
		Auth: Auth{Type: "magic"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"https", "headers.Authorization", "params.api_key", `auth.type "magic"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	for _, okName := range []string{"Accept", "limit"} {
		if strings.Contains(err.Error(), "."+okName+":") {
			t.Errorf("%s should be allowed", okName)
		}
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret(secretValue, "api.github.com")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "secret", s)
	js, _ := json.Marshal(struct{ S Secret }{s})
	hidden := struct{ s Secret }{s} // unexported field: fmt bypasses String()
	out := fmt.Sprintf("%v %+v %#v %s %+v %#v", s, s, s, s, hidden, hidden) + string(js) + buf.String()
	if strings.Contains(out, secretValue) {
		t.Fatalf("secret leaked: %s", out)
	}
}

func TestLogsAndErrorsNeverContainSecrets(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := h.conn("/x")
	c.Request.Params = map[string]string{"q": "visible-query"}
	_, _, err := h.fetch(c)
	if err == nil {
		t.Fatal("expected failure")
	}
	all := h.logs.String() + err.Error()
	if strings.Contains(all, secretValue) {
		t.Fatalf("secret leaked: %s", all)
	}
	if strings.Contains(all, "visible-query") {
		t.Fatalf("query string leaked into logs: %s", all)
	}
	if !strings.Contains(h.logs.String(), "retrying") {
		t.Fatalf("expected retry log lines, got: %s", h.logs.String())
	}
}
