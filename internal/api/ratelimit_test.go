package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRateLimits(t *testing.T) {
	keyA, keyB, keyC := strings.Repeat("key-a-", 8), strings.Repeat("key-b-", 8), strings.Repeat("key-c-", 8)
	lim := &Limits{
		PerIP:       Rate{PerSecond: 1, Burst: 8},
		FailedPerIP: Rate{PerSecond: 0.1, Burst: 3},
		PerKey:      Rate{PerSecond: 1, Burst: 3},
		RunPerKey:   Rate{PerSecond: 0.1, Burst: 1},
	}
	h, e := New(&API{Limits: lim, Authenticate: func(_ context.Context, k string) (string, error) {
		if k == keyA || k == keyB || k == keyC {
			return "tenant-a", nil
		}
		return "", errors.New("invalid")
	}})
	if e != nil {
		t.Fatal(e)
	}
	call := func(ip, method, path, key string) (int, string) {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = ip + ":5555"
		r.Header.Set("X-Forwarded-For", "203.0.113.99") // must be ignored
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		func() {
			defer func() { recover() }() // handlers have no store; only the gate matters
			h.ServeHTTP(w, r)
		}()
		return w.Code, w.Header().Get("Retry-After")
	}

	// failed authentication: 3 misses allowed, then the IP is refused even with a valid key
	for i := 0; i < 3; i++ {
		if c, _ := call("10.0.0.1", "GET", "/runs", "bad"); c != 401 {
			t.Fatal("miss", i, c)
		}
	}
	if c, ra := call("10.0.0.1", "GET", "/runs", strings.Repeat("unknown-", 6)); c != 429 || ra == "" {
		t.Fatal("guessing IP not blocked for an unverified key", c, ra)
	}
	// a key verified earlier from this IP is not locked out by the junk flood
	if c, _ := call("10.0.0.9", "GET", "/runs", keyC); c == 429 {
		t.Fatal("setup")
	}
	if c, _ := call("10.0.0.1", "GET", "/runs", keyC); c == 429 {
		t.Fatal("verified key locked out by another client's bad keys", c)
	}
	// another IP is unaffected
	if c, _ := call("10.0.0.2", "GET", "/runs", "bad"); c != 401 {
		t.Fatal("other IP blocked", c)
	}

	// per key: burst 3, then 429; a second key on the same IP still works
	for i := 0; i < 3; i++ {
		if c, _ := call("10.0.0.3", "GET", "/runs", keyA); c == 429 {
			t.Fatal("key limited too early", i)
		}
	}
	if c, _ := call("10.0.0.3", "GET", "/runs", keyA); c != 429 {
		t.Fatal("key A not limited", c)
	}
	if c, _ := call("10.0.0.3", "GET", "/runs", keyB); c == 429 {
		t.Fatal("key B limited by key A", c)
	}

	// run/test: one per key, then 429 (key B has plenty of general budget left)
	if c, _ := call("10.0.0.4", "POST", "/connectors/x/run", keyB); c == 429 {
		t.Fatal("first run limited")
	}
	if c, _ := call("10.0.0.4", "POST", "/connectors/x/test", keyB); c != 429 {
		t.Fatal("second run not limited", c)
	}

	// verified keys share a separate, larger per-IP backstop
	vip, _ := New(&API{Limits: &Limits{VerifiedIP: Rate{PerSecond: 1, Burst: 5}}, Authenticate: func(context.Context, string) (string, error) { return "tenant-a", nil }})
	blocked := 0
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "/runs", nil)
		r.RemoteAddr = "10.0.0.7:1"
		r.Header.Set("Authorization", "Bearer "+[]string{keyA, keyB, keyC}[i%3])
		w := httptest.NewRecorder()
		func() {
			defer func() { recover() }()
			vip.ServeHTTP(w, r)
		}()
		if w.Code == 429 {
			blocked++
		}
	}
	// first use of each of the 3 keys is unverified (not counted), the next 7 hit the backstop of 5
	if blocked != 2 {
		t.Fatal("verified per-IP backstop wrong", blocked)
	}

	// per IP: burst 8 for keys not yet verified
	ipOnly, _ := New(&API{Limits: &Limits{PerIP: Rate{PerSecond: 1, Burst: 8}}, Authenticate: func(context.Context, string) (string, error) { return "tenant-a", nil }})
	n := 0
	for i := 0; i < 12; i++ {
		r := httptest.NewRequest("GET", "/runs", nil)
		r.RemoteAddr = "10.0.0.5:1"
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("fresh", 8)+strconv.Itoa(i)) // never verified before
		w := httptest.NewRecorder()
		func() {
			defer func() { recover() }()
			ipOnly.ServeHTTP(w, r)
		}()
		if w.Code == 429 {
			n++
		}
	}
	if n != 4 {
		t.Fatal("per-IP limit wrong", n)
	}
}

func TestBucketRefills(t *testing.T) {
	l := newLimiter()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	r := Rate{PerSecond: 0.5, Burst: 1}
	if ok, _ := l.take("k", r); !ok {
		t.Fatal("first")
	}
	if ok, retry := l.take("k", r); ok || retry != 2 {
		t.Fatal("should wait 2s", ok, retry)
	}
	now = now.Add(2 * time.Second)
	if ok, _ := l.take("k", r); !ok {
		t.Fatal("not refilled")
	}
}
