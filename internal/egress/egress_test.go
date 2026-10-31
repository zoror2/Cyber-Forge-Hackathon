package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheckIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "198.18.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::",
	}
	for _, s := range blocked {
		if err := (Policy{}).CheckIP(netip.MustParseAddr(s)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s should be blocked, got %v", s, err)
		}
	}
	allowed := []string{"140.82.112.3", "8.8.8.8", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if err := (Policy{}).CheckIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s should be allowed, got %v", s, err)
		}
	}
	dev := Policy{AllowPrivate: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}}
	if err := dev.CheckIP(netip.MustParseAddr("172.18.0.5")); err != nil {
		t.Errorf("AllowPrivate should permit 172.18.0.5: %v", err)
	}
	if err := dev.CheckIP(netip.MustParseAddr("169.254.169.254")); !errors.Is(err, ErrBlocked) {
		t.Error("AllowPrivate for one range must not open the metadata address")
	}
}

func TestCheckURL(t *testing.T) {
	cases := map[string]bool{
		"https://api.github.com/orgs":        true,
		"http://api.github.com/orgs":         false,
		"ftp://api.github.com/":              false,
		"https://user:pass@api.github.com/":  false,
		"https:///nohost":                    false,
		"file:///etc/passwd":                 false,
		"gopher://169.254.169.254/":          false,
		"HTTPS://API.GITHUB.COM/mixed-case/": true,
	}
	for raw, ok := range cases {
		u, _ := url.Parse(raw)
		err := (Policy{}).CheckURL(u)
		if ok && err != nil {
			t.Errorf("%s should pass: %v", raw, err)
		}
		if !ok && !errors.Is(err, ErrBlocked) {
			t.Errorf("%s should be blocked, got %v", raw, err)
		}
	}
	u, _ := url.Parse("http://mock:8081/x")
	if err := (Policy{AllowHTTP: true}).CheckURL(u); err != nil {
		t.Errorf("AllowHTTP should permit http: %v", err)
	}
}

func TestCheckSecretHost(t *testing.T) {
	cases := []struct {
		bound, target string
		ok            bool
	}{
		{"api.github.com", "https://api.github.com/user", true},
		{"API.GitHub.com", "https://api.github.com/user", true},
		{"api.github.com", "https://api.github.com:443/user", true},
		{"api.github.com", "https://evil.com/user", false},
		{"api.github.com", "https://api.github.com.evil.com/user", false},
		{"api.github.com", "https://evil.com/?h=api.github.com", false},
		{"api.github.com", "https://api.github.com:8443/user", false},
		{"api.github.com", "https://sub.api.github.com/user", false},
		{"localhost:8081", "http://localhost:8081/x", true},
		{"localhost:8081", "http://localhost:9999/x", false},
		{"", "https://api.github.com/", false},
	}
	for _, c := range cases {
		u, _ := url.Parse(c.target)
		err := CheckSecretHost(c.bound, u)
		if c.ok && err != nil {
			t.Errorf("bound=%s target=%s should pass: %v", c.bound, c.target, err)
		}
		if !c.ok && !errors.Is(err, ErrBlocked) {
			t.Errorf("bound=%s target=%s should be blocked, got %v", c.bound, c.target, err)
		}
	}
}

func TestClientBlocksLoopbackAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request must never reach the server")
	}))
	defer srv.Close()

	client := Policy{AllowHTTP: true}.Client(2 * time.Second)
	// Both the raw IP and a hostname that resolves to it must be refused.
	for _, target := range []string{srv.URL, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)} {
		_, err := client.Get(target)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: expected ErrBlocked, got %v", target, err)
		}
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	policy := Policy{AllowHTTP: true, AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, err := policy.Client(2 * time.Second).Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected redirect to be refused, got %v", err)
	}
}
