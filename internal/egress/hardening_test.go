package egress

// Tests for the feature-1 hardening on top of the basic guard:
//   - TestCheckURLOddHosts: numeric IP tricks, zone IDs, look-alike Unicode
//   - TestCheckSecretHosts: multi-host bindings, wildcards, empty bindings
//   - TestCheckPort: 443 default, explicit overrides only
//   - TestProductionSafe: dev loosening can't reach production silently
//   - Fuzz*: random inputs never crash and never loosen the rules

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCheckURLOddHosts(t *testing.T) {
	blocked := []string{
		"https://127.1/",                    // short form of 127.0.0.1
		"https://2130706433/",               // 127.0.0.1 as one decimal number
		"https://0x7f000001/",               // 127.0.0.1 in hex
		"https://0177.0.0.1/",               // 127.0.0.1 in octal
		"https://0x7f.0.0.1/",               // mixed hex label
		"https://[::1]/",                    // IPv6 loopback literal
		"https://[fe80::1%25eth0]/",         // IPv6 zone ID
		"https://169.254.169.254/latest/",   // cloud metadata literal
		"https://[::ffff:169.254.169.254]/", // metadata hidden in IPv4-mapped IPv6
		"https://аpi.github.com/",           // Cyrillic "а" look-alike
	}
	for _, raw := range blocked {
		u, err := url.Parse(raw)
		if err != nil {
			continue // unparseable is refused earlier anyway
		}
		if err := (Policy{}).CheckURL(u); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s should be blocked, got %v", raw, err)
		}
	}

	allowed := []string{
		"https://123.example.com/",       // numeric first label, real domain
		"https://beef.cafe/",             // hex-looking letters, no 0x
		"https://8.8.8.8/",               // public IP literal
		"https://xn--pi-6kc.github.com/", // punycode form is accepted
		"https://api.github.com./",       // trailing dot (FQDN)
	}
	for _, raw := range allowed {
		u, _ := url.Parse(raw)
		if err := (Policy{}).CheckURL(u); err != nil {
			t.Errorf("%s should pass, got %v", raw, err)
		}
	}
}

func TestCheckSecretHosts(t *testing.T) {
	wiz := []string{"auth.app.wiz.io", "api.us17.app.wiz.io"}
	cases := []struct {
		bound  []string
		target string
		ok     bool
	}{
		{wiz, "https://auth.app.wiz.io/oauth/token", true},
		{wiz, "https://api.us17.app.wiz.io/graphql", true},
		{wiz, "https://api.us18.app.wiz.io/graphql", false}, // not listed
		{wiz, "https://evil.com/", false},
		{[]string{"*.wiz.io"}, "https://api.wiz.io/", false},                    // wildcard
		{[]string{"api.wiz.io", "*"}, "https://api.wiz.io/", false},             // any wildcard poisons the list
		{nil, "https://api.wiz.io/", false},                                     // unbound
		{[]string{""}, "https://api.wiz.io/", false},                            // empty entry
		{[]string{"api.github.com"}, "https://api.github.com:8443/", false},     // wrong port
		{[]string{"api.github.com:8443"}, "https://api.github.com:8443/", true}, // explicit port binding
	}
	for _, c := range cases {
		u, _ := url.Parse(c.target)
		err := CheckSecretHosts(c.bound, u)
		if c.ok && err != nil {
			t.Errorf("bound=%v target=%s should pass: %v", c.bound, c.target, err)
		}
		if !c.ok && !errors.Is(err, ErrBlocked) {
			t.Errorf("bound=%v target=%s should be blocked, got %v", c.bound, c.target, err)
		}
	}
	if !errors.Is(CheckSecretHosts(wiz, nil), ErrBlocked) {
		t.Error("nil target must be blocked")
	}
}

func TestCheckPort(t *testing.T) {
	cases := []struct {
		raw     string
		allowed []int
		ok      bool
	}{
		{"https://api.x.com/", []int{443}, true},
		{"https://api.x.com:443/", []int{443}, true},
		{"https://api.x.com:8443/", []int{443}, false},
		{"https://api.x.com:8443/", []int{443, 8443}, true},
		{"https://api.x.com:22/", []int{443}, false},
		{"http://mock:80/", []int{443}, false},
		{"http://mock/", []int{80}, true},
		{"https://api.x.com/", nil, false}, // nothing allowed -> nothing passes
	}
	for _, c := range cases {
		u, _ := url.Parse(c.raw)
		err := CheckPort(u, c.allowed)
		if c.ok && err != nil {
			t.Errorf("%s %v should pass: %v", c.raw, c.allowed, err)
		}
		if !c.ok && !errors.Is(err, ErrBlocked) {
			t.Errorf("%s %v should be blocked, got %v", c.raw, c.allowed, err)
		}
	}
}

func TestProductionSafe(t *testing.T) {
	if err := (Policy{}).ProductionSafe(); err != nil {
		t.Fatalf("zero policy must be production-safe: %v", err)
	}
	unsafe := []Policy{
		{AllowHTTP: true},
		{AllowPrivate: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	}
	for _, p := range unsafe {
		if p.ProductionSafe() == nil {
			t.Errorf("%+v must not be production-safe", p)
		}
	}
}

// FuzzCheckSecretHost: whatever the inputs, a secret is only ever allowed
// when the target host equals the bound host (ignoring case and port 443).
func FuzzCheckSecretHost(f *testing.F) {
	f.Add("api.github.com", "https://api.github.com/x")
	f.Add("api.github.com", "https://api.github.com.evil.com/")
	f.Add("localhost:8081", "http://localhost:8081/")
	f.Add("a.b", "https://A.B:443/")
	f.Fuzz(func(t *testing.T, bound, target string) {
		u, err := url.Parse(target)
		if err != nil {
			return
		}
		if CheckSecretHost(bound, u) != nil {
			return
		}
		b := strings.ToLower(strings.TrimSpace(bound))
		if strings.EqualFold(u.Host, b) {
			return
		}
		if strings.EqualFold(u.Hostname(), b) && (u.Port() == "" || u.Port() == "443") {
			return
		}
		t.Fatalf("allowed bound=%q for host=%q", bound, u.Host)
	})
}

// FuzzCheckIP: never panics, and anything allowed is a plain global unicast
// address (never loopback, private, link-local, multicast or unspecified).
func FuzzCheckIP(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "8.8.8.8", "2606:4700::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			return
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		if (Policy{}).CheckIP(ip) != nil {
			return
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
			ip.IsUnspecified() || !ip.IsGlobalUnicast() {
			t.Fatalf("allowed non-public address %s", s)
		}
	})
}
