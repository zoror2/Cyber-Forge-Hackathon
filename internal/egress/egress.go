// Package egress decides WHERE outbound vendor requests are allowed to go.
//
// It is the most security-critical package in the project. Every call the
// platform makes to a vendor API (CrowdStrike, Jira, a firewall...) must pass
// three checks from this file:
//
//  1. CheckURL        - the URL must be https and must not embed credentials.
//  2. CheckSecretHost - a secret is only ever sent to the one host it is
//     bound to (e.g. the "jira" secret can only go to acme.atlassian.net).
//  3. Client          - the HTTP client checks the REAL IP address at the
//     moment it connects (after DNS lookup), so a hostname that secretly
//     points at localhost, a private network or the cloud metadata service
//     is refused. It also never follows redirects.
//
// If any check fails, the error wraps ErrBlocked. Callers must never retry a
// blocked request, and should log it loudly because it may indicate misuse.
package egress

import (
	"crypto/tls"  // TLS settings (minimum version, trusted certificates)
	"crypto/x509" // certificate pools (only used by tests)
	"errors"
	"fmt"
	"net"       // low-level network dialing
	"net/http"  // the HTTP client we return
	"net/netip" // IP address parsing and range checks
	"net/url"   // URL parsing
	"strings"
	"syscall" // RawConn type used by the dial hook
	"time"
)

// ErrBlocked marks every refusal made by this package.
// Use errors.Is(err, egress.ErrBlocked) to detect it anywhere up the stack.
var ErrBlocked = errors.New("egress blocked")

// Policy holds the outbound rules.
//
// The ZERO VALUE (egress.Policy{}) IS THE PRODUCTION POLICY: https only, public
// IPs only. The fields below only LOOSEN the rules and exist for local
// development and tests. Production code must never set them.
type Policy struct {
	// AllowPrivate lists IP ranges that may be reached even though they are
	// private, e.g. the Docker network where the mock vendor runs.
	// DEV/TEST ONLY.
	AllowPrivate []netip.Prefix

	// AllowHTTP permits plain http:// URLs (the local mock vendor has no TLS).
	// DEV/TEST ONLY.
	AllowHTTP bool

	// RootCAs replaces the system's trusted certificate list. Tests use it to
	// trust their own self-signed test server. TESTS ONLY.
	RootCAs *x509.CertPool
}

// blockedPrefixes are address ranges that Go's helper methods would treat as
// "public" but that must never be reached: documentation ranges, carrier NAT,
// and IPv6 translation ranges that can smuggle an internal IPv4 address.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (shared address space)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (TEST-NET-1)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: can map to an internal IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/32"),       // Teredo tunnelling
	netip.MustParsePrefix("2001:db8::/32"),   // IPv6 documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: can embed a private IPv4
}

// CheckIP returns an error unless ip is a normal, public, unicast address.
//
// Refused: loopback (127.x, ::1), private (10.x, 172.16-31.x, 192.168.x,
// fc00::/7), link-local (169.254.x including the cloud metadata service
// 169.254.169.254, fe80::), multicast, unspecified (0.0.0.0, ::), and
// everything in blockedPrefixes.
func (p Policy) CheckIP(ip netip.Addr) error {
	// "::ffff:127.0.0.1" is IPv4 wearing an IPv6 costume. Unmap() strips the
	// costume so the IPv4 rules below apply to it.
	ip = ip.Unmap()

	// Dev/test exceptions are checked first (empty in production).
	for _, allowed := range p.AllowPrivate {
		if allowed.Contains(ip) {
			return nil
		}
	}

	// Go's built-in classifiers cover the common private/special ranges.
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: address %s is not public", ErrBlocked, ip)
	}

	// Then our extra list of ranges that look public but must not be reached.
	for _, blocked := range blockedPrefixes {
		if blocked.Contains(ip) {
			return fmt.Errorf("%w: address %s is in a reserved range", ErrBlocked, ip)
		}
	}
	return nil
}

// CheckURL validates the shape of a URL before any request is built.
func (p Policy) CheckURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: missing URL", ErrBlocked)
	}
	// Only https, unless the dev-only AllowHTTP flag permits http.
	// This also rejects file://, ftp://, gopher:// and similar.
	if u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http") {
		return fmt.Errorf("%w: scheme %q not allowed, use https", ErrBlocked, u.Scheme)
	}
	// "https://user:password@host" would put credentials in logs and proxies.
	if u.User != nil {
		return fmt.Errorf("%w: credentials inside the URL are not allowed", ErrBlocked)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: URL has no host", ErrBlocked)
	}
	return nil
}

// CheckSecretHost allows a secret to be sent only to the host it is bound to.
//
// Matching is exact and case-insensitive, so look-alikes are refused:
//
//	bound "api.github.com" vs "api.github.com"           -> allowed
//	bound "api.github.com" vs "api.github.com.evil.com"  -> refused
//	bound "api.github.com" vs "sub.api.github.com"       -> refused
//	bound "api.github.com" vs "api.github.com:8443"      -> refused (wrong port)
//
// A bound host WITH a port ("localhost:8081", used for the dev mock) must
// match host and port exactly.
func CheckSecretHost(boundHost string, target *url.URL) error {
	bound := strings.ToLower(strings.TrimSpace(boundHost))
	if bound == "" {
		// A secret without a binding can't be checked, so it can't be used.
		return fmt.Errorf("%w: secret has no bound host", ErrBlocked)
	}
	if target == nil {
		return fmt.Errorf("%w: missing target URL", ErrBlocked)
	}

	// Case 1: the binding includes a port -> compare "host:port" exactly.
	if strings.Contains(bound, ":") {
		if strings.ToLower(target.Host) != bound {
			return fmt.Errorf("%w: secret is bound to %s, not %s", ErrBlocked, bound, target.Host)
		}
		return nil
	}

	// Case 2: no port in the binding -> host must match and the port must be
	// absent or the default HTTPS port 443.
	host, port := strings.ToLower(target.Hostname()), target.Port()
	if host != bound || (port != "" && port != "443") {
		return fmt.Errorf("%w: secret is bound to %s, not %s", ErrBlocked, bound, target.Host)
	}
	return nil
}

// Client returns the ONLY HTTP client the engine may use for vendor calls.
//
// timeout is the overall limit for one request, including reading the body.
func (p Policy) Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second, // max time to open a TCP connection

		// Control runs just before each connection is opened, with the exact
		// IP:port being dialled (DNS is already resolved at this point).
		// Checking here, instead of on the hostname, defeats:
		//   - hostnames that point at internal IPs (evil.com -> 127.0.0.1)
		//   - DNS rebinding (name resolves to a public IP first, internal later)
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: cannot parse dial address", ErrBlocked)
			}
			return p.CheckIP(addrPort.Addr())
		},
	}

	return &http.Client{
		Timeout: timeout,

		// Never follow redirects. A redirect could carry our credentials to a
		// different host, or bounce us to an internal address.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirects are not followed", ErrBlocked)
		},

		Transport: &http.Transport{
			// nil = ignore HTTP_PROXY / HTTPS_PROXY env vars, so nobody can
			// route our traffic (and credentials) through a proxy of their choice.
			Proxy:       nil,
			DialContext: dialer.DialContext, // every connection goes through Control above

			// TLS 1.2 or newer. RootCAs is nil in production = system trust store.
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs},

			ForceAttemptHTTP2:      true,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  timeout,  // vendor must start answering within timeout
			MaxResponseHeaderBytes: 64 << 10, // 64 KB of headers max (stops header floods)
			IdleConnTimeout:        30 * time.Second,
		},
	}
}
