// Package app owns process-level wiring. Connector configs cannot enable local
// network access or disable certificate verification.
package app

import (
	"configbridge/internal/egress"
	"crypto/x509"
	"errors"
	"net/netip"
	"os"
	"strings"
)

func Policy(getenv func(string) string) (egress.Policy, error) {
	p := egress.Policy{}
	private, plain, ca := getenv("CB_DEV_ALLOW_PRIVATE"), getenv("CB_DEV_ALLOW_HTTP"), getenv("CB_DEV_CA_FILE")
	if getenv("CB_ENV") != "dev" {
		if private != "" || plain != "" || ca != "" {
			return p, errors.New("development egress overrides refused outside CB_ENV=dev")
		}
		return p, nil
	}
	if plain != "" {
		return p, errors.New("use the TLS mock; HTTP development override is not enabled by the API")
	}
	for _, raw := range strings.Split(private, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, e := netip.ParsePrefix(raw)
		if e != nil {
			return p, errors.New("invalid development IP range")
		}
		if !prefix.Addr().IsPrivate() && !prefix.Addr().IsLoopback() {
			return p, errors.New("development override must be a private or loopback IP range")
		}
		p.AllowPrivate = append(p.AllowPrivate, prefix)
	}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil {
			return p, errors.New("development CA unavailable")
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return p, errors.New("invalid development CA")
		}
		p.RootCAs = pool
	}
	return p, nil
}
