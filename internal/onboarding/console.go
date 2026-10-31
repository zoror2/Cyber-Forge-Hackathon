package onboarding

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Console struct {
	Origin string
	Host   string
	key    []byte
	clock  func() time.Time
}

func New(origin string) (*Console, error) {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid local console origin")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if u.Hostname() != "localhost" && (e != nil || !ip.IsLoopback()) {
		return nil, errors.New("console origin must be localhost")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, errors.New("console initialization failed")
	}
	return &Console{Origin: u.Scheme + "://" + u.Host, Host: u.Host, key: key, clock: time.Now}, nil
}
func (c *Console) signature(tenant, actor, payload string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(tenant + "\x00" + actor + "\x00" + payload))
	return m.Sum(nil)
}
func (c *Console) Token(tenant, actor string) string {
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return ""
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." + strconv.FormatInt(c.clock().Unix(), 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(c.signature(tenant, actor, payload))
}
func (c *Console) ValidToken(tenant, actor, token string) bool {
	if len(token) > 256 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	nonce, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || len(nonce) != 16 {
		return false
	}
	issued, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil {
		return false
	}
	age := c.clock().Unix() - issued
	if age < 0 || age > 1800 {
		return false
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return false
	}
	return hmac.Equal(sig, c.signature(tenant, actor, parts[0]+"."+parts[1]))
}
