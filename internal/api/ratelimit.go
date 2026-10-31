package api

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Rate is a token bucket: Burst requests at once, refilled at PerSecond.
type Rate struct {
	PerSecond float64
	Burst     float64
}

// Limits for our own API (vendor 429s are handled by the engine, FR-8).
// In-memory per instance: with N API replicas the effective limit is N times
// this; move the buckets to a shared store or the load balancer/WAF when scaling.
type Limits struct {
	PerIP       Rate // requests with a key not verified recently (before authentication)
	VerifiedIP  Rate // backstop per IP for verified keys: one machine can't multiply stolen keys
	FailedPerIP Rate // failed authentications only (key guessing)
	PerKey      Rate // every authenticated request, per API key
	RunPerKey   Rate // POST /connectors/{id}/run|test: these call the vendor
}

var DefaultLimits = Limits{
	PerIP:       Rate{PerSecond: 20, Burst: 60},
	VerifiedIP:  Rate{PerSecond: 100, Burst: 300}, // high, so one noisy key can't starve neighbours on a shared IP/NAT
	FailedPerIP: Rate{PerSecond: 0.2, Burst: 10},  // 10 misses, then one per 5 s
	PerKey:      Rate{PerSecond: 10, Burst: 40},
	RunPerKey:   Rate{PerSecond: 0.2, Burst: 6}, // 6 runs at once, then one per 5 s
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

func newLimiter() *limiter {
	return &limiter{buckets: map[string]*bucket{}, now: time.Now}
}

// take spends one token from the named bucket. When empty it returns false and
// how many whole seconds until a token is available (for Retry-After).
func (l *limiter) take(key string, r Rate) (bool, int) {
	if r.PerSecond <= 0 || r.Burst <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.buckets) > 100_000 {
		l.sweep(now)
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: r.Burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(r.Burst, b.tokens+now.Sub(b.last).Seconds()*r.PerSecond)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, int(math.Ceil((1 - b.tokens) / r.PerSecond))
}

// peek reports whether a bucket is empty without spending a token.
func (l *limiter) peek(key string, r Rate) (bool, int) {
	if r.PerSecond <= 0 || r.Burst <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return true, 0
	}
	t := math.Min(r.Burst, b.tokens+l.now().Sub(b.last).Seconds()*r.PerSecond)
	if t >= 1 {
		return true, 0
	}
	return false, int(math.Ceil((1 - t) / r.PerSecond))
}

// sweep drops buckets idle for 10 minutes (they would be full again anyway).
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// clientIP is the TCP peer address. X-Forwarded-For is deliberately ignored:
// any client can set it. Behind a load balancer, trust only its header there.
func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return host
}

// keyID names an API key's bucket without keeping the key in memory.
func keyID(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:12])
}

func limited(w http.ResponseWriter, retry int) {
	if retry < 1 {
		retry = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	fail(w, 429, "rate_limited")
}

// keyCache remembers recently verified keys (by hash, never the key itself).
// It only exempts them from per-IP gates; authentication always hits the DB.
type keyCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cached
	now func() time.Time
}
type cached struct {
	tenant string
	until  time.Time
}

func newKeyCache(ttl time.Duration) *keyCache {
	return &keyCache{ttl: ttl, m: map[string]cached{}, now: time.Now}
}
func (c *keyCache) get(id string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	if !ok || c.now().After(v.until) {
		delete(c.m, id)
		return "", false
	}
	return v.tenant, true
}
func (c *keyCache) drop(id string) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}
func (c *keyCache) put(id, tenant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 10_000 {
		c.m = map[string]cached{}
	}
	c.m[id] = cached{tenant, c.now().Add(c.ttl)}
}
