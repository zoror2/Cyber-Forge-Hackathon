// Package engine fetches records from vendor APIs: auth, safe HTTP, retries,
// rate limits and pagination. Mapping and storage belong to Member B.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"configbridge/internal/egress"
)

var (
	ErrTooLarge  = errors.New("response exceeds size limit")
	ErrPageLimit = errors.New("page limit reached")
)

// StatusError is a non-2xx vendor response. The body is never included.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("vendor returned HTTP %d", e.Code) }

// Page is one page of raw records handed to the mapper.
type Page struct {
	Number int
	Items  []any
}

type Result struct {
	Pages int
	Items int
}

type Engine struct {
	Secrets SecretStore
	Policy  egress.Policy
	Log     *slog.Logger

	sleep func(context.Context, time.Duration) error
	now   func() time.Time

	mu     sync.Mutex
	tokens map[string]oauthToken
}

func New(secrets SecretStore, policy egress.Policy, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{Secrets: secrets, Policy: policy, Log: log, sleep: sleepCtx, now: time.Now, tokens: map[string]oauthToken{}}
}

// Fetch pulls every page for one connector and hands each page to emit.
// Pages already emitted stay emitted if a later page fails.
func (e *Engine) Fetch(ctx context.Context, c Connector, emit func(Page) error) (Result, error) {
	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid connector: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.Limits.MaxRunSeconds)*time.Second)
	defer cancel()

	client := e.Policy.Client(time.Duration(c.Request.TimeoutSeconds) * time.Second)
	defer client.CloseIdleConnections()

	start, _ := url.Parse(c.Request.URL) // validated above
	q := start.Query()
	for k, v := range c.Request.Params {
		q.Set(k, v)
	}
	start.RawQuery = q.Encode()

	var res Result
	page, offset, cursor := c.Pagination.StartPage, 0, ""
	var next *url.URL
	seen := map[string]bool{}

	for {
		if res.Pages >= c.Limits.MaxPages {
			return res, ErrPageLimit
		}
		u := next
		if u == nil {
			u = c.pagedURL(start, page, offset, cursor)
		}
		if seen[u.String()] {
			return res, fmt.Errorf("pagination loop detected at page %d", res.Pages+1)
		}
		seen[u.String()] = true

		body, header, err := e.get(ctx, client, c, u)
		if err != nil {
			e.logFailure(c, u, err)
			return res, fmt.Errorf("page %d: %w", res.Pages+1, err)
		}
		payload, items, err := decodeItems(body, c.ItemsPath)
		if err != nil {
			return res, fmt.Errorf("page %d: %w", res.Pages+1, err)
		}
		res.Pages++
		res.Items += len(items)
		if err := emit(Page{Number: res.Pages, Items: items}); err != nil {
			return res, err
		}

		switch c.Pagination.Type {
		case "none":
			return res, nil
		case "page", "offset":
			if len(items) < c.Pagination.PageSize {
				return res, nil
			}
			page++
			offset += len(items)
		case "cursor":
			v, _ := getPath(payload, c.Pagination.CursorPath)
			s, _ := v.(string)
			if s == "" || len(items) == 0 {
				return res, nil
			}
			cursor = s
		case "link":
			link := nextLink(header.Values("Link"))
			if link == "" {
				return res, nil
			}
			nu, err := u.Parse(link)
			if err != nil {
				return res, fmt.Errorf("page %d: invalid next link", res.Pages)
			}
			// A vendor (or attacker controlling a response) must not steer us elsewhere.
			if !strings.EqualFold(nu.Host, start.Host) {
				err := fmt.Errorf("%w: next link points to a different host (%s)", egress.ErrBlocked, nu.Host)
				e.logFailure(c, nu, err)
				return res, err
			}
			next = nu
		}
	}
}

func (c Connector) pagedURL(base *url.URL, page, offset int, cursor string) *url.URL {
	u := *base
	q := u.Query()
	p := c.Pagination
	switch p.Type {
	case "page":
		q.Set(p.PageParam, strconv.Itoa(page))
	case "offset":
		q.Set(p.OffsetParam, strconv.Itoa(offset))
	case "cursor":
		if cursor != "" {
			q.Set(p.CursorParam, cursor)
		}
	}
	if p.SizeParam != "" && p.PageSize > 0 {
		q.Set(p.SizeParam, strconv.Itoa(p.PageSize))
	}
	u.RawQuery = q.Encode()
	return &u
}

// get performs one logical request with retries and rate-limit handling.
func (e *Engine) get(ctx context.Context, client *http.Client, c Connector, u *url.URL) ([]byte, http.Header, error) {
	if err := e.Policy.CheckURL(u); err != nil {
		return nil, nil, err
	}
	for attempt := 1; ; attempt++ {
		body, header, err := e.once(ctx, client, c, u)
		if err == nil || ctx.Err() != nil {
			return body, header, err
		}
		wait, retry := e.retryDelay(c.Retry, attempt, header, err)
		if !retry {
			return nil, header, err
		}
		e.Log.Warn("vendor request failed, retrying",
			"connector", c.ID, "url", RedactURL(u), "attempt", attempt, "wait", wait.String(), "error", err.Error())
		if err := e.sleep(ctx, wait); err != nil {
			return nil, nil, err
		}
	}
}

func (e *Engine) retryDelay(r Retry, attempt int, header http.Header, err error) (time.Duration, bool) {
	if attempt >= r.MaxAttempts || errors.Is(err, egress.ErrBlocked) || errors.Is(err, ErrTooLarge) {
		return 0, false
	}
	backoff := time.Duration(r.BaseDelayMillis) * time.Millisecond << (attempt - 1)
	var se *StatusError
	if !errors.As(err, &se) {
		return backoff, true // timeouts and network errors
	}
	switch {
	case se.Code == http.StatusTooManyRequests:
		if d, ok := parseRetryAfter(header.Get("Retry-After"), e.now()); ok {
			if d > time.Duration(r.MaxRetryAfterSeconds)*time.Second {
				return 0, false // vendor wants longer than one run should wait
			}
			return d, true
		}
		return backoff, true
	case se.Code == http.StatusRequestTimeout || se.Code >= 500:
		return backoff, true
	default:
		return 0, false // 401/403/404 etc. will not fix themselves
	}
}

func (e *Engine) once(ctx context.Context, client *http.Client, c Connector, u *url.URL) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: invalid URL")
	}
	for k, v := range c.Request.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "ConfigBridge/0.1")
	if err := e.authorize(ctx, client, c, req); err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, scrub(err, u)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode == http.StatusUnauthorized && c.Auth.Type == "oauth2_client_credentials" {
			e.dropToken(c.ID)
		}
		return nil, resp.Header, &StatusError{Code: resp.StatusCode}
	}
	body, err := readLimited(resp.Body, c.Limits.MaxResponseBytes)
	if err != nil {
		return nil, resp.Header, scrub(err, u)
	}
	return body, resp.Header, nil
}

func (e *Engine) logFailure(c Connector, u *url.URL, err error) {
	level := slog.LevelWarn
	if errors.Is(err, egress.ErrBlocked) {
		level = slog.LevelError // possible misuse: surface loudly
	}
	e.Log.Log(context.Background(), level, "vendor request failed",
		"connector", c.ID, "url", RedactURL(u), "error", err.Error())
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

func decodeItems(body []byte, path string) (any, []any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return nil, nil, errors.New("response is not valid JSON")
	}
	v, ok := getPath(payload, path)
	if !ok {
		return nil, nil, fmt.Errorf("items_path %q not found in response", path)
	}
	items, ok := v.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("items_path %q is not an array", path)
	}
	return payload, items, nil
}

// getPath follows a dotted path ("data.items", "results.0.id") through decoded JSON.
func getPath(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	for _, part := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			next, ok := t[part]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// nextLink returns the rel="next" target from RFC 8288 Link headers.
func nextLink(values []string) string {
	for _, v := range values {
		for _, part := range splitLinks(v) {
			segs := strings.Split(part, ";")
			target := strings.TrimSpace(segs[0])
			if len(target) < 2 || target[0] != '<' || target[len(target)-1] != '>' {
				continue
			}
			for _, s := range segs[1:] {
				k, val, ok := strings.Cut(strings.TrimSpace(s), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "rel") {
					continue
				}
				for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(val), `"`)) {
					if strings.EqualFold(rel, "next") {
						return target[1 : len(target)-1]
					}
				}
			}
		}
	}
	return ""
}

// splitLinks splits on commas that are outside <...>, since URLs may contain commas.
func splitLinks(v string) []string {
	var parts []string
	depth, start := 0, 0
	for i, r := range v {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, v[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, v[start:])
}

func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
