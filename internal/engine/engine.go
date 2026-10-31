// Package engine fetches records from vendor APIs: auth, safe HTTP, retries,
// rate limits and pagination. Mapping and storage belong to Member B.
//
// Main entry point: (*Engine).Fetch. Read this file top to bottom:
//
//	Fetch      -> loops over pages
//	  get      -> one logical request, with retries
//	    once   -> one single HTTP attempt
//	  retryDelay decides "retry? and how long to wait?"
//	helpers    -> size-limited reading, JSON paths, Link header parsing
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

// Errors callers can check with errors.Is to set the run status.
var (
	ErrTooLarge  = errors.New("response exceeds size limit") // response bigger than limits.max_response_bytes
	ErrPageLimit = errors.New("page limit reached")          // hit limits.max_pages before the vendor ran out of pages
)

// StatusError is a non-2xx vendor response (e.g. 401, 500).
// The response body is deliberately NOT included: vendor error bodies
// sometimes echo request headers, which could contain credentials.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("vendor returned HTTP %d", e.Code) }

// Page is one page of raw records handed to the mapper (Member B).
// Items are decoded JSON values: map[string]any, []any, string, bool, nil,
// and numbers as json.Number (not float64, so big IDs stay exact).
type Page struct {
	Number int   // 1-based page counter
	Items  []any // the records on this page
}

// Result summarises a run for the runs table / health page.
type Result struct {
	Attempts int // logical API attempts, including retries (token exchanges are separate)
	Pages    int // pages fetched successfully
	Items    int // records handed to emit
}

// Engine runs connectors. Create one with New and reuse it; it is safe for
// concurrent Fetch calls (the only shared state, the token cache, is locked).
type Engine struct {
	Secrets SecretStore   // where secrets come from (Member B's backend)
	Policy  egress.Policy // outbound rules; zero value = production
	Log     *slog.Logger  // structured logger; never receives secret values

	sleep func(context.Context, time.Duration) error // waiting between retries (tests replace it to run instantly)
	now   func() time.Time                           // current time (tests could replace it)

	mu     sync.Mutex            // protects tokens
	tokens map[string]oauthToken // OAuth tokens cached per tenant+connector (see tokenKey)
}

// New builds an Engine. Pass a nil logger to use slog's default.
func New(secrets SecretStore, policy egress.Policy, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{Secrets: secrets, Policy: policy, Log: log, sleep: sleepCtx, now: time.Now, tokens: map[string]oauthToken{}}
}

// Fetch pulls every page for one connector and hands each page to emit.
//
// emit is Member B's callback (map records, store them, quarantine bad ones).
// If emit returns an error, the run stops. Pages already emitted stay emitted
// if a later page fails, so the caller should record the run as "partial".
func (e *Engine) Fetch(ctx context.Context, c Connector, emit func(Page) error) (Result, error) {
	// 1. Fill defaults and validate. Nothing is sent for an invalid connector.
	//    (http:// is accepted only when the dev-only Policy.AllowHTTP is set.)
	c = c.withDefaults()
	if err := c.validate(e.Policy.AllowHTTP); err != nil {
		return Result{}, fmt.Errorf("invalid connector: %w", err)
	}

	// 2. Hard limit on the whole run (all pages and retries together).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.Limits.MaxRunSeconds)*time.Second)
	defer cancel()

	// 3. One egress-guarded HTTP client per run.
	client := e.Policy.Client(time.Duration(c.Request.TimeoutSeconds) * time.Second)
	defer client.CloseIdleConnections()

	// 4. Starting URL = configured URL + configured query params.
	start, _ := url.Parse(c.Request.URL) // already validated above
	q := start.Query()
	for k, v := range c.Request.Params {
		q.Set(k, v)
	}
	start.RawQuery = q.Encode()

	var res Result
	page, offset, cursor := c.Pagination.StartPage, 0, "" // position for page / offset / cursor styles
	var next *url.URL                                     // link style: next URL taken from the Link header
	seen := map[string]bool{}                             // URLs already fetched (loop detection)

	// 5. Page loop.
	for {
		if res.Pages >= c.Limits.MaxPages {
			return res, ErrPageLimit // runaway pagination protection
		}

		// Which URL to fetch now?
		u := next
		if u == nil {
			u = c.pagedURL(start, page, offset, cursor)
		}
		if seen[u.String()] { // vendor sent us back to a page we already fetched
			return res, fmt.Errorf("pagination loop detected at page %d", res.Pages+1)
		}
		seen[u.String()] = true

		// Fetch it (with retries).
		body, header, err := e.get(ctx, client, c, u, func() { res.Attempts++ })
		if err != nil {
			e.logFailure(c, u, err)
			return res, fmt.Errorf("page %d: %w", res.Pages+1, err)
		}

		// Decode JSON and pull out the record list.
		payload, items, err := decodeItems(body, c.ItemsPath)
		if err != nil {
			return res, fmt.Errorf("page %d: %w", res.Pages+1, err)
		}
		res.Pages++
		res.Items += len(items)

		// Hand the records to the mapper.
		if err := emit(Page{Number: res.Pages, Items: items}); err != nil {
			return res, err
		}

		// Work out the next page, or stop.
		switch c.Pagination.Type {
		case "none":
			return res, nil // single request, done

		case "page", "offset":
			// A short page means it was the last one.
			if len(items) < c.Pagination.PageSize {
				return res, nil
			}
			page++               // page style: ask for the next page number
			offset += len(items) // offset style: skip what we've already got

		case "cursor":
			// Read the next cursor from the response body.
			v, _ := getPath(payload, c.Pagination.CursorPath)
			s, _ := v.(string)
			if s == "" || len(items) == 0 {
				return res, nil // no cursor (or empty page) = last page
			}
			cursor = s

		case "link":
			// Read rel="next" from the Link header (GitHub, Okta style).
			link := nextLink(header.Values("Link"))
			if link == "" {
				return res, nil // no next link = last page
			}
			nu, err := u.Parse(link) // resolves relative links against the current URL
			if err != nil {
				return res, fmt.Errorf("page %d: invalid next link", res.Pages)
			}
			// SECURITY: a vendor (or an attacker who controls a response) must
			// not be able to steer us, with our credentials, to another host.
			if !strings.EqualFold(nu.Host, start.Host) {
				err := fmt.Errorf("%w: next link points to a different host (%s)", egress.ErrBlocked, nu.Host)
				e.logFailure(c, nu, err)
				return res, err
			}
			next = nu
		}
	}
}

// pagedURL returns base with the pagination params for the current position
// added, e.g. ?page=3&per_page=100 or ?startAt=200&maxResults=100.
func (c Connector) pagedURL(base *url.URL, page, offset int, cursor string) *url.URL {
	u := *base // copy, so base is never modified
	q := u.Query()
	p := c.Pagination
	switch p.Type {
	case "page":
		q.Set(p.PageParam, strconv.Itoa(page))
	case "offset":
		q.Set(p.OffsetParam, strconv.Itoa(offset))
	case "cursor":
		if cursor != "" { // first page has no cursor yet
			q.Set(p.CursorParam, cursor)
		}
	}
	if p.SizeParam != "" && p.PageSize > 0 {
		q.Set(p.SizeParam, strconv.Itoa(p.PageSize))
	}
	u.RawQuery = q.Encode()
	return &u
}

// get performs one logical request: it calls once() and retries on
// temporary failures, waiting between attempts as retryDelay decides.
//
// onAttempt (optional) is called before every attempt, retries included, so
// the runner can record how many requests a run really made.
func (e *Engine) get(ctx context.Context, client *http.Client, c Connector, u *url.URL, onAttempt ...func()) ([]byte, http.Header, error) {
	if err := e.Policy.CheckURL(u); err != nil { // https, no credentials, no odd hosts
		return nil, nil, err
	}
	if err := egress.CheckPort(u, c.Request.AllowedPorts); err != nil { // 443 unless approved
		return nil, nil, err
	}
	for attempt := 1; ; attempt++ {
		for _, observe := range onAttempt {
			observe()
		}
		body, header, err := e.once(ctx, client, c, u)
		// Success, or the whole run has been cancelled / timed out: stop here.
		if err == nil || ctx.Err() != nil {
			return body, header, err
		}
		wait, retry := e.retryDelay(c.Retry, attempt, header, err)
		if !retry {
			return nil, header, err
		}
		e.Log.Warn("vendor request failed, retrying",
			"tenant", c.TenantID, "connector", c.ID, "url", RedactURL(u),
			"attempt", attempt, "wait", wait.String(), "error", err.Error())
		if err := e.sleep(ctx, wait); err != nil { // returns early if the run is cancelled
			return nil, nil, err
		}
	}
}

// retryDelay decides whether a failed attempt should be retried, and after
// how long. This is the single place where FR-7 (retries) and FR-8 (429) live.
//
//	never retried:  egress blocks, oversized responses, last attempt reached,
//	                401 / 403 / 404 and other 4xx (they won't fix themselves)
//	429:            wait exactly Retry-After (if it's within our max), else backoff
//	408, 5xx:       exponential backoff 1s, 2s, 4s...
//	network errors and timeouts: exponential backoff
func (e *Engine) retryDelay(r Retry, attempt int, header http.Header, err error) (time.Duration, bool) {
	if attempt >= r.MaxAttempts || errors.Is(err, egress.ErrBlocked) || errors.Is(err, ErrTooLarge) {
		return 0, false
	}
	// base << (attempt-1) doubles each time: 1s, 2s, 4s, ...
	backoff := time.Duration(r.BaseDelayMillis) * time.Millisecond << (attempt - 1)

	var se *StatusError
	if !errors.As(err, &se) {
		return backoff, true // not an HTTP status: timeout or network error
	}
	switch {
	case se.Code == http.StatusTooManyRequests: // 429
		if d, ok := parseRetryAfter(header.Get("Retry-After"), e.now()); ok {
			if d > time.Duration(r.MaxRetryAfterSeconds)*time.Second {
				return 0, false // vendor wants longer than one run should wait
			}
			return d, true
		}
		return backoff, true // 429 without Retry-After: fall back to backoff
	case se.Code == http.StatusRequestTimeout || se.Code >= 500: // 408, 5xx
		return backoff, true
	default:
		return 0, false
	}
}

// once makes exactly one HTTP attempt and returns the body (2xx only).
func (e *Engine) once(ctx context.Context, client *http.Client, c Connector, u *url.URL) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: invalid URL")
	}
	// Non-secret headers from the config (validation already rejected
	// anything that looks like a credential).
	for k, v := range c.Request.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "ConfigBridge/0.1")

	// Attach credentials (checks secret-to-host binding first).
	if err := e.authorize(ctx, client, c, req); err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req) // egress-guarded client: IP check, no redirects
	if err != nil {
		return nil, nil, scrub(err, u) // remove full URL from the error text
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Read (and throw away) a little of the body so the connection can be
		// reused, but never more than 64 KB.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode == http.StatusUnauthorized && c.Auth.Type == "oauth2_client_credentials" {
			e.dropToken(c) // token rejected: fetch a fresh one next time
		}
		return nil, resp.Header, &StatusError{Code: resp.StatusCode}
	}

	body, err := readLimited(resp.Body, c.Limits.MaxResponseBytes)
	if err != nil {
		return nil, resp.Header, scrub(err, u)
	}
	return body, resp.Header, nil
}

// logFailure records a failed request.
//
// Egress blocks are SECURITY EVENTS: logged at ERROR with a fixed
// event="egress_blocked" field, so log-based alerting can match on it.
// A block can mean a misconfigured connector or someone trying to misuse one.
func (e *Engine) logFailure(c Connector, u *url.URL, err error) {
	if errors.Is(err, egress.ErrBlocked) {
		e.Log.Error("egress blocked",
			"event", "egress_blocked",
			"tenant", c.TenantID, "connector", c.ID,
			"url", RedactURL(u), "reason", err.Error())
		return
	}
	e.Log.Warn("vendor request failed",
		"event", "vendor_request_failed",
		"tenant", c.TenantID, "connector", c.ID, "url", RedactURL(u), "error", err.Error())
}

// readLimited reads at most max bytes. It reads one extra byte to detect
// "too big" without loading the whole oversized body into memory.
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

// decodeItems parses the JSON body and returns:
//   - payload: the whole decoded response (needed to read cursors)
//   - items:   the record array found at path ("" = the response itself)
func decodeItems(body []byte, path string) (any, []any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep numbers exact (json.Number) instead of float64
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return nil, nil, errors.New("response is not valid JSON") // no body content in the error
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, nil, errors.New("response has trailing JSON content")
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

// getPath follows a dotted path through decoded JSON.
//
//	getPath(v, "data.items")    -> v["data"]["items"]
//	getPath(v, "results.0.id")  -> v["results"][0]["id"]
//	getPath(v, "")              -> v
func getPath(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	for _, part := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any: // JSON object: look up the key
			next, ok := t[part]
			if !ok {
				return nil, false
			}
			v = next
		case []any: // JSON array: the part must be a valid index
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			v = t[i]
		default: // string/number/bool/null: can't go deeper
			return nil, false
		}
	}
	return v, true
}

// nextLink finds the rel="next" URL in HTTP Link headers (RFC 8288), e.g.
//
//	Link: <https://api.github.com/x?page=2>; rel="next", <...?page=9>; rel="last"
//
// returns "https://api.github.com/x?page=2". Returns "" if there's no next.
func nextLink(values []string) string {
	for _, v := range values {
		for _, part := range splitLinks(v) { // each "<url>; params" entry
			segs := strings.Split(part, ";")
			target := strings.TrimSpace(segs[0]) // "<url>"
			if len(target) < 2 || target[0] != '<' || target[len(target)-1] != '>' {
				continue
			}
			for _, s := range segs[1:] { // params like rel="next"
				k, val, ok := strings.Cut(strings.TrimSpace(s), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "rel") {
					continue
				}
				// rel can hold several space-separated values: rel="next last"
				for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(val), `"`)) {
					if strings.EqualFold(rel, "next") {
						return target[1 : len(target)-1] // strip < >
					}
				}
			}
		}
	}
	return ""
}

// splitLinks splits a Link header on commas that are OUTSIDE <...>,
// because URLs themselves may contain commas.
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
			if depth == 0 { // a separator, not part of a URL
				parts = append(parts, v[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, v[start:])
}

// parseRetryAfter reads a Retry-After header, which comes in two forms:
//
//	Retry-After: 30                              (seconds)
//	Retry-After: Wed, 21 Oct 2026 07:28:00 GMT   (a date)
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true // a date in the past means "retry now"
	}
	return 0, false
}

// sleepCtx waits for d, but returns early if ctx is cancelled (run timeout).
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
