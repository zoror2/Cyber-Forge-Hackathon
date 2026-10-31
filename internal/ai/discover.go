package ai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"configbridge/internal/egress"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
)

// Name-only drafting: the customer types just a product name. One Gemini call
// with Google Search finds the vendor's official API reference pages plus the
// exact dataset heading and access scope they use. Those then go through the
// ordinary documented flow: the backend fetches the pages itself and every
// execution setting must cite them (verifyDocumentation). Search output is
// only ever a list of candidate references, never trusted as config.

// ErrSearchRequired: name-only drafting needs a provider with web search.
var ErrSearchRequired = fmt.Errorf("%w: typing only a product name needs CB_AI_PROVIDER=gemini (web search); otherwise add public API documentation URLs, dataset and scope", ErrDocumentation)

// nameOnly: nothing but the product (and optionally the OCSF class) supplied.
func (r Request) nameOnly() bool {
	return r.Profile == "" && r.Dataset == "" && r.Scope == "" && len(r.DocumentationURLs) == 0
}

type discovery struct {
	urls           []string
	dataset, scope string
}

var discoveryLine = regexp.MustCompile(`(?im)^\s*[-*]?\s*(URL|DATASET|SCOPE)\s*:\s*(.+?)\s*$`)
var scopes = map[string]bool{"public": true, "repository": true, "organization": true, "account": true, "enterprise": true}

// parseDiscovery reads the labelled lines; anything else in the answer is ignored.
func parseDiscovery(text string) (discovery, error) {
	var d discovery
	seen := map[string]bool{}
	for _, m := range discoveryLine.FindAllStringSubmatch(text, -1) {
		v := strings.Trim(m[2], " `*\"'<>")
		switch strings.ToUpper(m[1]) {
		case "URL":
			if !seen[v] && len(d.urls) < 3 && publicDocURL(v) {
				seen[v] = true
				d.urls = append(d.urls, v)
			}
		case "DATASET":
			if d.dataset == "" && len(v) >= 2 && len(v) <= 200 {
				d.dataset = v
			}
		case "SCOPE":
			if s := strings.ToLower(v); d.scope == "" && scopes[s] {
				d.scope = s
			}
		}
	}
	// URLs may still come from search grounding; the model must name the
	// dataset and scope (it answers "URL: none" alone when it found nothing).
	if d.dataset == "" || d.scope == "" {
		return d, errNoReference
	}
	return d, nil
}

var errNoReference = fmt.Errorf("%w: web search found no usable official API reference for this product; add its documentation URL", ErrDocumentation)

const groundingHost = "vertexaisearch.cloud.google.com"

// resolveGrounding turns Google's grounding redirect into the page search
// actually visited, reading only the Location header (never following it).
// The result passes the same public-only checks as any reference.
func resolveGrounding(ctx context.Context, raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() != groundingHost {
		if publicDocURL(raw) {
			return raw
		}
		return ""
	}
	cl := (egress.Policy{}).Client(10 * time.Second)
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer cl.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return ""
	}
	res, e := cl.Do(req)
	if e != nil {
		return ""
	}
	res.Body.Close()
	l, e := url.Parse(res.Header.Get("Location"))
	if e != nil {
		return ""
	}
	l.RawQuery = "" // tracking parameters; references must be query-free
	if publicDocURL(l.String()) {
		return l.String()
	}
	return ""
}

// fetchSome keeps the first three references that load; dead links are skipped.
func (c *Client) fetchSome(ctx context.Context, urls []string) (map[string]string, []string, error) {
	fetch := c.FetchDocumentation
	if fetch == nil {
		fetch = readPublicDocumentation
	}
	docs, kept := map[string]string{}, []string{}
	last := errNoReference
	for _, u := range urls {
		if len(kept) == 3 {
			break
		}
		text, e := fetch(ctx, u)
		if e != nil {
			last = e
			continue
		}
		if text = compact(text); len(text) > maxDocumentationText {
			text = strings.Clone(text[:maxDocumentationText])
		}
		docs[u], kept = text, append(kept, u)
	}
	if len(kept) == 0 {
		return nil, nil, last
	}
	return docs, kept, nil
}

func (c *Client) discover(ctx context.Context, r Request, used *meter) (discovery, error) {
	data := "the main security dataset every customer has on the standard plan (users, devices, logins or findings)"
	if !r.Auto() {
		data = "records for the OCSF class " + r.Data
	}
	q := "Product: " + strings.TrimSpace(r.Product) + "\nData wanted: " + data + `
Search the vendor's CURRENT official API documentation. Find the read-only REST GET endpoint that lists that data.
Answer with exactly these lines and nothing else:
URL: <the official reference page for that endpoint, on the vendor's own documentation site; the page must show the route, authentication and a JSON response example>
URL: <optional second official page, e.g. the authentication or pagination page>
DATASET: <the endpoint's heading copied verbatim from that page, e.g. List users>
SCOPE: <one word that appears on that page describing what it lists across: public, repository, organization, account or enterprise>
Never invent a URL. If you cannot find an official page, answer: URL: none`
	body := map[string]any{
		"contents":         []map[string]any{{"role": "user", "parts": []map[string]any{{"text": q}}}},
		"tools":            []map[string]any{{"google_search": map[string]any{}}},
		"generationConfig": map[string]any{"thinkingConfig": map[string]any{"thinkingLevel": "low"}},
	}
	var text string
	var grounded []string
	e := c.retry(ctx, func() (time.Duration, error) {
		grounded = grounded[:0]
		t, u, wait, e := c.geminiGrounded(ctx, body, &grounded)
		used.add(u)
		text = t
		return wait, e
	})
	if e != nil {
		return discovery{}, e
	}
	if c.debugDiscovery != nil {
		c.debugDiscovery(text)
	}
	d, e := parseDiscovery(text)
	if e != nil {
		return d, e
	}
	// Then the pages Google Search actually returned: real pages, unlike a URL
	// the model typed (which can be a plausible 404).
	seen := map[string]bool{}
	for _, u := range d.urls {
		seen[u] = true
	}
	for _, g := range grounded {
		if u := resolveGrounding(ctx, g); u != "" && !seen[u] && len(d.urls) < 6 {
			seen[u] = true
			d.urls = append(d.urls, u)
		}
	}
	if len(d.urls) == 0 {
		return d, errNoReference
	}
	return d, nil
}

// site is the registrable domain, approximately: the last two labels, or three
// under a two-letter ccTLD with a short second level (example.co.uk).
func site(host string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && len(labels[len(labels)-2]) <= 3 {
		n = 3
	}
	if len(labels) < n {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// sameSite: a search result can be a lookalike page; the API it describes must
// belong to the same organisation as at least one cited reference. Customer
// specific hosts (your-tenant...) are filled in locally and cannot be compared.
func sameSite(apiURL string, refs []string) bool {
	u, e := url.Parse(apiURL)
	if e != nil {
		return false
	}
	if strings.Contains(u.Host, "your-") {
		return true
	}
	for _, ref := range refs {
		if r, e := url.Parse(ref); e == nil && site(r.Hostname()) == site(u.Hostname()) {
			return true
		}
	}
	return false
}

func (c *Client) discoveredDraft(ctx context.Context, r Request) (*Draft, error) {
	if !c.gemini {
		return nil, ErrSearchRequired
	}
	var used meter
	found, e := c.discover(ctx, r, &used)
	if e != nil {
		return nil, e
	}
	r.Dataset, r.Scope = found.dataset, found.scope
	if r.documents, r.DocumentationURLs, e = c.fetchSome(ctx, found.urls); e != nil {
		return nil, e
	}
	d, e := c.documentedDraft(ctx, r)
	var bad *InvalidDraft
	switch {
	case errors.As(e, &bad):
		bad.Usage = plus(used, bad.Usage)
		return nil, bad
	case e != nil:
		return nil, e
	}
	d.Usage = plus(used, d.Usage)
	if d.Contract == nil || !sameSite(d.Contract.Endpoint, d.Sources) {
		return nil, &InvalidDraft{Issues: []config.Issue{{Field: "request.url", Message: "the API host does not belong to the same site as the documentation web search found; add the vendor's official documentation URL"}}, Usage: d.Usage}
	}
	d.Notes = append([]string{"Found from the product name by web search: " + strings.Join(found.urls, ", ") + ". Check these are the vendor's official pages before activating."}, d.Notes...)
	return d, nil
}

// plus adds a draft's usage to the discovery call's; unknown stays unknown.
func plus(m meter, u insights.Usage) insights.Usage {
	m.add(u)
	return m.total()
}
