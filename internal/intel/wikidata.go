// Package intel builds a vendor ownership map: the vendor, the companies it
// owns (from Wikidata, structured and dated), and later the actively
// exploited CVEs and reported attacks per company.
package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"configbridge/internal/egress"
)

// Company is one node of the map.
type Company struct {
	Name   string `json:"name"`
	QID    string `json:"qid,omitempty"`   // Wikidata id
	Since  string `json:"since,omitempty"` // year it became part of the vendor, if recorded
	Source string `json:"source"`          // wikidata | cited (AI-found, quote verified)
	URL    string `json:"url,omitempty"`   // evidence page for cited companies
	Quote  string `json:"quote,omitempty"`
}

var ErrNotFound = errors.New("vendor_not_found")

const sparqlURL = "https://query.wikidata.org/sparql"

// Endpoint is a test seam.
var Endpoint = sparqlURL

func query(ctx context.Context, q string) ([]map[string]map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", Endpoint+"?query="+url.QueryEscape(q), nil)
	if e != nil {
		return nil, e
	}
	// Wikidata asks every client to identify itself.
	req.Header.Set("User-Agent", "ConfigBridge/0.1 (vendor ownership map)")
	req.Header.Set("Accept", "application/sparql-results+json")
	cl := (egress.Policy{}).Client(45 * time.Second)
	if strings.HasPrefix(Endpoint, "http://127.0.0.1") {
		cl = &http.Client{Timeout: 10 * time.Second} // tests only
	}
	defer cl.CloseIdleConnections()
	res, e := cl.Do(req)
	if e != nil {
		return nil, fmt.Errorf("wikidata unreachable")
	}
	defer res.Body.Close()
	if res.StatusCode == 429 {
		return nil, fmt.Errorf("Wikidata is rate-limiting requests; try again in a minute")
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("wikidata HTTP %d", res.StatusCode)
	}
	var out struct {
		Results struct {
			Bindings []map[string]map[string]string `json:"bindings"`
		} `json:"results"`
	}
	if e := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&out); e != nil {
		return nil, fmt.Errorf("wikidata answer unreadable")
	}
	return out.Results.Bindings, nil
}

func qid(uri string) string { return uri[strings.LastIndex(uri, "/")+1:] }

var validQID = regexp.MustCompile(`^Q[0-9]{1,12}$`)

// sparqlString escapes a value for a SPARQL string literal.
func sparqlString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ").Replace(s)
}

// Subsidiaries finds the vendor (a business, best search match) and the
// companies Wikidata records it currently owns ("subsidiary" / "parent
// organization" with no end date). Patents and other owned things are not
// companies and are left out.
func Subsidiaries(ctx context.Context, vendor string) (Company, []Company, error) {
	vendor = strings.TrimSpace(vendor)
	if len(vendor) < 2 || len(vendor) > 100 {
		return Company{}, nil, ErrNotFound
	}
	// Wikidata rate-limits (HTTP 429); ownership changes rarely, so cache.
	key := strings.ToLower(vendor)
	cacheMu.Lock()
	hit, ok := cache[key]
	cacheMu.Unlock()
	if ok && time.Since(hit.at) < 6*time.Hour {
		return hit.root, hit.subs, nil
	}
	root, subs, e := lookup(ctx, vendor)
	if e == nil {
		cacheMu.Lock()
		if len(cache) > 500 {
			cache = map[string]cached{}
		}
		cache[key] = cached{time.Now(), root, subs}
		cacheMu.Unlock()
	}
	return root, subs, e
}

type cached struct {
	at   time.Time
	root Company
	subs []Company
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cached{}
)

func lookup(ctx context.Context, vendor string) (Company, []Company, error) {
	rows, e := query(ctx, `SELECT ?org ?orgLabel WHERE {
  SERVICE wikibase:mwapi { bd:serviceParam wikibase:api "EntitySearch"; wikibase:endpoint "www.wikidata.org"; mwapi:search "`+sparqlString(vendor)+`"; mwapi:language "en". ?org wikibase:apiOutputItem mwapi:item. ?num wikibase:apiOrdinal true. }
  ?org wdt:P31/wdt:P279* wd:Q4830453.
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
} ORDER BY ?num LIMIT 1`)
	if e != nil {
		return Company{}, nil, e
	}
	if len(rows) == 0 {
		return Company{}, nil, ErrNotFound
	}
	root := Company{Name: rows[0]["orgLabel"]["value"], QID: qid(rows[0]["org"]["value"]), Source: "wikidata"}
	// the id goes into the next query unquoted: accept only a Wikidata item id
	if !validQID.MatchString(root.QID) {
		return Company{}, nil, ErrNotFound
	}
	rows, e = query(ctx, `SELECT DISTINCT ?sub ?subLabel ?start WHERE {
  { wd:`+root.QID+` p:P355 ?st. ?st ps:P355 ?sub. } UNION { ?sub p:P749 ?st. ?st ps:P749 wd:`+root.QID+`. }
  FILTER NOT EXISTS { ?sub wdt:P31 wd:Q253623 }
  OPTIONAL { ?st pq:P580 ?start }
  FILTER NOT EXISTS { ?st pq:P582 ?end }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}`)
	if e != nil {
		return root, nil, e
	}
	seen := map[string]*Company{}
	for _, r := range rows {
		name := r["subLabel"]["value"]
		id := qid(r["sub"]["value"])
		if name == "" || name == id { // no English label
			continue
		}
		c := seen[id]
		if c == nil {
			c = &Company{Name: name, QID: id, Source: "wikidata"}
			seen[id] = c
		}
		if s := r["start"]["value"]; len(s) >= 4 && (c.Since == "" || s[:4] < c.Since) {
			c.Since = s[:4]
		}
	}
	subs := make([]Company, 0, len(seen))
	for _, c := range seen {
		subs = append(subs, *c)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	return root, subs, nil
}
