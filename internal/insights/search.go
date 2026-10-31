package insights

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Search interface {
	Index(context.Context, string, Snapshot) error
	Find(context.Context, string, Snapshot, string) ([]string, error)
}
type OpenSearch struct {
	base      string
	namespace string
	user      string
	password  func() string
	client    *http.Client
}

func NewSearch(endpoint, user, password, environment, namespace string, roots *x509.CertPool) (*OpenSearch, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrSearch
	}
	if u.Scheme != "https" {
		ip, err := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || environment != "dev" || err != nil || !ip.IsLoopback() || user != "" || password != "" {
			return nil, ErrSearch
		}
	}
	if (user == "") != (password == "") || strings.ContainsAny(user, "\r\n") {
		return nil, ErrSearch
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConnsPerHost: 2}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrSearch }}
	if namespace == "" {
		namespace = "configbridge"
	}
	if len(namespace) > 128 {
		return nil, ErrSearch
	}
	return &OpenSearch{base: strings.TrimRight(endpoint, "/"), namespace: namespace, user: user, password: func() string { return password }, client: client}, nil
}
func (s *OpenSearch) request(ctx context.Context, method, path string, body []byte, ndjson bool) ([]byte, int, error) {
	r, e := http.NewRequestWithContext(ctx, method, s.base+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrSearch
	}
	r.Header.Set("Content-Type", "application/json")
	if ndjson {
		r.Header.Set("Content-Type", "application/x-ndjson")
	}
	if s.user != "" {
		r.SetBasicAuth(s.user, s.password())
	}
	resp, e := s.client.Do(r)
	if e != nil {
		return nil, 0, ErrSearch
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, resp.StatusCode, ErrSearch
	}
	return raw, resp.StatusCode, nil
}
func (s *OpenSearch) indexName(tenant string) string {
	return "cb-siem-v1-" + Hash(s.namespace+"/"+tenant)
}
func (s *OpenSearch) Index(ctx context.Context, tenant string, snap Snapshot) error {
	properties := map[string]any{}
	for _, k := range []string{"id", "tenant_hash", "connector_hash", "generation", "rule", "topic", "severity", "category"} {
		properties[k] = map[string]string{"type": "keyword"}
	}
	properties["count"] = map[string]string{"type": "long"}
	properties["observed_at"] = map[string]string{"type": "date"}
	body, _ := json.Marshal(map[string]any{"settings": map[string]any{"number_of_shards": 1, "number_of_replicas": 0}, "mappings": map[string]any{"dynamic": "strict", "properties": properties}})
	name := s.indexName(tenant)
	raw, status, e := s.request(ctx, "PUT", "/"+name, body, false)
	if e != nil {
		return e
	}
	if status != 200 {
		var result struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		if status != 400 || json.Unmarshal(raw, &result) != nil || result.Error.Type != "resource_already_exists_exception" {
			return ErrSearch
		}
	}
	if len(snap.Findings) == 0 {
		return nil
	}
	var bulk bytes.Buffer
	for _, f := range snap.Findings {
		rule, ok := RuleByID(f.Rule)
		if !ok || !Category(f.Category) || f.Severity != rule.Severity || f.Count < 1 || len(f.ID) != 64 || f.Generation != snap.Generation || f.Connector != snap.Connector {
			return ErrEvidence
		}
		json.NewEncoder(&bulk).Encode(map[string]any{"index": map[string]string{"_id": f.ID}})
		json.NewEncoder(&bulk).Encode(map[string]any{"id": f.ID, "tenant_hash": Hash(tenant), "connector_hash": Hash(snap.Connector), "generation": snap.Generation, "rule": f.Rule, "topic": rule.Topic, "severity": f.Severity, "category": f.Category, "count": f.Count, "observed_at": f.ObservedAt})
	}
	raw, status, e = s.request(ctx, "POST", "/"+name+"/_bulk?refresh=wait_for", bulk.Bytes(), true)
	if e != nil || status != 200 {
		return ErrSearch
	}
	var result struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Errors || len(result.Items) != len(snap.Findings) {
		return ErrSearch
	}
	for _, item := range result.Items {
		v, ok := item["index"]
		if !ok || (v.Status != 200 && v.Status != 201) {
			return ErrSearch
		}
	}
	return nil
}
func (s *OpenSearch) Find(ctx context.Context, tenant string, snap Snapshot, topic string) ([]string, error) {
	if !Topic(topic) {
		return nil, ErrEvidence
	}
	filters := []any{}
	for k, v := range map[string]string{"tenant_hash": Hash(tenant), "connector_hash": Hash(snap.Connector), "generation": snap.Generation, "topic": topic} {
		filters = append(filters, map[string]any{"term": map[string]string{k: v}})
	}
	body, _ := json.Marshal(map[string]any{"size": 20, "timeout": "3s", "_source": []string{"id", "tenant_hash", "connector_hash", "generation"}, "query": map[string]any{"bool": map[string]any{"filter": filters}}, "sort": []any{map[string]string{"rule": "asc"}}})
	raw, status, e := s.request(ctx, "POST", "/"+s.indexName(tenant)+"/_search", body, false)
	if e != nil || status != 200 {
		return nil, ErrSearch
	}
	var result struct {
		TimedOut bool `json:"timed_out"`
		Shards   struct {
			Failed int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Hits []struct {
				Source struct {
					ID         string `json:"id"`
					Tenant     string `json:"tenant_hash"`
					Connector  string `json:"connector_hash"`
					Generation string `json:"generation"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(raw, &result) != nil || result.TimedOut || result.Shards.Failed != 0 || len(result.Hits.Hits) > 20 {
		return nil, ErrSearch
	}
	out := []string{}
	for _, hit := range result.Hits.Hits {
		f := hit.Source
		if len(f.ID) != 64 || f.Tenant != Hash(tenant) || f.Connector != Hash(snap.Connector) || f.Generation != snap.Generation {
			return nil, ErrEvidence
		}
		out = append(out, f.ID)
	}
	return out, nil
}
