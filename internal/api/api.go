// Package api derives tenant identity from hashed API keys for every endpoint.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"configbridge/internal/ai"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"configbridge/pkg/secrets"
)

type API struct {
	Store   *store.Store
	Engine  *runner.Runner
	Secrets *secrets.Service
	// Test seam only; the binary always uses Store.Authenticate.
	Authenticate func(context.Context, string) (string, error)
	// Limits for this API; nil means DefaultLimits.
	Limits *Limits
	// AI drafts configs; nil or no key = POST /ai/draft answers 503.
	AI *ai.Client
}

type tenantKey struct{}

func (a *API) scope(r *http.Request) store.Scope {
	return a.Store.ForTenant(r.Context().Value(tenantKey{}).(string))
}
func New(a *API) (http.Handler, error) {
	lookup := a.Authenticate
	if lookup == nil {
		if a.Store == nil {
			return nil, errors.New("authentication store required")
		}
		lookup = a.Store.Authenticate
	}
	lim, rl, keys := newLimiter(), DefaultLimits, newKeyCache(30*time.Second)
	if a.Limits != nil {
		rl = *a.Limits
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /configs", a.listConfigs)
	mux.HandleFunc("GET /configs/{id}", a.getConfig)
	mux.HandleFunc("POST /configs", a.submit)
	mux.HandleFunc("POST /configs/{id}/validate", a.validate)
	mux.HandleFunc("POST /configs/{id}/activate", a.activate)
	mux.HandleFunc("PUT /secrets/{name}", a.putSecret)
	mux.HandleFunc("GET /secrets", a.listSecrets)
	mux.HandleFunc("POST /connectors/{id}/test", a.test)
	mux.HandleFunc("POST /connectors/{id}/run", a.run)
	mux.HandleFunc("GET /runs", a.runs)
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /records/{class}", a.records)
	mux.HandleFunc("GET /quarantine", a.quarantine)
	mux.HandleFunc("GET /schema/{view}", a.prdView)
	mux.HandleFunc("POST /ai/draft", a.aiDraft)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		ip := clientIP(r)
		supplied := r.Header.Get("Authorization")
		token := strings.TrimPrefix(supplied, "Bearer ")
		well := strings.HasPrefix(supplied, "Bearer ") && len(token) >= 32 && len(token) <= 512
		key := keyID(token)
		// A key verified in the last 30 s skips the per-IP gates, so junk-key
		// floods or a noisy neighbour behind the same IP/NAT can't lock it out.
		// It is still authenticated against the database on every request, so a
		// revoked key stops working immediately.
		if _, known := keys.get(key); known {
			if ok, retry := lim.take("vip:"+ip, rl.VerifiedIP); !ok {
				limited(w, retry)
				return
			}
		} else {
			// An IP that keeps failing authentication is refused before any key lookup.
			if ok, retry := lim.peek("fail:"+ip, rl.FailedPerIP); !ok {
				limited(w, retry)
				return
			}
			if ok, retry := lim.take("ip:"+ip, rl.PerIP); !ok {
				limited(w, retry)
				return
			}
		}
		var tenant string
		if well {
			tenant, _ = lookup(r.Context(), token)
		}
		if config.ValidID(tenant) {
			keys.put(key, tenant)
		} else {
			keys.drop(key)
			lim.take("fail:"+ip, rl.FailedPerIP)
			w.Header().Set("WWW-Authenticate", "Bearer")
			fail(w, 401, "unauthorized")
			return
		}
		if ok, retry := lim.take("key:"+key, rl.PerKey); !ok {
			limited(w, retry)
			return
		}
		// runs/tests call the vendor and AI drafts call the model: both are costly
		if r.Method == http.MethodPost && (r.URL.Path == "/ai/draft" || strings.HasPrefix(r.URL.Path, "/connectors/") &&
			(strings.HasSuffix(r.URL.Path, "/run") || strings.HasSuffix(r.URL.Path, "/test"))) {
			if ok, retry := lim.take("run:"+key, rl.RunPerKey); !ok {
				limited(w, retry)
				return
			}
		}
		if !sameOrigin(r) {
			fail(w, 403, "browser_cross_origin_requests_disabled")
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey{}, tenant)))
	}), nil
}

// sameOrigin allows non-browser clients (no Origin) and the bundled UI served
// from this host. Browsers set Sec-Fetch-Site/Origin themselves; page scripts
// cannot forge them. Auth is a bearer header, never a cookie, so this is
// defence in depth, not the CSRF control.
func sameOrigin(r *http.Request) bool {
	site, origin := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin")
	if origin == "" {
		return site != "cross-site" && site != "same-site"
	}
	u, e := url.Parse(origin)
	return e == nil && site == "same-origin" && u.Host == r.Host && (u.Scheme == "http" || u.Scheme == "https")
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, category string) {
	write(w, status, map[string]string{"error": category})
}
func dbFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, 404, "config_not_found_or_not_live")
	case errors.Is(err, store.ErrBusy):
		fail(w, 409, "connector_busy")
	default:
		fail(w, 503, "storage_unavailable")
	}
}
func jsonBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil || config.CheckJSON(body) != nil {
		fail(w, 400, "invalid_json_body")
		return false
	}
	d := json.NewDecoder(strings.NewReader(string(body)))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		fail(w, 400, "invalid_json_body")
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, 400, "one_json_object_required")
		return false
	}
	return true
}
func paging(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	limit, offset := 100, 0
	var err error
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			fail(w, 400, "invalid_pagination")
			return 0, 0, false
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			fail(w, 400, "invalid_pagination")
			return 0, 0, false
		}
	}
	if limit < 1 || limit > 500 || offset < 0 || offset > 1000000 {
		fail(w, 400, "invalid_pagination")
		return 0, 0, false
	}
	return limit, offset, true
}
func (a *API) submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxBytes)
	b, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 413, "config_too_large")
		return
	}
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		write(w, 422, map[string]any{"errors": issues})
		return
	}
	saved, e := a.scope(r).SaveConfig(r.Context(), c)
	if e != nil {
		dbFail(w, e)
		return
	}
	code := 201
	if saved.Unchanged {
		code = 200
	}
	write(w, code, map[string]any{"id": c.ID, "revision": saved.Revision, "status": saved.Status, "hash": saved.Hash, "unchanged": saved.Unchanged})
}
func (a *API) listConfigs(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	data, e := a.scope(r).Configs(r.Context(), l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, data)
}
func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	if !config.ValidID(r.PathValue("id")) {
		fail(w, 404, "config_not_found_or_not_live")
		return
	}
	s, e := a.scope(r).Config(r.Context(), r.PathValue("id"), false)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, s)
}
func (a *API) validate(w http.ResponseWriter, r *http.Request) {
	s, e := a.scope(r).Config(r.Context(), r.PathValue("id"), false)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, map[string]any{"errors": s.Config.Validate(), "warnings": a.secretWarnings(r, s.Config)})
}

// secretWarnings catches the config/secret mismatches that otherwise only show
// up at run time as credential_missing or credential_binding_mismatch. Warnings,
// not errors: a config may legitimately be written before its secret is stored.
func (a *API) secretWarnings(r *http.Request, c config.Config) []config.Issue {
	out := []config.Issue{}
	if c.Auth.Type == "" || c.Auth.Type == "none" || a.Secrets == nil {
		return out
	}
	list, e := a.Secrets.List(r.Context(), a.scope(r).Tenant, 500, 0)
	if e != nil {
		return append(out, config.Issue{Field: "auth.secret", Message: "secret store unavailable; could not check"})
	}
	hosts := map[string]string{}
	for _, m := range list {
		hosts[m.Name] = m.AllowedHost
	}
	host := func(raw string) string {
		u, e := url.Parse(raw)
		if e != nil {
			return ""
		}
		return u.Host
	}
	want := host(c.Request.URL)
	if c.Auth.Type == "oauth2_client_credentials" {
		want = host(c.Auth.TokenURL) // the client secret is only ever sent to the token endpoint
	}
	bound, ok := hosts[c.Auth.Secret]
	switch {
	case !ok:
		msg := "secret " + strconv.Quote(c.Auth.Secret) + " is not stored"
		// suggest the stored secret for this host whose name is closest to the typo
		best, bestD := "", 1<<30
		for name, h := range hosts {
			if d := editDistance(name, c.Auth.Secret); h == want && (d < bestD || d == bestD && name < best) {
				best, bestD = name, d
			}
		}
		if best != "" {
			msg += "; stored secret " + strconv.Quote(best) + " is bound to " + want + ", did you mean it?"
		}
		out = append(out, config.Issue{Field: "auth.secret", Message: msg})
	case bound != want:
		out = append(out, config.Issue{Field: "auth.secret", Message: "secret " + strconv.Quote(c.Auth.Secret) + " is bound to " + bound + " but this config calls " + want + "; the run would fail with credential_binding_mismatch"})
	}
	return out
}

// editDistance is the Levenshtein distance (names are short, so O(n*m) is fine).
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
func (a *API) activate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision int `json:"revision"`
	}
	if !jsonBody(w, r, &body) {
		return
	}
	if body.Revision < 1 {
		fail(w, 400, "revision_required")
		return
	}
	if e := a.scope(r).Activate(r.Context(), r.PathValue("id"), body.Revision); e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, map[string]any{"id": r.PathValue("id"), "revision": body.Revision, "status": "live"})
}
func (a *API) putSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string `json:"value"`
		Host  string `json:"allowed_host"`
	}
	if !jsonBody(w, r, &body) {
		return
	}
	// Name the bad field (never echo the value).
	for _, c := range []struct {
		bad   bool
		field string
	}{
		{!config.ValidID(r.PathValue("name")), "name: lowercase a-z 0-9 _ - only, e.g. nvd_key"},
		{!config.ValidHost(body.Host), "allowed_host: bare lowercase host only, e.g. services.nvd.nist.gov (no https://, path or spaces)"},
		{body.Value == "" || len(body.Value) > 32768, "value: required, at most 32768 bytes"},
	} {
		if c.bad {
			write(w, 422, map[string]string{"error": "invalid_secret_input", "detail": c.field})
			return
		}
	}
	e := a.Secrets.Put(r.Context(), a.scope(r).Tenant, r.PathValue("name"), body.Value, body.Host)
	if errors.Is(e, secrets.ErrBinding) {
		fail(w, 409, "host_binding_is_immutable")
		return
	}
	if e != nil {
		fail(w, 503, "secret_backend_unavailable")
		return
	}
	w.WriteHeader(204)
}
func (a *API) listSecrets(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	data, e := a.Secrets.List(r.Context(), a.scope(r).Tenant, l, o)
	if e != nil {
		fail(w, 503, "secret_backend_unavailable")
		return
	}
	write(w, 200, data)
}

// aiDraft returns an UNSAVED config drafted by the model and already passed
// through the platform validator. Only secret names/hosts reach the model.
func (a *API) aiDraft(w http.ResponseWriter, r *http.Request) {
	var req ai.Request
	if !jsonBody(w, r, &req) {
		return
	}
	if e := req.Check(); e != nil {
		write(w, 400, map[string]string{"error": "invalid_ai_request", "detail": e.Error()})
		return
	}
	var secrets []ai.Secret
	if a.Secrets != nil {
		list, e := a.Secrets.List(r.Context(), a.scope(r).Tenant, 200, 0)
		if e != nil {
			fail(w, 503, "secret_backend_unavailable")
			return
		}
		for _, m := range list {
			secrets = append(secrets, ai.Secret{Name: m.Name, Host: m.AllowedHost})
		}
	}
	d, e := a.AI.Draft(r.Context(), req, secrets)
	var bad *ai.InvalidDraft
	switch {
	case e == nil:
		write(w, 200, d)
	case errors.Is(e, ai.ErrNotConfigured):
		fail(w, 503, "ai_not_configured")
	case errors.As(e, &bad):
		write(w, 422, map[string]any{"error": "ai_draft_invalid", "issues": bad.Issues, "config": bad.Last})
	default:
		write(w, 502, map[string]string{"error": "ai_provider_failed", "detail": strings.TrimPrefix(e.Error(), ai.ErrUpstream.Error()+": ")})
	}
}
func (a *API) run(w http.ResponseWriter, r *http.Request)  { a.execute(w, r, false) }
func (a *API) test(w http.ResponseWriter, r *http.Request) { a.execute(w, r, true) }
func (a *API) execute(w http.ResponseWriter, r *http.Request, test bool) {
	// Arbitrary request-body configs cannot bypass the stored-live-config rule.
	b, e := io.ReadAll(io.LimitReader(r.Body, 2))
	if e != nil || len(b) > 0 {
		fail(w, 400, "run_body_must_be_empty")
		return
	}
	result, e := a.Engine.Run(r.Context(), a.scope(r).Tenant, r.PathValue("id"), test, false)
	if e != nil && result.ID == "" {
		dbFail(w, e)
		return
	}
	status := 200
	if e != nil {
		status = 502
	}
	write(w, status, result)
}
func (a *API) runs(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("connector")
	if !a.checkFilter(w, r, id) {
		return
	}
	data, e := a.scope(r).Runs(r.Context(), id, l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, data)
}
func (a *API) records(w http.ResponseWriter, r *http.Request) {
	class, ok := ocsf.Lookup(r.PathValue("class"))
	if !ok {
		fail(w, 404, "unknown_ocsf_class")
		return
	}
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	source := r.URL.Query().Get("source")
	if !a.checkFilter(w, r, source) {
		return
	}
	data, e := a.scope(r).Records(r.Context(), class.UID, source, l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, data)
}

// prdView serves the PRD common schema (users/devices/events) over the OCSF store.
func (a *API) prdView(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	source := r.URL.Query().Get("source")
	if !a.checkFilter(w, r, source) {
		return
	}
	data, e := a.scope(r).View(r.Context(), r.PathValue("view"), source, l, o)
	if errors.Is(e, store.ErrNotFound) {
		fail(w, 404, "unknown_view")
		return
	}
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, data)
}
func (a *API) quarantine(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("connector")
	if !a.checkFilter(w, r, id) {
		return
	}
	data, e := a.scope(r).Quarantine(r.Context(), id, l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, data)
}

var healthPage = template.Must(template.New("health").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>ConfigBridge health</title><h1>Connection health</h1><table><thead><tr><th>Connection</th><th>Status</th><th>Last attempt</th><th>Last clean success</th><th>Accepted last run</th><th>Error</th></tr></thead><tbody>{{range .}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.LastRun}}</td><td>{{.LastSuccess}}</td><td>{{.Accepted}}</td><td>{{.Error}}</td></tr>{{else}}<tr><td>No live connections</td></tr>{{end}}</tbody></table></html>`))

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	data, e := a.scope(r).Health(r.Context(), l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		healthPage.Execute(w, data)
		return
	}
	write(w, 200, data)
}
func (a *API) checkFilter(w http.ResponseWriter, r *http.Request, id string) bool {
	if id == "" {
		return true
	}
	if _, e := a.scope(r).Config(r.Context(), id, false); e != nil {
		dbFail(w, e)
		return false
	}
	return true
}
