// Package api derives tenant identity from hashed API keys for every endpoint.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"configbridge/internal/onboarding"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/incremental"
	"configbridge/pkg/secrets"
)

type API struct {
	Store               *store.Store
	Engine              *runner.Runner
	Secrets             *secrets.Service
	AI                  *Drafting
	SIEM                *SIEM
	NotificationTenants map[string]bool
	UI                  *onboarding.Console
	// Test seam only; the binary always uses Store.Authenticate.
	Authenticate func(context.Context, string) (string, error)
}

type tenantKey struct{}
type callerKey struct{}

func (a *API) scope(r *http.Request) store.Scope {
	return a.Store.ForTenant(r.Context().Value(tenantKey{}).(string))
}
func New(a *API) (http.Handler, error) {
	if a.Authenticate == nil {
		if a.Store == nil {
			return nil, errors.New("authentication store required")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /siem/refresh", a.siemRefresh)
	mux.HandleFunc("GET /siem/findings", a.siemFindings)
	mux.HandleFunc("POST /siem/ask", a.siemAsk)
	mux.HandleFunc("GET /ai/usage", a.aiUsage)
	mux.HandleFunc("GET /insights", a.insightsPage)
	mux.HandleFunc("GET /insights/style.css", a.insightsStyles)
	mux.HandleFunc("POST /insights/action", a.insightsAction)
	mux.HandleFunc("GET /onboarding", a.consoleForm)
	mux.HandleFunc("GET /onboarding/{$}", a.consoleForm)
	mux.HandleFunc("GET /onboarding/style.css", a.consoleCSS)
	mux.HandleFunc("POST /onboarding/generate", a.consoleGenerate)
	mux.HandleFunc("POST /onboarding/download", a.consoleDownload)
	mux.HandleFunc("POST /onboarding/save", a.consoleSave)
	mux.HandleFunc("POST /onboarding/test", a.consoleTest)
	mux.HandleFunc("POST /configs", a.submit)
	mux.HandleFunc("POST /configs/{id}/validate", a.validate)
	mux.HandleFunc("POST /configs/{id}/activate", a.activate)
	mux.HandleFunc("POST /configs/{id}/test", a.preview)
	mux.HandleFunc("PUT /secrets/{name}", a.putSecret)
	mux.HandleFunc("GET /secrets", a.listSecrets)
	mux.HandleFunc("POST /connectors/{id}/test", a.test)
	mux.HandleFunc("POST /connectors/{id}/run", a.run)
	mux.HandleFunc("GET /connectors/{id}/sync-state", a.syncState)
	mux.HandleFunc("GET /runs", a.runs)
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /records/{entity}", a.records)
	mux.HandleFunc("GET /quarantine", a.quarantine)
	mux.HandleFunc("GET /alerts", a.alerts)
	mux.HandleFunc("GET /exposure", a.exposure)
	mux.HandleFunc("GET /ai/sources", a.aiSources)
	mux.HandleFunc("POST /ai/config-draft", a.aiDraft)
	mux.HandleFunc("GET /ai/audit", a.aiAudit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		supplied := r.Header.Get("Authorization")
		token := strings.TrimPrefix(supplied, "Bearer ")
		consoleRequest := isConsole(r.URL.Path)
		bearer := strings.HasPrefix(supplied, "Bearer ")
		if consoleRequest && !bearer {
			user, password, ok := r.BasicAuth()
			if ok && user == "apikey" {
				token = password
				bearer = true
			}
		}
		var tenant string
		var caller store.Caller
		if bearer && len(token) >= 32 && len(token) <= 512 {
			if a.Authenticate != nil {
				tenant, _ = a.Authenticate(r.Context(), token)
				caller = store.Caller{Tenant: tenant, Actor: "test:principal"}
			} else {
				caller, _ = a.Store.AuthenticateCaller(r.Context(), token)
				tenant = caller.Tenant
			}
		}
		if !config.ValidID(tenant) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			if consoleRequest {
				w.Header().Set("WWW-Authenticate", `Basic realm="ConfigBridge local console", charset="UTF-8"`)
			}
			fail(w, 401, "unauthorized")
			return
		}
		if consoleRequest {
			if a.UI == nil {
				http.NotFound(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if !strings.EqualFold(r.Host, a.UI.Host) || r.Header.Get("Sec-Fetch-Site") == "cross-site" || (origin != "" && origin != a.UI.Origin) || (r.Method == "POST" && origin != a.UI.Origin) {
				fail(w, 403, "console_origin_denied")
				return
			}
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
			w.Header().Set("X-Frame-Options", "DENY")
			// Same-origin form navigations need their real Origin. Browsers can
			// send Origin:null under no-referrer; cross-origin referrers stay off.
			w.Header().Set("Referrer-Policy", "same-origin")
		} else if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "browser_cross_origin_requests_disabled")
			return
		}
		ctx := context.WithValue(r.Context(), tenantKey{}, tenant)
		mux.ServeHTTP(w, r.WithContext(context.WithValue(ctx, callerKey{}, caller)))
	}), nil
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
	case errors.Is(err, incremental.ErrState):
		fail(w, 503, "incremental_state_invalid")
	case errors.Is(err, incremental.ErrNotReady):
		fail(w, 409, "incremental_window_not_ready")
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
	if c.Notifications != nil && c.Notifications.Enabled && !a.NotificationTenants[a.scope(r).Tenant] {
		fail(w, 422, "email_notifications_not_configured_for_tenant")
		return
	}
	saved, e := a.scope(r).SaveConfig(r.Context(), c)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 201, map[string]any{"id": c.ID, "revision": saved.Revision, "status": saved.Status, "hash": saved.Hash})
}
func (a *API) validate(w http.ResponseWriter, r *http.Request) {
	s, e := a.scope(r).Config(r.Context(), r.PathValue("id"), false)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, map[string]any{"errors": s.Config.Validate()})
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
	var body secrets.Input
	if !jsonBody(w, r, &body) {
		return
	}
	if _, _, err := body.Normalize(); !config.ValidID(r.PathValue("name")) || err != nil {
		fail(w, 422, "invalid_secret_input")
		return
	}
	e := a.Secrets.PutCredential(r.Context(), r.Context().Value(callerKey{}).(store.Caller), r.PathValue("name"), body)
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
	entities := map[string]string{"users": "user", "devices": "device", "events": "event"}
	entity, ok := entities[r.PathValue("entity")]
	if !ok {
		fail(w, 404, "unknown_entity")
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
	data, e := a.scope(r).Records(r.Context(), entity, source, l, o)
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
