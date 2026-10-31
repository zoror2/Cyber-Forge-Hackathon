// Package api exposes Member B's admin-only Phase 1 interface.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/zoror2/Cyber-Forge-Hackathon/internal/engine"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/store"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/collector"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/secrets"
)

type API struct {
	Store   *store.Store
	Engine  *engine.Engine
	Secrets *secrets.Service
}

func New(a *API, token string) (http.Handler, error) {
	if len(token) < 32 {
		return nil, errors.New("admin token must have at least 32 characters")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /configs", a.submit)
	mux.HandleFunc("POST /configs/{id}/validate", a.validate)
	mux.HandleFunc("POST /configs/{id}/activate", a.activate)
	mux.HandleFunc("PUT /secrets/{name}", a.putSecret)
	mux.HandleFunc("GET /secrets", a.listSecrets)
	mux.HandleFunc("POST /connectors/{id}/test", a.test)
	mux.HandleFunc("POST /connectors/{id}/run", a.run)
	mux.HandleFunc("GET /runs", a.runs)
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /records/{entity}", a.records)
	mux.HandleFunc("GET /quarantine", a.quarantine)
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		supplied := r.Header.Get("Authorization")
		got := sha256.Sum256([]byte(strings.TrimPrefix(supplied, "Bearer ")))
		if !strings.HasPrefix(supplied, "Bearer ") || subtle.ConstantTimeCompare(expected[:], got[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			fail(w, 401, "unauthorized")
			return
		}
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "browser_cross_origin_requests_disabled")
			return
		}
		mux.ServeHTTP(w, r)
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
	d := json.NewDecoder(r.Body)
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
	saved, e := a.Store.SaveConfig(r.Context(), c)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 201, map[string]any{"id": c.ID, "revision": saved.Revision, "status": saved.Status, "hash": saved.Hash})
}
func (a *API) validate(w http.ResponseWriter, r *http.Request) {
	s, e := a.Store.Config(r.Context(), r.PathValue("id"), false)
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
	if e := a.Store.Activate(r.Context(), r.PathValue("id"), body.Revision); e != nil {
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
	if !config.ValidID(r.PathValue("name")) || !config.ValidHost(body.Host) || body.Value == "" || len(body.Value) > 32768 {
		fail(w, 422, "invalid_secret_input")
		return
	}
	e := a.Secrets.Put(r.Context(), r.PathValue("name"), body.Value, body.Host)
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
	data, e := a.Secrets.List(r.Context(), l, o)
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
	result, e := a.Engine.Run(r.Context(), r.PathValue("id"), test, false)
	if e != nil && result.ID == "" {
		dbFail(w, e)
		return
	}
	status := 200
	if e != nil {
		status = 502
	}
	if errors.Is(e, collector.ErrUnavailable) {
		status = 503
	}
	write(w, status, result)
}
func (a *API) runs(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	data, e := a.Store.Runs(r.Context(), r.URL.Query().Get("connector"), l, o)
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
	data, e := a.Store.Records(r.Context(), entity, r.URL.Query().Get("source"), l, o)
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
	data, e := a.Store.Quarantine(r.Context(), r.URL.Query().Get("connector"), l, o)
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
	data, e := a.Store.Health(r.Context(), l, o)
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
