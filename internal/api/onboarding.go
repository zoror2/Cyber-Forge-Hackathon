package api

import (
	"configbridge/internal/onboarding"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (a *API) consoleView(r *http.Request) onboarding.View {
	caller := r.Context().Value(callerKey{}).(store.Caller)
	values := url.Values{"port": {"443"}, "auth_type": {"none"}, "pagination_type": {"none"}, "page_param": {"page"}, "size_param": {"per_page"}, "page_size": {"100"}, "offset_param": {"offset"}, "cursor_param": {"after"}, "interval_seconds": {"900"}, "failure_threshold": {"3"}, "cooldown_seconds": {"3600"}, "overlap_seconds": {"60"}, "safety_lag_seconds": {"5"}, "path_id": {"id"}, "transform_id": {"string"}, "constant_type": {"security_event"}, "constant_severity": {"unknown"}}
	for _, field := range []string{"timestamp", "last_login", "last_seen"} {
		values.Set("transform_"+field, "datetime")
		values.Set("timezone_"+field, "UTC")
	}
	v := onboarding.View{Token: a.UI.Token(caller.Tenant, caller.Actor), Entity: "user", Fields: onboarding.MappingRows("user"), NotificationReady: a.NotificationTenants[caller.Tenant], Values: values}
	if a.Secrets != nil {
		if meta, err := a.Secrets.List(r.Context(), caller.Tenant, 500, 0); err == nil {
			for _, m := range meta {
				v.SecretNames = append(v.SecretNames, m.Name)
			}
		}
	}
	return v
}
func (a *API) renderConsole(w http.ResponseWriter, status int, v onboarding.View) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	onboarding.Render(w, v)
}
func (a *API) consoleForm(w http.ResponseWriter, r *http.Request) {
	if a.UI == nil {
		http.NotFound(w, r)
		return
	}
	v := a.consoleView(r)
	entity := r.URL.Query().Get("entity")
	if entity == "device" || entity == "event" {
		v.Entity = entity
		v.Fields = onboarding.MappingRows(entity)
	}
	a.renderConsole(w, 200, v)
}
func (a *API) consoleCSS(w http.ResponseWriter, r *http.Request) {
	if a.UI == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write([]byte(onboarding.CSS))
}
func (a *API) consolePost(w http.ResponseWriter, r *http.Request) bool {
	if a.UI == nil {
		http.NotFound(w, r)
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		fail(w, 415, "form_content_type_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxBytes)
	if r.ParseForm() != nil {
		fail(w, 413, "invalid_or_oversized_form")
		return false
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			fail(w, 400, "duplicate_form_field")
			return false
		}
	}
	caller := r.Context().Value(callerKey{}).(store.Caller)
	if !a.UI.ValidToken(caller.Tenant, caller.Actor, r.PostForm.Get("csrf_token")) {
		fail(w, 403, "expired_or_invalid_form_token")
		return false
	}
	return true
}
func (a *API) consoleGenerate(w http.ResponseWriter, r *http.Request) {
	if !a.consolePost(w, r) {
		return
	}
	c, issues := onboarding.Build(r.PostForm)
	if c.Notifications != nil && c.Notifications.Enabled && !a.NotificationTenants[a.scope(r).Tenant] {
		issues = append(issues, config.Issue{Field: "notifications", Message: "ask your administrator to configure a tenant email destination first"})
	}
	v := a.consoleView(r)
	v.Values = r.PostForm
	if c.Auth.Type != "none" {
		found := false
		for _, name := range v.SecretNames {
			if name == c.Auth.Secret {
				found = true
			}
		}
		if !found {
			issues = append(issues, config.Issue{Field: "auth.secret", Message: "select a stored credential belonging to your tenant; add it through the secrets API first"})
		}
	}
	if _, ok := config.Fields[c.Destination.Entity]; ok {
		v.Entity = c.Destination.Entity
		v.Fields = onboarding.MappingRows(v.Entity)
	}
	if len(issues) > 0 {
		v.Issues = issues
		a.renderConsole(w, 422, v)
		return
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	if len(raw) > 64<<10 {
		v.Issues = []config.Issue{{Field: "form", Message: "generated config exceeds this form's 64 KiB limit"}}
		a.renderConsole(w, 422, v)
		return
	}
	v.JSON = string(raw)
	v.ID = c.ID
	a.renderConsole(w, 200, v)
}
func (a *API) consoleConfig(w http.ResponseWriter, r *http.Request) (config.Config, bool) {
	if !a.consolePost(w, r) {
		return config.Config{}, false
	}
	for k := range r.PostForm {
		if k != "csrf_token" && k != "config" {
			fail(w, 400, "unknown_form_field")
			return config.Config{}, false
		}
	}
	raw := []byte(r.PostForm.Get("config"))
	if len(raw) > 64<<10 {
		fail(w, 413, "form_config_too_large")
		return config.Config{}, false
	}
	c, issues := config.Decode(raw)
	if len(issues) > 0 {
		v := a.consoleView(r)
		v.Issues = issues
		a.renderConsole(w, 422, v)
		return c, false
	}
	if c.Notifications != nil && c.Notifications.Enabled && !a.NotificationTenants[a.scope(r).Tenant] {
		fail(w, 422, "email_notifications_not_configured_for_tenant")
		return c, false
	}
	return c, true
}
func (a *API) consoleDownload(w http.ResponseWriter, r *http.Request) {
	c, ok := a.consoleConfig(w, r)
	if !ok {
		return
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+c.ID+`.json"`)
	w.Write(raw)
}
func (a *API) consoleSave(w http.ResponseWriter, r *http.Request) {
	c, ok := a.consoleConfig(w, r)
	if !ok {
		return
	}
	saved, err := a.scope(r).SaveConfig(r.Context(), c)
	if err != nil {
		dbFail(w, err)
		return
	}
	v := a.consoleView(r)
	v.ID = c.ID
	v.Revision = saved.Revision
	v.Saved = true
	raw, _ := json.MarshalIndent(c, "", "  ")
	v.JSON = string(raw)
	a.renderConsole(w, 201, v)
}
func (a *API) consoleTest(w http.ResponseWriter, r *http.Request) {
	if !a.consolePost(w, r) {
		return
	}
	for k := range r.PostForm {
		if k != "csrf_token" && k != "id" && k != "revision" {
			fail(w, 400, "unknown_form_field")
			return
		}
	}
	id := r.PostForm.Get("id")
	revision, e := strconv.Atoi(r.PostForm.Get("revision"))
	if !config.ValidID(id) || e != nil || revision < 1 {
		fail(w, 400, "invalid_draft_reference")
		return
	}
	result, err := a.Engine.Preview(r.Context(), a.scope(r).Tenant, id, revision)
	if err != nil && result.ID == "" {
		dbFail(w, err)
		return
	}
	v := a.consoleView(r)
	v.ID = id
	v.Revision = revision
	v.Saved = true
	v.Tested = true
	v.Result = &result
	if saved, err := a.scope(r).ConfigRevision(r.Context(), id, revision); err == nil {
		raw, _ := json.MarshalIndent(saved.Config, "", "  ")
		v.JSON = string(raw)
	}
	status := 200
	if err != nil {
		status = 502
	}
	a.renderConsole(w, status, v)
}
func isConsole(path string) bool {
	return path == "/onboarding" || strings.HasPrefix(path, "/onboarding/") || path == "/insights" || strings.HasPrefix(path, "/insights/")
}
