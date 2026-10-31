package api

import (
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
)

//go:embed insights.html
var insightsHTML string

//go:embed insights.css
var insightsCSS string

func (a *API) insightsStyles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write([]byte(insightsCSS))
}

var insightsTemplate = template.Must(template.New("insights").Funcs(template.FuncMap{"check": func(s string) string { return insights.Checks[s] }, "rule": func(s string) string { r, _ := insights.RuleByID(s); return r.Description }}).Parse(insightsHTML))

type insightsView struct {
	Token     string
	Connector string
	Topic     string
	Enabled   bool
	Error     string
	Snapshot  *insights.Snapshot
	Response  *SIEMResponse
	Usage     store.AIConsumption
	Budget    int64
}

func (a *API) renderInsights(w http.ResponseWriter, r *http.Request, status int, v insightsView) {
	caller := r.Context().Value(callerKey{}).(store.Caller)
	v.Token = a.UI.Token(caller.Tenant, caller.Actor)
	v.Enabled = a.siemEnabled(caller.Tenant)
	if v.Topic == "" {
		v.Topic = "connection_health"
	}
	if usage, e := a.scope(r).AIConsumption(r.Context()); e == nil {
		v.Usage = usage
	} else {
		status = 503
		v.Error = "Usage storage is unavailable."
	}
	v.Budget = 400000
	if a.SIEM != nil && a.SIEM.DailyTokens != 0 {
		v.Budget = a.SIEM.DailyTokens
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	insightsTemplate.Execute(w, v)
}
func (a *API) insightsPage(w http.ResponseWriter, r *http.Request) {
	v := insightsView{Connector: r.URL.Query().Get("connector")}
	if v.Connector != "" {
		if !config.ValidID(v.Connector) {
			fail(w, 422, "invalid_connector")
			return
		}
		if a.siemEnabled(a.scope(r).Tenant) {
			snap, e := a.scope(r).SIEMSnapshot(r.Context(), v.Connector)
			if e == nil {
				v.Snapshot = &snap
			}
		}
	}
	a.renderInsights(w, r, 200, v)
}
func (a *API) insightsAction(w http.ResponseWriter, r *http.Request) {
	if !a.consolePost(w, r) {
		return
	}
	for k := range r.PostForm {
		if k != "csrf_token" && k != "connector" && k != "topic" && k != "action" && k != "consent" {
			fail(w, 400, "unknown_form_field")
			return
		}
	}
	v := insightsView{Connector: r.PostForm.Get("connector"), Topic: r.PostForm.Get("topic")}
	if !config.ValidID(v.Connector) || !insights.Topic(v.Topic) {
		fail(w, 422, "invalid_siem_question")
		return
	}
	scope := a.scope(r)
	if !a.siemEnabled(scope.Tenant) {
		fail(w, 503, "siem_disabled")
		return
	}
	switch r.PostForm.Get("action") {
	case "refresh":
		snap, e := a.refreshSIEM(r.Context(), scope, v.Connector)
		if e != nil {
			siemFailure(w, e)
			return
		}
		v.Snapshot = &snap
	case "ask":
		if r.PostForm.Get("consent") != "on" {
			v.Error = "Tick the consent checkbox to send aggregate counts/categories to Groq."
			a.renderInsights(w, r, 422, v)
			return
		}
		caller := r.Context().Value(callerKey{}).(store.Caller)
		answer, e := a.answerSIEM(r.Context(), scope, caller.Actor, SIEMQuestion{Connector: v.Connector, Topic: v.Topic, Consent: true})
		if e != nil {
			siemFailure(w, e)
			return
		}
		v.Response = &answer
	default:
		fail(w, 400, "unknown_action")
		return
	}
	a.renderInsights(w, r, 200, v)
}

// References stay within the authenticated API; no provider-supplied URLs.
func runReference(connector string) string { return "/runs?connector=" + url.QueryEscape(connector) }
