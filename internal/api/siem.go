package api

import (
	"configbridge/internal/ai"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Explainer is the model boundary (internal/ai.Client: Gemini, Groq or
// Bedrock). It receives validated aggregate facts, public CVE IDs and an opt-in
// question as untrusted text. It has no SQL executor or raw-record access.
type Explainer interface {
	Explain(context.Context, insights.Evidence) (insights.Answer, insights.Usage, error)
	Provider() string
	ModelID() string
}
type SIEM struct {
	Search         insights.Search
	Provider       Explainer
	EnabledTenants map[string]bool
	DailyTokens    int64
	DailyCalls     int
	mu             sync.Mutex
	active         map[string]bool // one explanation per tenant at a time
}

func (s *SIEM) acquire(tenant string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[tenant] {
		return false
	}
	if s.active == nil {
		s.active = map[string]bool{}
	}
	s.active[tenant] = true
	return true
}
func (s *SIEM) release(tenant string) {
	s.mu.Lock()
	delete(s.active, tenant)
	s.mu.Unlock()
}

// References stay within the authenticated API; no provider-supplied URLs.
func runReference(connector string) string { return "/runs?connector=" + url.QueryEscape(connector) }

func (a *API) siemEnabled(tenant string) bool {
	return a.SIEM != nil && a.SIEM.Search != nil && a.SIEM.EnabledTenants[tenant]
}
func siemFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrBusy) {
		dbFail(w, err)
	} else if errors.Is(err, store.ErrAIBudget) {
		fail(w, 429, "ai_budget_reached")
	} else {
		fail(w, 503, "siem_unavailable")
	}
}

// Every refresh starts from the authoritative PostgreSQL rows. Locking prevents
// parallel refreshes or a collection from changing this connector mid-indexing.
func (a *API) refreshSIEM(ctx context.Context, scope store.Scope, id string) (insights.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lease, unlock, e := scope.Lock(ctx, id)
	if e != nil {
		return insights.Snapshot{}, e
	}
	defer unlock()
	snap, e := scope.BuildSIEMSnapshot(lease, id)
	if e != nil {
		return snap, e
	}
	e = a.SIEM.Search.Index(lease, scope.Tenant, snap)
	return snap, e
}
func (a *API) siemRefresh(w http.ResponseWriter, r *http.Request) {
	s := a.scope(r)
	if !a.siemEnabled(s.Tenant) {
		fail(w, 503, "siem_disabled")
		return
	}
	var in struct {
		Connector string `json:"connector"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if !config.ValidID(in.Connector) {
		fail(w, 422, "invalid_connector")
		return
	}
	out, e := a.refreshSIEM(r.Context(), s, in.Connector)
	if e != nil {
		siemFailure(w, e)
		return
	}
	write(w, 200, out)
}
func (a *API) siemFindings(w http.ResponseWriter, r *http.Request) {
	s := a.scope(r)
	if !a.siemEnabled(s.Tenant) {
		fail(w, 503, "siem_disabled")
		return
	}
	id := r.URL.Query().Get("connector")
	if !config.ValidID(id) {
		fail(w, 422, "invalid_connector")
		return
	}
	if !a.checkFilter(w, r, id) {
		return
	}
	out, e := s.SIEMSnapshot(r.Context(), id)
	if e != nil {
		siemFailure(w, e)
		return
	}
	write(w, 200, out)
}

type SIEMQuestion struct {
	Question  string `json:"question,omitempty"`
	Connector string `json:"connector"`
	Topic     string `json:"topic"`
	Consent   bool   `json:"external_ai_consent"`
}
type SIEMResponse struct {
	RequestID  string             `json:"request_id,omitempty"`
	Status     string             `json:"status"`
	Answer     insights.Answer    `json:"answer"`
	Evidence   insights.Evidence  `json:"evidence"`
	Findings   []insights.Finding `json:"findings"`
	Usage      insights.Usage     `json:"usage"`
	Provider   string             `json:"provider,omitempty"`
	Model      string             `json:"model,omitempty"`
	RunHistory string             `json:"run_history_reference"`
}

func (a *API) answerSIEM(ctx context.Context, scope store.Scope, actor string, in SIEMQuestion) (out SIEMResponse, err error) {
	out.RunHistory = runReference(in.Connector)
	if !insights.ValidQuestion(in.Question) || !config.ValidID(in.Connector) || !insights.Topic(in.Topic) || !in.Consent {
		return out, insights.ErrEvidence
	}
	if !a.SIEM.acquire(scope.Tenant) {
		return out, store.ErrBusy
	}
	defer a.SIEM.release(scope.Tenant)
	// Keep the connector lease through index retrieval and DB revalidation only;
	// a slow LLM must never block scheduled collection.
	var snap insights.Snapshot
	var findings []insights.Finding
	var matched store.KEVMatches
	err = func() error {
		bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		lease, unlock, e := scope.Lock(bounded, in.Connector)
		if e != nil {
			return e
		}
		defer unlock()
		snap, e = scope.BuildSIEMSnapshot(lease, in.Connector)
		if e != nil {
			return e
		}
		if e = a.SIEM.Search.Index(lease, scope.Tenant, snap); e != nil {
			return e
		}
		ids, e := a.SIEM.Search.Find(lease, scope.Tenant, snap, in.Topic)
		if e != nil {
			return e
		}
		findings, e = scope.ResolveSIEM(lease, in.Connector, snap.Generation, ids, in.Topic)
		if e != nil {
			return e
		}
		for _, f := range findings {
			if f.Rule == "kev_exact_matches" {
				matched, e = scope.KEVMatches(lease, in.Connector, 20, 0)
				if e != nil {
					return e
				}
				if matched.Total != f.Count {
					return insights.ErrEvidence
				}
			}
		}
		return nil
	}()
	if err != nil {
		return out, err
	}
	out.Findings = findings
	out.Evidence = insights.Evidence{Topic: in.Topic, WindowHours: 24, RunSampleCapped: snap.RunSampleCapped, Facts: []insights.Fact{}}
	out.Evidence.Question = in.Question
	for i, f := range findings {
		out.Evidence.Facts = append(out.Evidence.Facts, insights.Fact{ID: fmt.Sprintf("e%d", i+1), Rule: f.Rule, Severity: f.Severity, Category: f.Category, Count: f.Count})
		if f.Rule == "kev_exact_matches" {
			seen := map[string]bool{}
			for _, m := range matched.Matches {
				if !seen[m.CVE] {
					out.Evidence.KEVCVEs = append(out.Evidence.KEVCVEs, m.CVE)
					seen[m.CVE] = true
				}
			}
			out.Evidence.KEVListCapped = matched.Total > int64(len(matched.Matches))
		}
	}
	if len(findings) == 0 {
		out.Status = "no_findings"
		out.Answer = insights.Answer{Summary: "No matching findings were found in this 24-hour window. This does not establish that the connection or deployment is secure.", EvidenceIDs: []string{}, NextChecks: []string{}}
		return out, nil
	}
	if out.Evidence.Validate() != nil {
		return out, insights.ErrEvidence
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return out, err
	}
	out.RequestID = hex.EncodeToString(id)
	out.Provider = a.SIEM.Provider.Provider()
	out.Model = a.SIEM.Provider.ModelID()
	// limits come from .env (internal/app.SIEM); nothing is defaulted here
	if err = scope.ReserveMeteredAI(ctx, a.SIEM.DailyCalls, a.SIEM.DailyTokens, store.AIAudit{RequestID: out.RequestID, Actor: actor, SourceID: "aggregate_siem", Provider: out.Provider, Model: out.Model, PromptVersion: ai.ExplainPromptVersion}, "siem_explanation"); err != nil {
		return out, err
	}
	out.Answer, out.Usage, err = a.SIEM.Provider.Explain(ctx, out.Evidence)
	if !out.Usage.Valid() {
		out.Usage = insights.Usage{}
	}
	outcome := "explained"
	if err != nil || out.Answer.Validate(out.Evidence) != nil {
		outcome = "provider_failed"
		out.Answer = insights.Answer{}
		err = insights.ErrProvider
	}
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := scope.FinishTokens(finish, out.RequestID, outcome, out.Usage); e != nil {
		return out, e
	}
	if e := scope.RecordAI(finish, store.AIAudit{RequestID: out.RequestID, Actor: actor, SourceID: "aggregate_siem", Provider: out.Provider, Model: out.Model, PromptVersion: ai.ExplainPromptVersion, Outcome: outcome}); e != nil {
		return out, e
	}
	out.Status = "explanation_requires_review"
	return out, err
}
func (a *API) siemAsk(w http.ResponseWriter, r *http.Request) {
	s := a.scope(r)
	if !a.siemEnabled(s.Tenant) || a.SIEM.Provider == nil {
		fail(w, 503, "siem_disabled")
		return
	}
	var in SIEMQuestion
	if !jsonBody(w, r, &in) {
		return
	}
	if !in.Consent {
		fail(w, 422, "external_ai_consent_required")
		return
	}
	if !insights.ValidQuestion(in.Question) || !config.ValidID(in.Connector) || !insights.Topic(in.Topic) {
		fail(w, 422, "invalid_siem_question")
		return
	}
	caller := r.Context().Value(callerKey{}).(store.Caller)
	out, e := a.answerSIEM(r.Context(), s, caller.Actor, in)
	if e != nil {
		siemFailure(w, e)
		return
	}
	write(w, 200, out)
}
func (a *API) aiUsage(w http.ResponseWriter, r *http.Request) {
	out, e := a.scope(r).AIConsumption(r.Context())
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, out)
}
