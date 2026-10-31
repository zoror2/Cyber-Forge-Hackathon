package api

import (
	"configbridge/internal/aidraft"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type Drafting struct {
	Provider       aidraft.Provider
	Sources        map[string]aidraft.Source
	EnabledTenants map[string]bool
	DailyLimit     int
	TokenLimit     int64
	mu             sync.Mutex
	active         map[string]bool
}

func (d *Drafting) acquire(tenant string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == nil {
		d.active = map[string]bool{}
	}
	if d.active[tenant] || len(d.active) >= 2 {
		return false
	}
	d.active[tenant] = true
	return true
}
func (d *Drafting) release(tenant string) { d.mu.Lock(); defer d.mu.Unlock(); delete(d.active, tenant) }
func (a *API) aiEnabled(tenant string) bool {
	return a.AI != nil && a.AI.Provider != nil && a.AI.EnabledTenants[tenant]
}
func (a *API) aiSources(w http.ResponseWriter, r *http.Request) {
	if !a.aiEnabled(a.scope(r).Tenant) {
		fail(w, 503, "ai_drafting_disabled")
		return
	}
	out := []aidraft.PublicSource{}
	for _, s := range a.AI.Sources {
		out = append(out, s.Summary())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	write(w, 200, out)
}
func (a *API) aiDraft(w http.ResponseWriter, r *http.Request) {
	caller := r.Context().Value(callerKey{}).(store.Caller)
	if !a.aiEnabled(caller.Tenant) {
		fail(w, 503, "ai_drafting_disabled")
		return
	}
	var in struct {
		SourceID    string `json:"source_id"`
		ConnectorID string `json:"connector_id"`
		Name        string `json:"name"`
		Consent     bool   `json:"external_ai_consent"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if !in.Consent {
		fail(w, 422, "external_ai_consent_required")
		return
	}
	if !config.ValidID(in.ConnectorID) || len(in.Name) > 200 || (in.Name != "" && strings.TrimSpace(in.Name) == "") {
		fail(w, 422, "invalid_draft_input")
		return
	}
	source, ok := a.AI.Sources[in.SourceID]
	if !ok {
		fail(w, 404, "public_source_not_found")
		return
	}
	if source.Validate() != nil {
		fail(w, 503, "public_source_unavailable")
		return
	}
	if !a.AI.acquire(caller.Tenant) {
		fail(w, 429, "ai_drafting_busy")
		return
	}
	defer a.AI.release(caller.Tenant)
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		fail(w, 503, "ai_drafting_unavailable")
		return
	}
	audit := store.AIAudit{RequestID: hex.EncodeToString(id), Actor: caller.Actor, SourceID: source.ID, SourceHash: source.Hash(), Provider: a.AI.Provider.Name(), Model: a.AI.Provider.Model(), PromptVersion: aidraft.PromptVersion}
	scope := a.scope(r)
	limit := a.AI.DailyLimit
	if limit < 1 || limit > 100 {
		fail(w, 503, "invalid_ai_budget")
		return
	}
	tokenLimit := a.AI.TokenLimit
	if tokenLimit == 0 {
		tokenLimit = 400000
	}
	if err := scope.ReserveMeteredAI(r.Context(), limit, tokenLimit, audit, "config_draft"); err != nil {
		if errors.Is(err, store.ErrAIBudget) {
			fail(w, 429, "ai_daily_limit_reached")
		} else {
			dbFail(w, err)
		}
		return
	}
	var raw []byte
	var usage insights.Usage
	var err error
	if metered, ok := a.AI.Provider.(interface {
		GenerateMetered(context.Context, aidraft.Source) ([]byte, insights.Usage, error)
	}); ok {
		raw, usage, err = metered.GenerateMetered(r.Context(), source)
	} else {
		raw, err = a.AI.Provider.Generate(r.Context(), source)
	}
	var c config.Config
	audit.Outcome = "provider_failed"
	if err == nil {
		c, err = aidraft.Assemble(raw, source, in.ConnectorID, in.Name)
		audit.Outcome = "validation_rejected"
		if err == nil {
			audit.Outcome = "draft_validated"
			body, _ := json.Marshal(c)
			hash := sha256.Sum256(body)
			audit.OutputHash = hex.EncodeToString(hash[:])
		}
	}
	// Even cancelled requests leave a terminal audit event; no raw prompts, draft
	// contents, names or credential values are put into the audit table.
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := scope.FinishTokens(finish, audit.RequestID, audit.Outcome, usage); e != nil {
		dbFail(w, e)
		return
	}
	if e := scope.RecordAI(finish, audit); e != nil {
		dbFail(w, e)
		return
	}
	if err != nil {
		if errors.Is(err, aidraft.ErrOutput) {
			fail(w, 422, "ai_draft_rejected_by_validator")
		} else {
			fail(w, 502, "ai_provider_unavailable")
		}
		return
	}
	write(w, 200, map[string]any{"status": "draft_proposal", "review_required": true, "config": c, "source": source.Summary(), "provider": audit.Provider, "model": audit.Model, "prompt_version": audit.PromptVersion, "request_id": audit.RequestID, "config_hash": audit.OutputHash})
}
func (a *API) aiAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r)
	if !ok {
		return
	}
	out, err := a.scope(r).AIAudits(r.Context(), limit, offset)
	if err != nil {
		dbFail(w, err)
		return
	}
	write(w, 200, out)
}
func (a *API) preview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision int `json:"revision"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if in.Revision < 1 {
		fail(w, 400, "revision_required")
		return
	}
	result, err := a.Engine.Preview(r.Context(), a.scope(r).Tenant, r.PathValue("id"), in.Revision)
	if err != nil && result.ID == "" {
		dbFail(w, err)
		return
	}
	status := 200
	if err != nil {
		status = 502
	}
	write(w, status, result)
}
