package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"configbridge/internal/ai"
	"configbridge/internal/insights"
	"configbridge/internal/intel"
	"configbridge/internal/store"
)

// Vendor ownership map: vendor -> companies it owns -> KEV CVEs, plus
// AI-found acquisitions and reported attacks that passed quote verification.

type intelNode struct {
	intel.Company
	KEV []store.KEVHit `json:"kev"`
}

type intelMap struct {
	Vendor       intelNode   `json:"vendor"`
	Subsidiaries []intelNode `json:"subsidiaries"`
	KEVTotal     int         `json:"kev_total"` // KEV entries in this tenant; 0 = no live KEV source
	Notes        []string    `json:"notes"`
}

func (a *API) withKEV(r *http.Request, root intel.Company, subs []intel.Company) (intelMap, error) {
	names := []string{root.Name}
	for _, s := range subs {
		names = append(names, s.Name)
	}
	hits, total, e := a.scope(r).KEVForCompanies(r.Context(), names)
	if e != nil {
		return intelMap{}, e
	}
	node := func(c intel.Company) intelNode {
		k := hits[strings.ToLower(strings.TrimSpace(c.Name))]
		if k == nil {
			k = []store.KEVHit{}
		}
		return intelNode{c, k}
	}
	m := intelMap{Vendor: node(root), Subsidiaries: []intelNode{}, KEVTotal: total,
		Notes: []string{"Ownership is a vendor-level signal, not proof you run these products. A CVE added before a company was acquired belongs to its previous owner's history."}}
	for _, s := range subs {
		m.Subsidiaries = append(m.Subsidiaries, node(s))
	}
	if total == 0 {
		m.Notes = append(m.Notes, "No live CISA KEV source in this account: add configs/cisa_kev.json to see exploited CVEs per company.")
	}
	return m, nil
}

// GET /intel/map?vendor=Cisco — structured data only (Wikidata + KEV), no AI.
func (a *API) intelMap(w http.ResponseWriter, r *http.Request) {
	vendor := strings.TrimSpace(r.URL.Query().Get("vendor"))
	if len(vendor) < 2 || len(vendor) > 100 {
		write(w, 400, map[string]string{"error": "invalid_vendor", "detail": "vendor: 2-100 characters"})
		return
	}
	root, subs, e := intel.Subsidiaries(r.Context(), vendor)
	switch {
	case errors.Is(e, intel.ErrNotFound):
		write(w, 404, map[string]string{"error": "vendor_not_found", "detail": "Wikidata has no company named " + vendor})
		return
	case e != nil:
		write(w, 502, map[string]string{"error": "ownership_source_failed", "detail": e.Error()})
		return
	}
	m, e := a.withKEV(r, root, subs)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, m)
}

type intelResearchReq struct {
	Vendor  string   `json:"vendor"`
	Company string   `json:"company"` // set: reported attacks on this company; empty: acquisitions of vendor
	Known   []string `json:"known"`
}

// POST /intel/research — metered AI web research; only quote-verified claims return.
func (a *API) intelResearch(w http.ResponseWriter, r *http.Request) {
	var req intelResearchReq
	if !jsonBody(w, r, &req) {
		return
	}
	req.Vendor, req.Company = strings.TrimSpace(req.Vendor), strings.TrimSpace(req.Company)
	if len(req.Vendor) < 2 || len(req.Vendor) > 100 || len(req.Company) > 100 || len(req.Known) > 200 {
		write(w, 400, map[string]string{"error": "invalid_request", "detail": "vendor 2-100 characters; company up to 100; known up to 200 names"})
		return
	}
	caller := r.Context().Value(callerKey{}).(store.Caller)
	if !a.AI.Allowed(caller.Tenant) {
		fail(w, 503, "ai_not_configured")
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	subject := req.Vendor + "|" + req.Company
	audit := store.AIAudit{RequestID: hex.EncodeToString(id), Actor: caller.Actor, SourceID: aiSourceID(req.Vendor),
		SourceHash: sha([]byte(subject)), Provider: a.AI.Provider(), Model: a.AI.Model, PromptVersion: "vendor-intel-v1"}
	scope := a.scope(r)
	if e := scope.ReserveMeteredAI(r.Context(), a.AI.DailyLimit, a.AI.TokenLimit, audit, "vendor_intel"); e != nil {
		if errors.Is(e, store.ErrAIBudget) {
			fail(w, 429, "ai_daily_limit_reached")
		} else {
			dbFail(w, e)
		}
		return
	}
	var claims []ai.Claim
	var usage insights.Usage
	var e error
	if req.Company == "" {
		claims, usage, e = a.AI.Acquisitions(r.Context(), req.Vendor, req.Known)
	} else {
		claims, usage, e = a.AI.Incidents(r.Context(), req.Company)
	}
	audit.Outcome = "researched"
	if e != nil {
		audit.Outcome = "provider_failed"
	}
	done := r.Context()
	if e2 := scope.FinishTokens(done, audit.RequestID, audit.Outcome, usage); e2 != nil {
		dbFail(w, e2)
		return
	}
	if e2 := scope.RecordAI(done, audit); e2 != nil {
		dbFail(w, e2)
		return
	}
	switch {
	case errors.Is(e, ai.ErrSearchRequired):
		write(w, 422, map[string]string{"error": "search_required", "detail": "web research needs CB_AI_PROVIDER=gemini"})
	case e != nil:
		write(w, 502, map[string]string{"error": "ai_provider_failed"})
	default:
		if claims == nil {
			claims = []ai.Claim{}
		}
		write(w, 200, map[string]any{"claims": claims, "note": "Only claims whose quoted sentence was found on the cited page are shown."})
	}
}
