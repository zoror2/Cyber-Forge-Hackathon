package api

import (
	"bytes"
	"configbridge/internal/ai"
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/ocsf"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

type repairCandidate struct {
	config config.Config
	option ai.RepairOption
}

var repairSampleDone = errors.New("repair_sample_done")

// Only conversion metadata can change: no URL/auth/path/filter/constant changes,
// no disabling required fields, no invented data, no checkpoint reset.
func repairCandidates(c config.Config, rows []any, tenant string) []repairCandidate {
	out := []repairCandidate{}
	now := time.Now()
	fields := map[string]bool{}
	for i, row := range rows {
		_, q := mapping.Map(row, c, tenant, now, i)
		if q != nil {
			fields[q.Field] = true
		}
	}
	keys := []string{}
	for field := range fields {
		keys = append(keys, field)
	}
	sort.Strings(keys)
	class, _ := ocsf.Lookup(c.Destination.Class)
	for _, field := range keys {
		if field == ocsf.Identity[c.Destination.Class] {
			continue
		}
		original, ok := c.Destination.Mapping[field]
		if !ok || original.Path == nil {
			continue
		}
		attr, err := ocsf.Resolve(class, field)
		if err != nil {
			continue
		}
		alternatives := []config.Field{}
		transforms := []string{}
		switch attr.BaseType() {
		case "string_t":
			transforms = []string{"string"}
		case "integer_t", "long_t":
			transforms = []string{"integer"}
		case "timestamp_t":
			transforms = []string{"datetime"}
		}
		for _, transform := range transforms {
			f := original
			f.Transform = transform
			f.Format = ""
			if transform != "datetime" {
				f.Timezone = ""
			}
			alternatives = append(alternatives, f)
		}
		if attr.Type == "timestamp_t" && original.Timezone != "" {
			for _, format := range []string{"2006-01-02", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
				f := original
				f.Transform = "datetime"
				f.Format = format
				alternatives = append(alternatives, f)
			}
		}
		for _, f := range alternatives {
			raw, _ := json.Marshal(c)
			var candidate config.Config
			json.Unmarshal(raw, &candidate)
			candidate.Destination.Mapping[field] = f
			if len(candidate.Validate()) != 0 {
				continue
			}
			good, bad := 0, 0
			for i, row := range rows {
				mapped, q := mapping.Map(row, candidate, tenant, now, i)
				previous, oldErr := mapping.Map(row, c, tenant, now, i)
				if oldErr == nil && !bytes.Equal(previous.Payload, mapped.Payload) {
					bad++
					continue
				}
				if q != nil {
					bad++
				} else {
					good++
				}
			}
			if bad != 0 || good == 0 {
				continue
			}
			out = append(out, repairCandidate{candidate, ai.RepairOption{ID: fmt.Sprintf("r%d", len(out)+1), Operation: f.Transform, Accepted: good, Rejected: bad}})
			if len(out) == 20 {
				return out
			}
		}
	}
	return out
}

func (a *API) repairConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Consent bool `json:"external_ai_consent"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if !in.Consent {
		fail(w, 422, "external_ai_consent_required")
		return
	}
	s := a.scope(r)
	id := r.PathValue("id")
	saved, err := s.Config(r.Context(), id, true)
	if err != nil {
		dbFail(w, err)
		return
	}
	if !a.AI.Allowed(s.Tenant) {
		fail(w, 503, "ai_not_configured")
		return
	}
	if a.Engine == nil || saved.Config.Incremental != nil {
		fail(w, 422, "manual_repair_required_for_incremental_source")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	lease, unlock, err := s.Lock(ctx, id)
	if err != nil {
		dbFail(w, err)
		return
	}
	release, ok := a.Engine.AcquireCapacity(s.Tenant)
	if !ok {
		unlock()
		dbFail(w, store.ErrBusy)
		return
	}
	// At most 1 MiB and 100 first-page records; never persist sample values.
	probe := saved.Config.Connector(s.Tenant)
	probe.Limits.MaxResponseBytes = min(probe.Limits.MaxResponseBytes, 1<<20)
	if probe.Limits.MaxResponseBytes <= 0 {
		probe.Limits.MaxResponseBytes = 1 << 20
	}
	probe.Limits.MaxRunSeconds = 20
	rows := []any{}
	sampleCtx, stopSample := context.WithTimeout(lease, 20*time.Second)
	_, err = a.Engine.Fetcher.Fetch(sampleCtx, probe, func(p engine.Page) error {
		for _, row := range p.Items {
			if mapping.Keep(row, saved.Config.Filter, time.Now()) {
				rows = append(rows, row)
			}
			if len(rows) >= 100 {
				break
			}
		}
		return repairSampleDone
	})
	stopSample()
	unlock()
	release()
	if err != nil && !errors.Is(err, repairSampleDone) {
		fail(w, 422, "repair_sample_failed_check_connection")
		return
	}
	candidates := repairCandidates(saved.Config, rows, s.Tenant)
	rows = nil
	if len(candidates) == 0 {
		write(w, 422, map[string]string{"error": "no_safe_conversion_repair", "detail": "No verified conversion fix. Missing fields, incorrect paths, invalid source values or multiple simultaneous errors need documented mapping review. The live config is unchanged."})
		return
	}
	options := []ai.RepairOption{}
	for _, c := range candidates {
		options = append(options, c.option)
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		fail(w, 503, "repair_unavailable")
		return
	}
	caller := r.Context().Value(callerKey{}).(store.Caller)
	audit := store.AIAudit{RequestID: hex.EncodeToString(random), Actor: caller.Actor, SourceID: "conversion_repair", Provider: a.AI.Provider(), Model: a.AI.Model, PromptVersion: "conversion-repair-v1"}
	if err = s.ReserveMeteredAI(ctx, a.AI.DailyLimit, a.AI.TokenLimit, audit, "config_repair"); err != nil {
		siemFailure(w, err)
		return
	}
	chosen, usage, err := a.AI.ChooseRepair(ctx, options)
	audit.Outcome = "drafted"
	if err != nil {
		audit.Outcome = "provider_failed"
	}
	finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if e := s.FinishTokens(finish, audit.RequestID, audit.Outcome, usage); e != nil {
		dbFail(w, e)
		return
	}
	if e := s.RecordAI(finish, audit); e != nil {
		dbFail(w, e)
		return
	}
	if err != nil {
		fail(w, 502, "ai_repair_failed")
		return
	}
	var selected *repairCandidate
	for i := range candidates {
		if candidates[i].option.ID == chosen {
			selected = &candidates[i]
		}
	}
	if selected == nil {
		fail(w, 422, "no_safe_conversion_repair")
		return
	}
	draft, err := s.SaveConfig(ctx, selected.config)
	if err != nil {
		dbFail(w, err)
		return
	}
	preview, err := a.Engine.Preview(ctx, s.Tenant, id, draft.Revision)
	if err != nil || preview.Outcome != "success" || preview.Quarantined != 0 || preview.Accepted == 0 {
		write(w, 422, map[string]any{"error": "repair_preview_failed", "preview": preview, "revision": draft.Revision})
		return
	}
	if err = s.ActivateExpected(ctx, id, draft.Revision, saved.Revision); err != nil {
		dbFail(w, err)
		return
	}
	run, err := a.Engine.RunExpected(ctx, s.Tenant, id, draft.Revision)
	status := "repaired_and_rerun"
	if err != nil || run.Outcome != "success" {
		status = "repair_applied_run_needs_review"
	}
	write(w, 200, map[string]any{"status": status, "revision": draft.Revision, "previous_revision": saved.Revision, "preview": preview, "run": run, "sample_only": true, "note": "Historical quarantine rows remain as audit evidence. Inspect the new run; later pages can still contain invalid source records."})
}
