package insights

import (
	"strings"
	"testing"
)

func validEvidence() Evidence {
	return Evidence{Topic: "connection_health", WindowHours: 24, Facts: []Fact{{ID: "e1", Rule: "collection_failures", Severity: "warning", Category: "auth_failed", Count: 3}}}
}
func TestEvidenceBoundaryAndAnswerValidation(t *testing.T) {
	if validEvidence().Validate() != nil {
		t.Fatal("valid evidence rejected")
	}
	for _, mutate := range []func(*Evidence){func(e *Evidence) { e.Topic = "private_question" }, func(e *Evidence) { e.WindowHours = 1000 }, func(e *Evidence) { e.Facts[0].ID = "tenant-a" }, func(e *Evidence) { e.Facts[0].Rule = "private_description" }, func(e *Evidence) { e.Facts[0].Category = "PRIVATE_SECRET" }, func(e *Evidence) { e.Facts[0].Count = -1 }, func(e *Evidence) { e.Facts[0].Severity = "customer_email" }, func(e *Evidence) { e.Facts = append(e.Facts, e.Facts[0]) }} {
		e := validEvidence()
		mutate(&e)
		if e.Validate() == nil {
			t.Fatal("unsafe evidence accepted")
		}
	}
	e := validEvidence()
	a := Answer{Summary: "The sampled runs failed authentication; review credential permissions.", EvidenceIDs: []string{"e1"}, NextChecks: []string{"credential_permissions"}}
	if a.Validate(e) != nil {
		t.Fatal("valid answer rejected")
	}
	for _, mutate := range []func(*Answer){func(a *Answer) { a.EvidenceIDs = []string{"other-tenant"} }, func(a *Answer) { a.EvidenceIDs = []string{"e1", "e1"} }, func(a *Answer) { a.NextChecks = []string{"disable_tls"} }, func(a *Answer) { a.Summary = "<script>" }, func(a *Answer) { a.Summary = "https://evil.invalid" }, func(a *Answer) { a.Summary = strings.Repeat("x", 2001) }} {
		copy := a
		mutate(&copy)
		if copy.Validate(e) == nil {
			t.Fatal("unsafe answer accepted")
		}
	}
	for _, u := range []Usage{{Known: true, Input: 10, Output: 2, Total: 11}, {Known: true, Input: -1, Total: 1}, {Input: 1, Total: 1}, {Known: true, Input: 1_000_001, Total: 1_000_001}} {
		if u.Valid() {
			t.Fatal("invalid usage accepted")
		}
	}
}
