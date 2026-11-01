package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubsidiariesFiltersAndDates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if r.Header.Get("User-Agent") == "" {
			t.Error("Wikidata requires a User-Agent")
		}
		b := func(k, v string) map[string]string { return map[string]string{"type": "literal", "value": v} }
		var rows []map[string]map[string]string
		if strings.Contains(q, "EntitySearch") {
			rows = []map[string]map[string]string{{"org": b("", "http://www.wikidata.org/entity/Q173395"), "orgLabel": b("", "Cisco")}}
		} else {
			rows = []map[string]map[string]string{
				{"sub": b("", "http://www.wikidata.org/entity/Q1"), "subLabel": b("", "Cisco Meraki"), "start": b("", "2012-12-20T00:00:00Z")},
				{"sub": b("", "http://www.wikidata.org/entity/Q1"), "subLabel": b("", "Cisco Meraki"), "start": b("", "2013-01-01T00:00:00Z")},
				{"sub": b("", "http://www.wikidata.org/entity/Q2"), "subLabel": b("", "Q2")}, // no English label
				{"sub": b("", "http://www.wikidata.org/entity/Q3"), "subLabel": b("", "Sourcefire")},
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{"bindings": rows}})
	}))
	defer srv.Close()
	old := Endpoint
	Endpoint = srv.URL
	defer func() { Endpoint = old }()
	root, subs, e := Subsidiaries(context.Background(), `Cisco" } INJECT {`)
	if e != nil || root.QID != "Q173395" || len(subs) != 2 || subs[0].Name != "Cisco Meraki" || subs[0].Since != "2012" || subs[1].Source != "wikidata" {
		t.Fatal(root, subs, e)
	}
	if sparqlString(`a"b\c`) != `a\"b\\c` {
		t.Fatal("SPARQL string not escaped")
	}
}
