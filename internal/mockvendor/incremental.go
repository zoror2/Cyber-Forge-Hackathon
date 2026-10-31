package mockvendor

import (
	"net/http"
	"sync"
	"time"
)

// All data and mutation routes here are synthetic, local-demo fixtures. The
// platform uses only GET; the demo operator changes this fake vendor via POST.
func incrementalHandler() http.Handler {
	type user struct {
		ID, Name  string
		UpdatedAt time.Time
	}
	var mu sync.Mutex
	var rows []user
	var advanced bool
	snapshots := map[string][]user{}
	var keys []string
	reset := func() {
		base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
		rows = []user{{"1", "User One", base}, {"2", "User Two", base.Add(time.Minute)}, {"3", "User Three", base.Add(2 * time.Minute)}}
		advanced = false
		snapshots = map[string][]user{}
		keys = nil
	}
	reset()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /incremental/reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reset()
		mu.Unlock()
		writeJSON(w, map[string]string{"status": "synthetic_fixture_reset"})
	})
	mux.HandleFunc("POST /incremental/advance", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !advanced {
			at := time.Now().UTC().Truncate(time.Second)
			rows[1] = user{"2", "User Two (updated)", at}
			rows = append(rows, user{"4", "User Four", at})
			advanced = true
		}
		writeJSON(w, map[string]string{"status": "synthetic_user_2_updated_and_user_4_added"})
	})
	mux.HandleFunc("GET /incremental/users", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		since, e1 := time.Parse(time.RFC3339Nano, q.Get("updated_since"))
		until, e2 := time.Parse(time.RFC3339Nano, q.Get("updated_before"))
		page, size := intParam(r, "page", 1), intParam(r, "per_page", 2)
		if e1 != nil || e2 != nil || since.After(until) || page < 1 || page > 100000 || size < 1 || size > 100 {
			http.Error(w, "invalid synthetic filter or pagination", 400)
			return
		}
		key := since.UTC().Format(time.RFC3339Nano) + "/" + until.UTC().Format(time.RFC3339Nano)
		mu.Lock()
		snapshot, exists := snapshots[key]
		if !exists {
			snapshot = []user{}
			for _, row := range rows {
				if !row.UpdatedAt.Before(since) && row.UpdatedAt.Before(until) {
					snapshot = append(snapshot, row)
				}
			}
			if len(keys) == 128 {
				delete(snapshots, keys[0])
				keys = keys[1:]
			}
			keys = append(keys, key)
			snapshots[key] = snapshot
		}
		mu.Unlock()
		start := min((page-1)*size, len(snapshot))
		end := min(start+size, len(snapshot))
		out := []map[string]any{}
		for _, row := range snapshot[start:end] {
			out = append(out, map[string]any{"id": row.ID, "profile": map[string]string{"name": row.Name}, "updated_at": row.UpdatedAt.Format(time.RFC3339Nano)})
		}
		writeJSON(w, out)
	})
	return mux
}
