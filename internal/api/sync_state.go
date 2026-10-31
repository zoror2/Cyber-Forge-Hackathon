package api

import "net/http"

func (a *API) syncState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !a.checkFilter(w, r, id) {
		return
	}
	state, err := a.scope(r).SyncState(r.Context(), id)
	if err != nil {
		dbFail(w, err)
		return
	}
	write(w, 200, state)
}
