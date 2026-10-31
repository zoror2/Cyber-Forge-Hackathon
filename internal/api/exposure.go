package api

import "net/http"

func (a *API) exposure(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("connector")
	if !a.checkFilter(w, r, id) {
		return
	}
	rows, err := a.scope(r).Exposure(r.Context(), id, limit, offset)
	if err != nil {
		dbFail(w, err)
		return
	}
	write(w, 200, rows)
}
