package api

import "net/http"

func (a *API) kevMatches(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := paging(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("connector")
	if !a.checkFilter(w, r, id) {
		return
	}
	out, e := a.scope(r).KEVMatches(r.Context(), id, limit, offset)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, out)
}
