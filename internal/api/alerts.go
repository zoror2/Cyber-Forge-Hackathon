package api

import "net/http"

func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("connector")
	if !a.checkFilter(w, r, id) {
		return
	}
	out, err := a.scope(r).Alerts(r.Context(), id, l, o)
	if err != nil {
		dbFail(w, err)
		return
	}
	write(w, 200, out)
}
