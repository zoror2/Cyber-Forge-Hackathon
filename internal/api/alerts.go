package api

import "net/http"

func (a *API) notificationsReady(r *http.Request) (bool, error) {
	if a.NotificationReady != nil {
		return a.NotificationReady(r.Context(), a.scope(r).Tenant)
	}
	return a.NotificationTenants[a.scope(r).Tenant], nil
}

// Report only this tenant's capability, never SMTP credentials or other routes.
// Configured means delivery can be attempted, not that a mailbox accepted it.
func (a *API) notificationStatus(w http.ResponseWriter, r *http.Request) {
	configured, err := a.notificationsReady(r)
	if err != nil {
		dbFail(w, err)
		return
	}
	mode := "disabled"
	if configured {
		mode = "smtp"
		if a.NotificationLocalCapture {
			mode = "local_capture"
		}
	}
	write(w, 200, map[string]any{
		"configured": configured, "delivery_mode": mode,
		"kind": "connector_failures", "max_delivery_attempts": 5,
	})
}

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
