package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"configbridge/pkg/config"
)

func (a *API) authorizeAIReportOperator(w http.ResponseWriter, r *http.Request) bool {
	if len(a.OperatorToken) < 32 {
		fail(w, 503, "platform_operator_not_configured")
		return false
	}
	supplied := r.Header.Get("Authorization")
	token := strings.TrimPrefix(supplied, "Bearer ")
	if !strings.HasPrefix(supplied, "Bearer ") || len(token) > 512 || subtle.ConstantTimeCompare([]byte(token), []byte(a.OperatorToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		fail(w, 401, "platform_operator_required")
		return false
	}
	return true
}

type aiReportQuery struct {
	from, to, customer string
	limit, offset      int
}

func parseAIReport(r *http.Request, operator bool) (p aiReportQuery, ok bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return p, false
	}
	for k, values := range q {
		if len(values) != 1 || (k != "from" && k != "to" && k != "limit" && k != "offset" && !(operator && k == "customer")) {
			return p, false
		}
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	p.from = q.Get("from")
	if p.from == "" {
		p.from = today.AddDate(0, 0, -6).Format(time.DateOnly)
	}
	p.to = q.Get("to")
	if p.to == "" {
		p.to = today.Format(time.DateOnly)
	}
	from, e1 := time.Parse(time.DateOnly, p.from)
	to, e2 := time.Parse(time.DateOnly, p.to)
	if e1 != nil || e2 != nil || from.After(to) || to.Sub(from) > 89*24*time.Hour || to.After(today) {
		return p, false
	}
	p.limit = 50
	p.offset = 0
	if v := q.Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 100 {
			return p, false
		}
		p.limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 || n > 100000 {
			return p, false
		}
		p.offset = n
	}
	p.customer = q.Get("customer")
	if p.customer != "" && !config.ValidID(p.customer) {
		return p, false
	}
	return p, true
}
func (a *API) aiConsumption(w http.ResponseWriter, r *http.Request) {
	p, ok := parseAIReport(r, false)
	if !ok {
		fail(w, 400, "invalid_ai_report_filters")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	report, e := a.scope(r).AIReport(ctx, p.from, p.to, p.limit, p.offset)
	if e != nil {
		fail(w, 503, "ai_report_unavailable")
		return
	}
	write(w, 200, report)
}
func (a *API) operatorAIConsumption(w http.ResponseWriter, r *http.Request) {
	p, ok := parseAIReport(r, true)
	if !ok {
		fail(w, 400, "invalid_ai_report_filters")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	report, e := a.Store.OperatorAIReport(ctx, p.from, p.to, p.customer, p.limit, p.offset)
	if e != nil {
		fail(w, 503, "ai_report_unavailable")
		return
	}
	write(w, 200, report)
}
