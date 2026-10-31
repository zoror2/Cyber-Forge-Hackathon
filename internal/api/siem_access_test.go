package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestSIEMRoutesRejectUnauthenticatedRequests(t *testing.T) {
	h, e := New(&API{Authenticate: func(context.Context, string) (string, error) { return "", errors.New("invalid") }})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/siem/refresh", "/siem/findings", "/siem/ask", "/ai/usage", "/ai/consumption"} {
		for _, method := range []string{"GET", "POST"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			if w.Code != 401 {
				t.Fatal(path, w.Code)
			}
		}
	}
}
