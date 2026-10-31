// Package ui serves the bundled web console. It is static files only: no data
// and no secrets are served here. Every data call the page makes goes through
// the authenticated API. Browser sign-in uses HttpOnly session cookies; the
// JavaScript cannot read those cookies; the API never returns stored vendor
// secret values. Login and credential forms submit locally entered values.
package ui

import (
	"embed"
	"io/fs"
	"net/http"

	"configbridge/pkg/ocsf"
)

//go:embed static
var files embed.FS

// csp: scripts, styles and fetches from this origin only; no inline script,
// no framing, no form posts, no third-party CDNs.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// Mount puts the console at /ui/ and redirects / to it; everything else goes to api.
func Mount(api http.Handler) http.Handler {
	static, _ := fs.Sub(files, "static")
	server := http.StripPrefix("/ui/", http.FileServer(http.FS(static)))
	schema, err := ocsf.Public()
	if err != nil {
		panic("ui: OCSF metadata: " + err.Error())
	}
	mux := http.NewServeMux()
	mux.Handle("/", api)
	mux.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
	mux.HandleFunc("GET /ui/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.URL.Path == "/ui/ocsf.json" {
			h.Set("Content-Type", "application/json")
			w.Write(schema)
			return
		}
		server.ServeHTTP(w, r)
	})
	return mux
}
