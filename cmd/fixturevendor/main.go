// A public static fixture service for Compose wiring. Member A owns the richer
// switchable failure server; this serves only a fixed synthetic JSON response.
package main

import (
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/fixture"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture.Body)
	})
	server := &http.Server{Addr: ":8090", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
