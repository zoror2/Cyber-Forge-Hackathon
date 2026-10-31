// mockvendor is the synthetic failure server; TLS keeps the connector validator
// and production request policy intact during local integration tests.
package main

import (
	"configbridge/internal/mockvendor"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	server := &http.Server{Addr: addr, Handler: mockvendor.Handler(), ReadHeaderTimeout: 5 * time.Second}
	cert, key := os.Getenv("MOCK_TLS_CERT"), os.Getenv("MOCK_TLS_KEY")
	log.Print("mockvendor started (synthetic test data only)")
	var err error
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}
