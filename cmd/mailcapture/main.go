package main

import (
	"configbridge/internal/mailcapture"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("Local mail capture stopped: ", err)
	}
}
func run() error {
	smtpAddr, httpAddr := os.Getenv("CB_CAPTURE_SMTP_ADDR"), os.Getenv("CB_CAPTURE_HTTP_ADDR")
	if smtpAddr == "" {
		smtpAddr = "127.0.0.1:1025"
	}
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8025"
	}
	for _, address := range []string{smtpAddr, httpAddr} {
		host, _, err := net.SplitHostPort(address)
		ip, e := netip.ParseAddr(host)
		if err != nil || e != nil || !ip.IsLoopback() {
			return errors.New("capture listeners must use literal loopback addresses")
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	listener, err := net.Listen("tcp", smtpAddr)
	if err != nil {
		return errors.New("SMTP capture listener unavailable")
	}
	defer listener.Close()
	capture := &mailcapture.Server{}
	server := &http.Server{Addr: httpAddr, Handler: capture.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 2)
	go func() { done <- capture.ServeSMTP(ctx, listener) }()
	go func() { done <- server.ListenAndServe() }()
	log.Print("Synthetic loopback mailbox started; no external delivery")
	select {
	case <-ctx.Done():
	case <-done:
	}
	shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	server.Shutdown(shutdown)
	return nil
}
