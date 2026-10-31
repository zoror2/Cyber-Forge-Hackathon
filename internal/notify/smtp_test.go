package notify

import (
	"configbridge/internal/mailcapture"
	"configbridge/internal/store"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSMTPTransportSecurityAndMetadata(t *testing.T) {
	for _, c := range []SMTPConfig{
		{Address: "127.0.0.1:1025", From: "sender@example.invalid", Mode: "plain", Environment: "prod"},
		{Address: "smtp.example.com:1025", From: "sender@example.invalid", Mode: "plain", Environment: "dev"},
		{Address: "127.0.0.1:1025", From: "sender@example.invalid", Mode: "plain", Environment: "dev", Username: "user", Password: "secret"},
		{Address: "127.0.0.1:1025", From: "bad\r\nBcc: other@example.invalid", Mode: "starttls"},
	} {
		if _, err := NewSMTP(c); err == nil {
			t.Fatal("unsafe SMTP config accepted")
		}
	}
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	defer cert.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: cert.TLS.Certificates, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	box := &mailcapture.Server{}
	go box.ServeSMTP(ctx, tlsListener)
	sender, err := NewSMTP(SMTPConfig{Address: listener.Addr().String(), From: "sender@example.invalid", Mode: "implicit"})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Alert{TenantID: "tenant-a", ID: "alert-1", Connector: "fixture", RunID: "run-1", FailureCount: 3, Error: "auth_failed", Outcome: "failed"}
	if sender.Send(ctx, "recipient@example.invalid", a) == nil {
		t.Fatal("untrusted SMTP certificate accepted")
	}
	sender.tlsConfig.RootCAs = cert.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if err = sender.Send(ctx, "recipient@example.invalid", a); err != nil {
		t.Fatal("trusted TLS delivery failed", err)
	}
	if len(box.Messages()) != 1 {
		t.Fatal("message not captured")
	}
	if sender.Send(ctx, "a@example.invalid\r\nBcc: b@example.invalid", a) == nil {
		t.Fatal("header injection accepted")
	}
	sender.password = func() string { return "SYNTHETIC-SMTP-PASSWORD" }
	if strings.Contains(fmt.Sprintf("%+v %#v", sender, sender), "SYNTHETIC-SMTP-PASSWORD") {
		t.Fatal("sender formatting leaked password")
	}
}
func TestSMTPRequiresStartTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	box := &mailcapture.Server{}
	go box.ServeSMTP(ctx, listener)
	sender, err := NewSMTP(SMTPConfig{Address: listener.Addr().String(), From: "sender@example.invalid", Mode: "starttls"})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Alert{TenantID: "tenant-a", ID: "alert-1", Connector: "fixture", RunID: "run-1", FailureCount: 3, Error: "auth_failed", Outcome: "failed"}
	if sender.Send(ctx, "recipient@example.invalid", a) == nil || len(box.Messages()) != 0 {
		t.Fatal("SMTP downgraded to plaintext")
	}
}

func TestSMTPDeadlineAndUntrustedErrorRedaction(t *testing.T) {
	for _, scenario := range []string{"hang", "error"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				if scenario == "hang" {
					<-done
				} else {
					fmt.Fprint(c, "530 PRIVATE-SMTP-RESPONSE\r\n")
				}
			}()
			defer close(done)
			s, err := NewSMTP(SMTPConfig{Address: listener.Addr().String(), From: "sender@example.invalid", Mode: "plain", Environment: "dev"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			a := store.Alert{TenantID: "tenant-a", ID: "alert-1", Connector: "fixture", RunID: "run-1", FailureCount: 3, Error: "auth_failed", Outcome: "failed"}
			err = s.Send(ctx, "recipient@example.invalid", a)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unbounded or unsafe SMTP failure", err)
			}
		})
	}
}
