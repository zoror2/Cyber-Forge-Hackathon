// Package notify delivers bounded, metadata-only connection-failure emails.
package notify

import (
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"regexp"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("smtp_unavailable")

type SMTPConfig struct{ Address, From, Username, Password, Mode, Environment string }
type SMTP struct {
	address, host, from, username, mode string
	password                            func() string
	tlsConfig                           *tls.Config
}

func ValidEmail(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && a.Name == "" && len(s) <= 254 && !strings.ContainsAny(s, "\r\n")
}
func NewSMTP(c SMTPConfig) (*SMTP, error) {
	host, port, e := net.SplitHostPort(c.Address)
	if e != nil || host == "" || port == "" || !ValidEmail(c.From) {
		return nil, ErrUnavailable
	}
	if c.Mode == "" {
		c.Mode = "starttls"
	}
	switch c.Mode {
	case "starttls", "implicit":
	case "plain":
		ip, err := netip.ParseAddr(host)
		if c.Environment != "dev" || err != nil || !ip.IsLoopback() || c.Username != "" || c.Password != "" {
			return nil, ErrUnavailable
		}
	default:
		return nil, ErrUnavailable
	}
	if (c.Username == "") != (c.Password == "") || strings.ContainsAny(c.Username, "\r\n") {
		return nil, ErrUnavailable
	}
	password := c.Password
	return &SMTP{address: c.Address, host: host, from: c.From, username: c.Username, mode: c.Mode, password: func() string { return password }, tlsConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}, nil
}
func (s *SMTP) Send(ctx context.Context, to string, a store.Alert) error {
	safe := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
	if !ValidEmail(to) || !config.ValidID(a.TenantID) || !config.ValidID(a.Connector) || !safe.MatchString(a.ID) || !safe.MatchString(a.RunID) || a.FailureCount < 1 || a.FailureCount > 1000000 || !regexp.MustCompile(`^[a-z_]{1,64}$`).MatchString(a.Error) {
		return ErrUnavailable
	}
	switch a.Outcome {
	case "failed", "incomplete", "completed_with_errors":
	default:
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", s.address)
	if e != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	done := make(chan struct{})
	defer close(done)
	rawConn := conn
	go func() {
		select {
		case <-ctx.Done():
			rawConn.Close()
		case <-done:
		}
	}()
	if s.mode == "implicit" {
		tlsConn := tls.Client(conn, s.tlsConfig.Clone())
		if tlsConn.HandshakeContext(ctx) != nil {
			return ErrUnavailable
		}
		conn = tlsConn
	}
	client, e := smtp.NewClient(conn, s.host)
	if e != nil {
		return ErrUnavailable
	}
	defer client.Close()
	if s.mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return ErrUnavailable
		}
		if client.StartTLS(s.tlsConfig.Clone()) != nil {
			return ErrUnavailable
		}
	}
	if s.username != "" {
		if client.Auth(smtp.PlainAuth("", s.username, s.password(), s.host)) != nil {
			return ErrUnavailable
		}
	}
	if client.Mail(s.from) != nil || client.Rcpt(to) != nil {
		return ErrUnavailable
	}
	writer, e := client.Data()
	if e != nil {
		return ErrUnavailable
	}
	text := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: ConfigBridge: repeated collection failures\r\nMessage-ID: <%s@configbridge.invalid>\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nA connection has failed repeatedly.\r\n\r\nTenant: %s\r\nConnector: %s\r\nConsecutive failed collections: %d\r\nLatest outcome: %s\r\nError category: %s\r\nRun: %s\r\n\r\nReview the connection's current health and run history.\r\nNo vendor credentials or response records are included in this message.\r\n", s.from, to, a.ID, time.Now().UTC().Format(time.RFC1123Z), a.TenantID, a.Connector, a.FailureCount, a.Outcome, a.Error, a.RunID)
	if _, e = writer.Write([]byte(text)); e != nil {
		return ErrUnavailable
	}
	if writer.Close() != nil {
		return ErrUnavailable
	}
	// DATA was accepted. A dropped QUIT response does not require another email.
	client.Quit()
	return nil
}
