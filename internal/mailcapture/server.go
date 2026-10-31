// Package mailcapture is a bounded loopback-only test mailbox, never a relay.
package mailcapture

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type Message struct {
	From string `json:"from"`
	To   string `json:"to"`
	Body string `json:"body"`
}
type Server struct {
	mu       sync.Mutex
	messages []Message
}

func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message{}, s.messages...)
}
func (s *Server) ServeSMTP(ctx context.Context, l net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-done:
		}
	}()
	slots := make(chan struct{}, 16)
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); s.connection(ctx, c) }()
		default:
			c.Close()
		}
	}
}
func (s *Server) connection(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	r := textproto.NewReader(bufio.NewReader(io.LimitReader(c, 128<<10)))
	write := func(v string) { fmt.Fprint(c, v+"\r\n") }
	write("220 localhost ConfigBridge synthetic capture")
	var from, to string
	for n := 0; n < 50; n++ {
		line, e := r.ReadLine()
		if e != nil || len(line) > 1024 {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		switch verb {
		case "EHLO", "HELO":
			write("250 localhost")
		case "MAIL":
			if !strings.HasPrefix(strings.ToUpper(arg), "FROM:") {
				write("501 invalid sender")
				continue
			}
			from = strings.TrimSpace(arg[5:])
			write("250 ok")
		case "RCPT":
			if from == "" || !strings.HasPrefix(strings.ToUpper(arg), "TO:") {
				write("503 sender required")
				continue
			}
			to = strings.TrimSpace(arg[3:])
			write("250 ok")
		case "DATA":
			if from == "" || to == "" {
				write("503 envelope required")
				continue
			}
			write("354 end with dot")
			body, e := io.ReadAll(io.LimitReader(r.DotReader(), (64<<10)+1))
			if e != nil || len(body) > 64<<10 {
				write("552 message too large")
				return
			}
			s.mu.Lock()
			if len(s.messages) >= 100 {
				s.messages = s.messages[1:]
			}
			s.messages = append(s.messages, Message{from, to, string(body)})
			s.mu.Unlock()
			write("250 captured locally")
			from = ""
			to = ""
		case "RSET":
			from = ""
			to = ""
			write("250 ok")
		case "NOOP":
			write("250 ok")
		case "QUIT":
			write("221 bye")
			return
		default:
			write("502 unsupported")
		}
	}
}

var page = template.Must(template.New("mail").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Local alert mailbox</title><h1>Local alert mailbox</h1><p>Synthetic capture only. No messages leave this computer.</p>{{range .}}<article><h2>{{.To}}</h2><pre>{{.Body}}</pre></article>{{else}}<p>No messages received.</p>{{end}}</html>`))

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /messages", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Messages())
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		page.Execute(w, s.Messages())
	})
	return mux
}
