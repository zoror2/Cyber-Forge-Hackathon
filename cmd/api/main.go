package main

import (
	"configbridge/internal/api"
	"configbridge/internal/app"
	"configbridge/internal/engine"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/pkg/secrets"
	"context"
	"encoding/json"
	"errors"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("API startup failed", "tenant_id", "system", "error", e.Error())
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	policy, e := app.Policy(os.Getenv)
	if e != nil {
		return e
	}
	db, e := store.Open(setup, os.Getenv("DATABASE_URL"))
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	if db.Recover(setup) != nil {
		return errors.New("run recovery failed")
	}
	var backend secrets.Backend
	name := os.Getenv("CB_SECRETS_BACKEND")
	switch name {
	case "local":
		if os.Getenv("CB_ENV") != "dev" {
			return errors.New("local encrypted secrets are development-only")
		}
		var keys map[string]string
		if json.Unmarshal([]byte(os.Getenv("CB_DEV_TENANT_KEYS")), &keys) != nil {
			return errors.New("invalid development tenant keyring")
		}
		backend, e = secrets.NewLocal(db, keys)
	case "aws":
		cfg, err := awsconfig.LoadDefaultConfig(setup)
		if err != nil {
			return errors.New("AWS configuration unavailable")
		}
		backend = &secrets.AWS{Client: secretsmanager.NewFromConfig(cfg), Store: db, Prefix: "configbridge/"}
	default:
		return errors.New("CB_SECRETS_BACKEND must be local or aws")
	}
	if e != nil {
		return e
	}
	svc := &secrets.Service{Store: db, Backend: backend, BackendName: name}
	requests := engine.New(svc, policy, slog.Default())
	runs := runner.New(db, requests)
	handler, e := api.New(&api.API{Store: db, Engine: runs, Secrets: svc})
	if e != nil {
		return e
	}
	addr := os.Getenv("CB_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 3610 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: nil}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); runs.Schedule(ctx, time.Second) }()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("API started", "tenant_id", "system", "authentication", "tenant API keys")
	select {
	case e = <-done:
		stop()
	case <-ctx.Done():
	}
	shutdown, end := context.WithTimeout(context.Background(), 10*time.Second)
	defer end()
	server.Shutdown(shutdown)
	server.Close()
	stop()
	wg.Wait()
	if e != nil && !errors.Is(e, http.ErrServerClosed) {
		return errors.New("HTTP server failed")
	}
	return nil
}
