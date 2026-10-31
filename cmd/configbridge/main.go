package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/api"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/engine"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/fixture"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/store"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/collector"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/secrets"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	token := os.Getenv("CONFIGBRIDGE_ADMIN_TOKEN")
	if len(token) < 32 {
		return errors.New("CONFIGBRIDGE_ADMIN_TOKEN requires at least 32 characters")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db, err := store.Open(setup, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	if db.Migrate(setup) != nil {
		return errors.New("database migration failed")
	}
	if db.Recover(setup) != nil {
		return errors.New("run recovery failed")
	}
	backendName := os.Getenv("CONFIGBRIDGE_SECRETS_BACKEND")
	if backendName == "" {
		backendName = "local"
	}
	var backend secrets.Backend
	switch backendName {
	case "local":
		backend, err = secrets.NewLocal(db.Pool, os.Getenv("CONFIGBRIDGE_MASTER_KEY"))
	case "aws":
		var cfgErr error
		cfg, cfgErr := awsconfig.LoadDefaultConfig(setup)
		if cfgErr != nil {
			return errors.New("AWS configuration unavailable")
		}
		backend = &secrets.AWS{Client: secretsmanager.NewFromConfig(cfg), Prefix: "configbridge/"}
	default:
		return errors.New("unknown secret backend")
	}
	if err != nil {
		return err
	}
	secretService := &secrets.Service{Pool: db.Pool, Backend: backend, BackendName: backendName}
	// Member A wires its production Fetcher here, taking secretService as Reader.
	var fetcher collector.Fetcher = collector.Unavailable{}
	mode := "live"
	if os.Getenv("CONFIGBRIDGE_FIXTURE_MODE") == "1" {
		fetcher = fixture.Fetcher{}
		mode = "fixture"
	}
	runner := engine.New(db, fetcher, mode)
	handler, err := api.New(&api.API{Store: db, Engine: runner, Secrets: secretService}, token)
	if err != nil {
		return err
	}
	addr := os.Getenv("CONFIGBRIDGE_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 3610 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); runner.Schedule(ctx, time.Second) }()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	log.Printf("ConfigBridge started (mode=%s, auth required)", mode)
	select {
	case err = <-done:
		stop()
	case <-ctx.Done():
	}
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	server.Shutdown(shutdown)
	stop()
	wg.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("HTTP server failed")
	}
	return nil
}
