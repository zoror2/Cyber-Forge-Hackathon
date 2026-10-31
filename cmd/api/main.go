package main

import (
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/app"
	"configbridge/internal/engine"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/internal/ui"
	"configbridge/pkg/secrets"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	if os.Getenv("CB_ENV") != "dev" {
		if e = policy.ProductionSafe(); e != nil {
			return e
		}
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
		var local *secrets.Local
		local, e = secrets.NewLocal(db, keys)
		if e == nil && os.Getenv("CB_DEV_MASTER_KEY") != "" {
			e = local.WithMaster(os.Getenv("CB_DEV_MASTER_KEY"))
		}
		backend = local
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
	var limits *api.Limits
	// Load tests measure raw capacity, so dev may switch our own rate limit off.
	if os.Getenv("CB_DEV_RATE_LIMIT") == "off" {
		if os.Getenv("CB_ENV") != "dev" {
			return errors.New("CB_DEV_RATE_LIMIT is only allowed when CB_ENV=dev")
		}
		limits = &api.Limits{}
	}
	alerts, e := app.Notifications(os.Getenv, db)
	if e != nil {
		return e
	}
	notificationTenants := map[string]bool{}
	if alerts != nil {
		for tenant := range alerts.Routes {
			notificationTenants[tenant] = true
		}
	}
	// AI drafter. Every setting comes from the environment (.env locally);
	// nothing is defaulted in code. CB_AI_PROVIDER empty = drafter off.
	// Bedrock uses the AWS default credential chain (task role in AWS, shared
	// config locally). Keys are never logged.
	drafter := &ai.Client{}
	if provider := os.Getenv("CB_AI_PROVIDER"); provider != "" {
		model := os.Getenv("CB_AI_MODEL")
		limit, err := strconv.Atoi(os.Getenv("CB_AI_DAILY_LIMIT"))
		tokens, err2 := strconv.ParseInt(os.Getenv("CB_AI_DAILY_TOKEN_LIMIT"), 10, 64)
		if model == "" || err != nil || limit < 1 || limit > 100 || err2 != nil || tokens < 40000 || tokens > 100000000 {
			return errors.New("CB_AI_PROVIDER set: CB_AI_MODEL, CB_AI_DAILY_LIMIT (1-100) and CB_AI_DAILY_TOKEN_LIMIT (40000-100000000) are required")
		}
		switch provider {
		case "bedrock":
			region := os.Getenv("CB_BEDROCK_REGION")
			if region == "" {
				return errors.New("CB_AI_PROVIDER=bedrock: CB_BEDROCK_REGION is required")
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
			if err != nil {
				return errors.New("bedrock: AWS config could not be loaded")
			}
			drafter = ai.NewBedrock(bedrockruntime.NewFromConfig(awsCfg), model)
			slog.Info("ai drafter", "provider", "bedrock", "region", region, "model", model)
		case "gemini":
			if os.Getenv("GEMINI_API_KEY") == "" {
				return errors.New("CB_AI_PROVIDER=gemini: GEMINI_API_KEY is required")
			}
			drafter = ai.NewGemini(os.Getenv("GEMINI_API_KEY"), model)
			slog.Info("ai drafter", "provider", "gemini", "model", model, "research", "google_search")
		case "groq":
			if os.Getenv("GROQ_API_KEY") == "" {
				return errors.New("CB_AI_PROVIDER=groq: GROQ_API_KEY is required")
			}
			drafter = ai.New(os.Getenv("GROQ_API_KEY"), model)
			slog.Info("ai drafter", "provider", "groq", "model", model)
		default:
			return errors.New("CB_AI_PROVIDER must be gemini, groq, bedrock or empty")
		}
		drafter.DailyLimit, drafter.TokenLimit = limit, tokens
		drafter.Resolve = ai.LookupDNS
	}
	if raw := strings.TrimSpace(os.Getenv("CB_AI_ENABLED_TENANTS")); raw != "" {
		drafter.Tenants = map[string]bool{}
		for _, t := range strings.Split(raw, ",") {
			drafter.Tenants[strings.TrimSpace(t)] = true
		}
	}
	// Console sessions (JWT in an HttpOnly cookie). Dev without a secret gets a
	// random one: sessions then end when the API restarts.
	dev := os.Getenv("CB_ENV") == "dev"
	sessionKey := []byte(os.Getenv("CB_JWT_SECRET"))
	if len(sessionKey) == 0 && dev {
		sessionKey = make([]byte, 32)
		rand.Read(sessionKey)
		slog.Warn("CB_JWT_SECRET unset: random session key, sign-ins end on restart", "tenant_id", "system")
	}
	if len(sessionKey) < 32 {
		return errors.New("CB_JWT_SECRET must be at least 32 bytes")
	}
	signup := os.Getenv("CB_SIGNUP") == "open"
	if signup && !dev {
		return errors.New("CB_SIGNUP=open is development-only; use CB_OPERATOR_TOKEN")
	}
	operator := os.Getenv("CB_OPERATOR_TOKEN")
	if operator != "" && len(operator) < 32 {
		return errors.New("CB_OPERATOR_TOKEN must be at least 32 characters")
	}
	siem, e := app.SIEM(os.Getenv, drafter)
	if e != nil {
		return e
	}
	handler, e := api.New(&api.API{Store: db, Engine: runs, Secrets: svc, Limits: limits, AI: drafter, SIEM: siem, NotificationTenants: notificationTenants,
		SessionKey: sessionKey, InsecureCookies: dev, OpenSignup: signup, OperatorToken: operator})
	if e != nil {
		return e
	}
	addr := os.Getenv("CB_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: ui.Mount(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 3610 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: nil}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); runs.Schedule(ctx, time.Second) }()
	if alerts != nil {
		wg.Add(1)
		go func() { defer wg.Done(); alerts.Run(ctx, time.Second) }()
	}
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
