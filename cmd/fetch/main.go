// fetch is a developer command that runs ONE connector config through the real
// engine and prints what comes back. It lets you test a connector by hand
// (against the mock vendor or a real vendor) without the API or database.
//
//	fetch -config examples/mock_users.json
//	fetch -config my.json -show 3                  print the first 3 records of each page
//
// Egress rules come from internal/app.Policy, exactly like the API: production
// rules by default; CB_ENV=dev plus CB_DEV_ALLOW_PRIVATE / CB_DEV_CA_FILE reach
// the TLS mock inside Docker. Plain HTTP is always refused.
//
// Secrets come from environment variables, never from the config file:
//
//	CB_SECRET_<NAME>        the value      (NAME = auth.secret, upper-cased, "-" -> "_")
//	CB_SECRET_<NAME>_HOSTS  comma-separated exact hosts the value may be sent to
//
// Exit code 0 = success, 1 = any failure (bad config, blocked, vendor error).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"configbridge/internal/app"
	"configbridge/internal/engine"
)

// envSecrets reads secrets from environment variables. Dev use only: the real
// store (Member B) is per-tenant and KMS-encrypted. This one ignores the tenant.
type envSecrets struct{}

func (envSecrets) Get(_ context.Context, _ string, name string) (engine.Secret, error) {
	key := "CB_SECRET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return engine.Secret{}, fmt.Errorf("environment variable %s is not set", key) // name only, never a value
	}
	var hosts []string
	for _, h := range strings.Split(os.Getenv(key+"_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return engine.NewSecret(value, hosts...), nil // no hosts -> the engine refuses to use it
}

func main() {
	configPath := flag.String("config", "", "path to a connector JSON file (required)")
	show := flag.Int("show", 2, "records to print per page (0 = none)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)) // logs on stderr, data on stdout
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	if *configPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 1. Read the config: at most 1 MB, unknown fields rejected (a typo like
	//    "alowed_ports" must fail loudly, not silently fall back to a default).
	f, err := os.Open(*configPath)
	if err != nil {
		fail("open config", err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	if err != nil {
		fail("read config", err)
	}
	if len(raw) > 1<<20 {
		fail("read config", errors.New("config is larger than 1 MB"))
	}
	var c engine.Connector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		fail("parse config", err)
	}

	// 2. Egress policy: the same rules as the API (internal/app.Policy).
	//    Production rules unless CB_ENV=dev enables CB_DEV_ALLOW_PRIVATE / CB_DEV_CA_FILE.
	policy, err := app.Policy(os.Getenv)
	if err != nil {
		fail("egress policy", err)
	}
	if policy.ProductionSafe() != nil {
		log.Warn("DEV egress overrides active: never use outside local testing")
	}

	// 3. Run it. Ctrl+C cancels cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	eng := engine.New(envSecrets{}, policy, log)
	out := json.NewEncoder(os.Stdout)
	res, err := eng.Fetch(ctx, c, func(p engine.Page) error {
		fmt.Printf("page %d: %d records\n", p.Number, len(p.Items))
		for i := 0; i < len(p.Items) && i < *show; i++ {
			if err := out.Encode(p.Items[i]); err != nil {
				return err
			}
		}
		return nil
	})
	fmt.Printf("done: %d pages, %d records\n", res.Pages, res.Items)
	if err != nil {
		fail("fetch failed", err)
	}
}
