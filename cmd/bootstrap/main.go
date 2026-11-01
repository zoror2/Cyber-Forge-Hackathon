// bootstrap is an operator-only provisioning command, not an HTTP endpoint.
package main

import (
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("bootstrap failed", "tenant_id", "system", "error", e.Error())
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminDSN, appDSN := os.Getenv("MIGRATION_DATABASE_URL"), os.Getenv("DATABASE_URL")
	u, e := url.Parse(appDSN)
	if e != nil || u.User == nil {
		return errors.New("runtime DATABASE_URL required")
	}
	role := u.User.Username()
	if !config.ValidID(role) {
		return errors.New("invalid runtime database role")
	}
	if os.Getenv("CB_CREATE_RUNTIME_ROLE") == "1" {
		if os.Getenv("CB_ENV") != "dev" {
			return errors.New("runtime role creation is development-only")
		}
		p, e := pgxpool.New(ctx, adminDSN)
		if e != nil {
			return errors.New("provisioning DB unavailable")
		}
		defer p.Close()
		var exists bool
		if p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists) != nil {
			return errors.New("role lookup failed")
		}
		if !exists {
			password, ok := u.User.Password()
			if !ok || len(password) < 20 {
				return errors.New("strong runtime database password required")
			}
			sql := "CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '" + strings.ReplaceAll(password, "'", "''") + "'"
			if _, e = p.Exec(ctx, sql); e != nil {
				return errors.New("role creation failed")
			}
		}
	}
	if store.Migrate(ctx, adminDSN, role) != nil {
		return errors.New("database migration failed")
	}
	// Accounts are created by sign-up (operator token in production); a
	// bootstrap tenant + API key is optional, e.g. for local smoke scripts.
	if os.Getenv("CB_BOOTSTRAP_TENANT") == "" {
		slog.Info("migrations complete; no bootstrap tenant requested", "tenant_id", "system")
		return nil
	}
	if store.Bootstrap(ctx, adminDSN, os.Getenv("CB_BOOTSTRAP_TENANT"), os.Getenv("CB_BOOTSTRAP_API_KEY"), os.Getenv("CB_TENANT_KMS_KEY")) != nil {
		return errors.New("tenant bootstrap failed")
	}
	slog.Info("bootstrap complete", "tenant_id", os.Getenv("CB_BOOTSTRAP_TENANT"))
	return nil
}
