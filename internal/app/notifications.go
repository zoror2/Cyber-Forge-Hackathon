package app

import (
	"configbridge/internal/notify"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
)

func Notifications(getenv func(string) string, db *store.Store) (*notify.Worker, error) {
	address, routesRaw := getenv("CB_SMTP_ADDR"), getenv("CB_ALERT_EMAIL_ROUTES")
	accountEmail := getenv("CB_ALERT_USE_ACCOUNT_EMAIL")
	if address == "" && routesRaw == "" && (accountEmail == "" || accountEmail == "0") {
		return nil, nil
	}
	if address == "" || (accountEmail != "" && accountEmail != "0" && accountEmail != "1") {
		return nil, errors.New("invalid notification configuration")
	}
	routes := map[string]string{}
	if routesRaw != "" && (config.CheckJSON([]byte(routesRaw)) != nil || json.Unmarshal([]byte(routesRaw), &routes) != nil) {
		return nil, errors.New("invalid tenant notification routes")
	}
	if len(routes) > 1000 || (len(routes) == 0 && accountEmail != "1") {
		return nil, errors.New("invalid tenant notification routes")
	}
	for tenant, email := range routes {
		if !config.ValidID(tenant) || !notify.ValidEmail(email) {
			return nil, errors.New("invalid tenant notification route")
		}
	}
	sender, err := notify.NewSMTP(notify.SMTPConfig{Address: address, From: getenv("CB_SMTP_FROM"), Username: getenv("CB_SMTP_USERNAME"), Password: getenv("CB_SMTP_PASSWORD"), Mode: getenv("CB_SMTP_TLS_MODE"), Environment: getenv("CB_ENV")})
	if err != nil {
		return nil, errors.New("invalid SMTP configuration")
	}
	w := &notify.Worker{Store: db, Sender: sender, Routes: routes}
	if accountEmail == "1" {
		w.AccountRecipient = func(ctx context.Context, tenant string) (string, error) {
			return db.ForTenant(tenant).AlertRecipient(ctx)
		}
	}
	return w, nil
}
