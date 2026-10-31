package app

import (
	"configbridge/internal/notify"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"encoding/json"
	"errors"
)

func Notifications(getenv func(string) string, db *store.Store) (*notify.Worker, error) {
	address, routesRaw := getenv("CB_SMTP_ADDR"), getenv("CB_ALERT_EMAIL_ROUTES")
	if address == "" && routesRaw == "" {
		return nil, nil
	}
	if address == "" || config.CheckJSON([]byte(routesRaw)) != nil {
		return nil, errors.New("invalid notification configuration")
	}
	var routes map[string]string
	if json.Unmarshal([]byte(routesRaw), &routes) != nil || len(routes) == 0 || len(routes) > 1000 {
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
	return &notify.Worker{Store: db, Sender: sender, Routes: routes}, nil
}
