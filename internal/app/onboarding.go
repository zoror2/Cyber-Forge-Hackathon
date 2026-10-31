package app

import (
	"configbridge/internal/onboarding"
	"errors"
)

func Onboarding(getenv func(string) string) (*onboarding.Console, error) {
	enabled := getenv("CB_UI_ENABLED")
	if enabled != "" && enabled != "0" && enabled != "1" {
		return nil, errors.New("CB_UI_ENABLED must be 0 or 1")
	}
	if enabled == "0" {
		return nil, nil
	}
	if getenv("CB_ENV") != "dev" {
		if enabled == "1" {
			return nil, errors.New("local onboarding console is development-only")
		}
		return nil, nil
	}
	origin := getenv("CB_UI_ORIGIN")
	if origin == "" {
		origin = "http://127.0.0.1:8080"
	}
	return onboarding.New(origin)
}
