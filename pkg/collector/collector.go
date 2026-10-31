// Package collector is Member A's integration point. Implementations own egress,
// auth, retry, pagination, HTTP budgets, and safe request error classification.
package collector

import (
	"context"
	"errors"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
)

var ErrUnavailable = errors.New("request_engine_not_connected")

// Page contains one decoded JSON response; the runner extracts response.items_path.
type Page struct {
	Payload  any
	Attempts int
}
type Fetcher interface {
	Fetch(ctx context.Context, cfg config.Config, emit func(Page) error) error
}
type Unavailable struct{}

func (Unavailable) Fetch(context.Context, config.Config, func(Page) error) error {
	return ErrUnavailable
}

// Failure carries ONLY a fixed public category, never a URL, body or credential.
type Failure struct{ Code string }

func (f Failure) Error() string { return "collection failed" }
func Category(err error) string {
	if errors.Is(err, ErrUnavailable) {
		return "request_engine_not_connected"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	var f Failure
	if errors.As(err, &f) {
		switch f.Code {
		case "auth_failed", "rate_limited", "destination_denied", "response_too_large", "pagination_failed", "invalid_json", "network_failed":
			return f.Code
		}
	}
	return "collection_failed"
}
