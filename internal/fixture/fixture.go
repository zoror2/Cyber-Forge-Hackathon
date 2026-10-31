// Package fixture is an explicit OFFLINE demo adapter, not a real API connection.
package fixture

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/collector"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
)

//go:embed testdata/events.json
var Body []byte

type Fetcher struct{}

func (Fetcher) Fetch(ctx context.Context, c config.Config, emit func(collector.Page) error) error {
	if c.Request.URL != "https://fixture.invalid/events" || c.Auth.Type != "none" {
		return collector.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var payload any
	if err := json.Unmarshal(Body, &payload); err != nil {
		return err
	}
	return emit(collector.Page{Payload: payload, Attempts: 1})
}
