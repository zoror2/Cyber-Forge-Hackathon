// Package incremental computes bounded query windows and validates modification
// timestamps. It never performs network calls or saves checkpoints itself.
package incremental

import (
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"errors"
	"maps"
	"time"
)

var ErrState = errors.New("incremental_state_invalid")
var ErrNotReady = errors.New("incremental_window_not_ready")
var ErrOutsideWindow = errors.New("incremental_filter_not_respected")

// Checkpoint is persisted in the existing tenant-scoped sync_state.watermark.
// A config change starts again at start_time; it cannot reuse another recipe's
// progress merely because the connector ID stayed the same.
type Checkpoint struct {
	Version    int       `json:"version"`
	ConfigHash string    `json:"config_hash"`
	Through    time.Time `json:"through"`
}

func Begin(c config.Config, hash string, previous *Checkpoint, now time.Time) (*model.SyncWindow, error) {
	if c.Incremental == nil {
		return nil, nil
	}
	i := c.Incremental
	start, err := time.Parse(time.RFC3339Nano, i.StartTime)
	if err != nil {
		return nil, ErrState
	}
	start = start.UTC()
	until := now.UTC().Truncate(time.Second).Add(-time.Duration(i.SafetyLagSeconds) * time.Second)
	since := start
	window := &model.SyncWindow{Since: since, Until: until}
	if previous != nil {
		if previous.Version != 1 || previous.ConfigHash == "" || previous.Through.IsZero() {
			return nil, ErrState
		}
		if previous.ConfigHash == hash {
			if previous.Through.Before(start) {
				return nil, ErrState
			}
			window.PreviousThrough = &previous.Through
			since = previous.Through.Add(-time.Duration(i.OverlapSeconds) * time.Second)
			if since.Before(start) {
				since = start
			}
			if until.Before(previous.Through) {
				until = previous.Through
			} // never rewind on clock regression
		} else {
			window.Reset = true
		}
	}
	if until.Before(start) {
		return nil, ErrNotReady
	}
	window.Since = since
	window.Until = until
	return window, nil
}
func Apply(c engine.Connector, i *config.Incremental, w *model.SyncWindow) engine.Connector {
	if i == nil || w == nil {
		return c
	}
	c.Request.Params = maps.Clone(c.Request.Params)
	if c.Request.Params == nil {
		c.Request.Params = map[string]string{}
	}
	c.Request.Params[i.SinceParam] = w.Since.UTC().Format(time.RFC3339Nano)
	c.Request.Params[i.UntilParam] = w.Until.UTC().Format(time.RFC3339Nano)
	return c
}

// Invalid timestamps are quarantined without echoing their contents. A timestamp
// outside the requested window fails the run: the filter contract is not met.
func CheckRow(row any, i *config.Incremental, w *model.SyncWindow, index int) (*model.Rejection, error) {
	if i == nil || w == nil {
		return nil, nil
	}
	v, ok := mapping.Path(row, i.UpdatedAtPath)
	text, stringOK := v.(string)
	t, err := time.Parse(time.RFC3339Nano, text)
	if !ok || !stringOK || err != nil {
		return &model.Rejection{Index: index, Field: "incremental.updated_at", Reason: "missing or invalid RFC3339 modification timestamp"}, nil
	}
	if t.Before(w.Since) || !t.Before(w.Until) {
		return nil, ErrOutsideWindow
	}
	return nil, nil
}
