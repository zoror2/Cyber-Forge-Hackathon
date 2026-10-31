package model

import (
	"encoding/json"
	"time"
)

type Provenance struct {
	TenantID  string    `json:"tenant_id"`
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
}
type User struct {
	Provenance
	Name      *string    `json:"name"`
	Email     *string    `json:"email"`
	Status    *string    `json:"status"`
	LastLogin *time.Time `json:"last_login"`
}
type Device struct {
	Provenance
	Hostname *string    `json:"hostname"`
	IP       *string    `json:"ip"`
	OS       *string    `json:"os"`
	Owner    *string    `json:"owner"`
	LastSeen *time.Time `json:"last_seen"`
}
type Event struct {
	Provenance
	Type               string    `json:"type"`
	Severity           string    `json:"severity"`
	Timestamp          time.Time `json:"timestamp"`
	Description        string    `json:"description"`
	Vendor             *string   `json:"vendor,omitempty"`
	Product            *string   `json:"product,omitempty"`
	TimestampPrecision string    `json:"timestamp_precision,omitempty"`
}
type Record struct {
	TenantID           string
	Entity, ID, Source string
	FetchedAt          time.Time
	Payload            json.RawMessage
}
type Rejection struct {
	Page   int    `json:"page"`
	Index  int    `json:"record_index"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Run is the shared persisted result; Error is always a safe, fixed category.
type Run struct {
	TenantID      string      `json:"tenant_id"`
	ID            string      `json:"id"`
	Connector     string      `json:"connector"`
	ConfigVersion int         `json:"config_version"`
	ConfigHash    string      `json:"config_hash"`
	Mode          string      `json:"mode"`
	StartedAt     time.Time   `json:"started_at"`
	EndedAt       *time.Time  `json:"ended_at"`
	Outcome       string      `json:"outcome"`
	Pages         int         `json:"pages"`
	Attempts      int         `json:"attempts"`
	Received      int         `json:"received"`
	Accepted      int         `json:"accepted"`
	Quarantined   int         `json:"quarantined"`
	Error         string      `json:"error"`
	Incremental   *SyncWindow `json:"incremental,omitempty"`
}
type SyncWindow struct {
	Since           time.Time  `json:"since"`
	Until           time.Time  `json:"until"`
	PreviousThrough *time.Time `json:"previous_through,omitempty"`
	Committed       bool       `json:"checkpoint_committed"`
	Reset           bool       `json:"config_changed_reset,omitempty"`
}
