package model

import (
	"encoding/json"
	"time"
)

// Record is one stored OCSF event. Payload is the full OCSF JSON; the other
// fields are the columns used for tenant isolation, upsert and lookups.
type Record struct {
	TenantID  string
	Class     string // OCSF class name, e.g. "vulnerability_finding"
	ClassUID  int    // OCSF class_uid, e.g. 2002
	ID        string // the class identity field (finding_info.uid, user.uid, ...)
	Source    string // connector id
	FetchedAt time.Time
	Payload   json.RawMessage
}
type Rejection struct {
	Page   int    `json:"page"`
	Index  int    `json:"record_index"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Run is the shared persisted result; Error is always a safe, fixed category.
type Run struct {
	TenantID      string     `json:"tenant_id"`
	ID            string     `json:"id"`
	Connector     string     `json:"connector"`
	ConfigVersion int        `json:"config_version"`
	ConfigHash    string     `json:"config_hash"`
	Mode          string     `json:"mode"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at"`
	Outcome       string     `json:"outcome"`
	Pages         int        `json:"pages"`
	Attempts      int        `json:"attempts"`
	Received      int        `json:"received"`
	Accepted      int        `json:"accepted"`
	Quarantined   int        `json:"quarantined"`
	Skipped       int        `json:"skipped"`
	Error         string     `json:"error"`
}
