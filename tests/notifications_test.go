package tests

import (
	"configbridge/internal/api"
	"configbridge/internal/mailcapture"
	"configbridge/internal/notify"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func notificationEnv(t *testing.T) *environment {
	e := setup(t)
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, NotificationTenants: map[string]bool{"tenant-a": true, "tenant-b": true}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	return e
}
func alertConfig(e *environment, id string) config.Config {
	c := userConfig(id, e.vendor.URL+"/flaky")
	c.Request.Params = map[string]string{"scenario_id": id, "fail": "100"}
	c.Retry.MaxAttempts = 1
	c.Notifications = &config.Notifications{Enabled: true, FailureThreshold: 3, CooldownSeconds: 3600}
	return c
}
func readAlerts(t *testing.T, e *environment, tenant, id string) []store.Alert {
	t.Helper()
	var out []store.Alert
	if err := json.Unmarshal(e.request(t, tenant, "GET", "/alerts?connector="+id, nil, 200), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func forceDue(t *testing.T, e *environment, id string) {
	t.Helper()
	if _, err := e.db.Admin.Exec(context.Background(), "UPDATE "+e.db.Schema+".alert_outbox SET next_attempt_at=now()-interval '1 second',lease_until=now()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
}

type testSender struct {
	calls int
	err   error
	to    string
}

func (s *testSender) Send(_ context.Context, to string, a store.Alert) error {
	s.calls++
	s.to = to
	return s.err
}

func TestNotificationThresholdEmailAndTenantIsolation(t *testing.T) {
	e := notificationEnv(t)
	c := alertConfig(e, "mail_failures")
	e.save(t, "tenant-a", c, true)
	// Preview never contributes to the failure streak.
	e.request(t, "tenant-a", "POST", "/connectors/"+c.ID+"/test", nil, 502)
	for i := 0; i < 2; i++ {
		e.run(t, "tenant-a", c.ID, 502)
		if len(readAlerts(t, e, "tenant-a", c.ID)) != 0 {
			t.Fatal("notified before threshold")
		}
	}
	e.run(t, "tenant-a", c.ID, 502)
	alerts := readAlerts(t, e, "tenant-a", c.ID)
	if len(alerts) != 1 || alerts[0].FailureCount != 3 || alerts[0].Status != "pending" {
		t.Fatal(alerts)
	}
	e.run(t, "tenant-a", c.ID, 502)
	if len(readAlerts(t, e, "tenant-a", c.ID)) != 1 {
		t.Fatal("repeated outage queued duplicate emails")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer listener.Close()
	mailbox := &mailcapture.Server{}
	go mailbox.ServeSMTP(ctx, listener)
	sender, err := notify.NewSMTP(notify.SMTPConfig{Address: listener.Addr().String(), From: "alerts@example.invalid", Mode: "plain", Environment: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	w := &notify.Worker{Store: e.db.Store, Sender: sender, Routes: map[string]string{"tenant-a": "jury@example.invalid", "tenant-b": "other@example.invalid"}}
	due, err := e.db.Store.DueAlerts(ctx)
	if err != nil || len(due) != 1 {
		t.Fatal(due, err)
	}
	wrong := due[0]
	wrong.Tenant = "tenant-b"
	if err = w.Process(ctx, wrong); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign alert claimed", err)
	}
	if err = w.Process(ctx, due[0]); err != nil {
		t.Fatal(err)
	}
	messages := mailbox.Messages()
	if len(messages) != 1 || !strings.Contains(messages[0].To, "jury@example.invalid") || !strings.Contains(messages[0].Body, "Consecutive failed collections: 3") {
		t.Fatal("SMTP capture failed", messages)
	}
	if strings.Contains(messages[0].Body, key("tenant-a")) || strings.Contains(messages[0].Body, "Authorization") || strings.Contains(messages[0].Body, "profile") {
		t.Fatal("email exposed sensitive data")
	}
	if got := readAlerts(t, e, "tenant-a", c.ID); got[0].Status != "sent" || got[0].Attempts != 1 {
		t.Fatal(got)
	}
	e.request(t, "tenant-b", "GET", "/alerts?connector="+c.ID, nil, 404)
	if string(e.request(t, "tenant-b", "GET", "/alerts", nil, 200)) != "[]\n" {
		t.Fatal("foreign tenant saw alert")
	}
}

func TestNotificationRecoveryCooldownRetriesAndFencing(t *testing.T) {
	e := notificationEnv(t)
	ctx := context.Background()
	c := alertConfig(e, "mail_retries")
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 3; i++ {
		e.run(t, "tenant-a", c.ID, 502)
	}
	a := readAlerts(t, e, "tenant-a", c.ID)[0]
	s := &testSender{err: errors.New("PRIVATE-SMTP-RESPONSE")}
	worker := &notify.Worker{Store: e.db.Store, Sender: s, Routes: map[string]string{"tenant-a": "jury@example.invalid"}}
	job := store.AlertJob{Tenant: "tenant-a", ID: a.ID, Connector: c.ID}
	if err := worker.Process(ctx, job); err != nil {
		t.Fatal(err)
	}
	got := readAlerts(t, e, "tenant-a", c.ID)[0]
	if got.Status != "pending" || got.Attempts != 1 || got.DeliveryError != "smtp_unavailable" {
		t.Fatal(got)
	}
	if err := worker.Process(ctx, job); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("retried before due", err)
	}
	forceDue(t, e, a.ID)
	s.err = nil
	if err := worker.Process(ctx, job); err != nil {
		t.Fatal(err)
	}
	if s.calls != 2 {
		t.Fatal("unexpected sends", s.calls)
	}
	// Recovery resets the outage, while cooldown survives quick recover/fail cycles.
	c.Request.URL = e.vendor.URL + "/clean"
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	c.Request.URL = e.vendor.URL + "/flaky"
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 3; i++ {
		e.run(t, "tenant-a", c.ID, 502)
	}
	if len(readAlerts(t, e, "tenant-a", c.ID)) != 1 {
		t.Fatal("cooldown bypassed")
	}
	if _, err := e.db.Admin.Exec(ctx, "UPDATE "+e.db.Schema+".alert_state SET last_queued_at=now()-interval '2 hours' WHERE tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	e.run(t, "tenant-a", c.ID, 502)
	alerts := readAlerts(t, e, "tenant-a", c.ID)
	if len(alerts) != 2 {
		t.Fatal("new outage did not queue", alerts)
	}
	pending := alerts[0]
	if pending.Status != "pending" {
		pending = alerts[1]
	}
	scope := e.db.Store.ForTenant("tenant-a")
	claimed, err := scope.ClaimAlert(ctx, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	forceDue(t, e, pending.ID)
	reclaimed, err := scope.ClaimAlert(ctx, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = scope.FinishAlert(ctx, claimed, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("stale worker published delivery")
	}
	if err = scope.FinishAlert(ctx, reclaimed, false); err != nil {
		t.Fatal(err)
	}
	// A healthy run cancels a pending email before dispatch.
	c.Request.URL = e.vendor.URL + "/clean"
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	for _, x := range readAlerts(t, e, "tenant-a", c.ID) {
		if x.ID == pending.ID && x.Status != "cancelled" {
			t.Fatal("recovered connector kept pending alert", x)
		}
	}
	err = scope.WithTx(ctx, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, "DELETE FROM alert_outbox"); return err })
	if err == nil {
		t.Fatal("runtime deleted alert history")
	}
}

func TestNotificationRetryCapAndUnavailableRoute(t *testing.T) {
	e := notificationEnv(t)
	c := alertConfig(e, "mail_cap")
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 3; i++ {
		e.run(t, "tenant-a", c.ID, 502)
	}
	a := readAlerts(t, e, "tenant-a", c.ID)[0]
	s := &testSender{err: errors.New("down")}
	w := &notify.Worker{Store: e.db.Store, Sender: s, Routes: map[string]string{}}
	j := store.AlertJob{Tenant: "tenant-a", ID: a.ID, Connector: c.ID}
	if err := w.Process(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if s.calls != 0 {
		t.Fatal("sent without tenant route")
	}
	w.Routes["tenant-a"] = "jury@example.invalid"
	for i := 0; i < 5; i++ {
		forceDue(t, e, a.ID)
		if err := w.Process(context.Background(), j); err != nil {
			t.Fatal(err)
		}
	}
	got := readAlerts(t, e, "tenant-a", c.ID)[0]
	if got.Status != "abandoned" || got.Attempts != 5 || s.calls != 5 {
		t.Fatal("retry cap failed", got)
	}
	if err := w.Process(context.Background(), j); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("abandoned retry", err)
	}
}

func TestNotificationOptOutAndMappingFailures(t *testing.T) {
	e := notificationEnv(t)
	c := alertConfig(e, "mail_mapping")
	c.Request.URL = e.vendor.URL + "/malformed"
	c.Notifications.FailureThreshold = 1
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	alerts := readAlerts(t, e, "tenant-a", c.ID)
	if len(alerts) != 1 || alerts[0].Error != "mapping_rejections" {
		t.Fatal("degraded run not notified", alerts)
	}
	c.Notifications.Enabled = false
	e.save(t, "tenant-a", c, true)
	if got := readAlerts(t, e, "tenant-a", c.ID); got[0].Status != "cancelled" {
		t.Fatal("opt out did not cancel pending email", got)
	}
	e.run(t, "tenant-a", c.ID, 200)
	if len(readAlerts(t, e, "tenant-a", c.ID)) != 1 {
		t.Fatal("opt-out generated email")
	}
}
