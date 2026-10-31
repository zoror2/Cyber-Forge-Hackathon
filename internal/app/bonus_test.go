package app

import "testing"

func TestNotificationEnvironmentIsExplicitAndTenantBound(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if w, e := Notifications(get, nil); e != nil || w != nil {
		t.Fatal("notifications unexpectedly enabled")
	}
	env["CB_SMTP_ADDR"] = "127.0.0.1:1025"
	env["CB_SMTP_FROM"] = "alerts@example.invalid"
	env["CB_SMTP_TLS_MODE"] = "plain"
	env["CB_ENV"] = "dev"
	env["CB_ALERT_EMAIL_ROUTES"] = `{"tenant-a":"jury@example.invalid"}`
	w, e := Notifications(get, nil)
	if e != nil || w.Routes["tenant-a"] != "jury@example.invalid" || w.Routes["tenant-b"] != "" {
		t.Fatal("invalid routes", e)
	}
	for k, v := range map[string]string{"CB_ENV": "prod", "CB_SMTP_ADDR": "smtp.example.com:1025", "CB_SMTP_FROM": "bad\r\nheader", "CB_ALERT_EMAIL_ROUTES": `{"tenant-a":"a@example.invalid","tenant-a":"b@example.invalid"}`, "CB_SMTP_TLS_MODE": "insecure"} {
		old := env[k]
		env[k] = v
		if _, err := Notifications(get, nil); err == nil {
			t.Fatalf("unsafe %s accepted", k)
		}
		env[k] = old
	}
}
