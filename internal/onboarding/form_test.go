package onboarding

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
)

func values() url.Values {
	return url.Values{"id": {"demo"}, "name": {"Demo users"}, "entity": {"user"}, "url": {"https://api.example.com/users"}, "auth_type": {"none"}, "pagination_type": {"none"}, "path_id": {"id"}, "transform_id": {"string"}, "path_name": {"profile.name"}}
}
func TestFormUsesSharedValidatorAndCommonSchemas(t *testing.T) {
	for _, entity := range []string{"user", "device", "event"} {
		v := values()
		v.Set("entity", entity)
		v.Del("path_name")
		if entity == "event" {
			v.Set("constant_type", "security_event")
			v.Set("constant_severity", "unknown")
			v.Set("path_timestamp", "created")
			v.Set("transform_timestamp", "datetime")
			v.Set("timezone_timestamp", "UTC")
			v.Set("path_description", "description")
		}
		c, issues := Build(v)
		if len(issues) > 0 || len(c.Validate()) > 0 {
			t.Fatal(entity, issues)
		}
	}
	for name, change := range map[string]func(url.Values){
		"tenant": func(v url.Values) { v.Set("tenant_id", "other") }, "activation": func(v url.Values) { v.Set("status", "live") }, "credential": func(v url.Values) { v.Set("password", "private") }, "destination": func(v url.Values) { v.Set("email_to", "other@example.invalid") },
		"duplicate": func(v url.Values) { v.Add("id", "other") }, "http": func(v url.Values) { v.Set("url", "http://example.com") }, "url token": func(v url.Values) { v.Set("url", "https://user:private@example.com") }, "query token": func(v url.Values) { v.Set("query_params", "apiKey=private") },
		"bad page": func(v url.Values) { v.Set("pagination_type", "page"); v.Set("page_size", "bad") }, "bad mapping": func(v url.Values) { v.Set("transform_id", "exec") }, "two mapping inputs": func(v url.Values) { v.Set("constant_id", "duplicate") }, "bad interval": func(v url.Values) { v.Set("schedule_enabled", "on"); v.Set("interval_seconds", "-1") },
		"bad lookup": func(v url.Values) { v.Set("transform_name", "lookup"); v.Set("lookup_name", `{"a":"b","a":"c"}`) }, "bad threshold": func(v url.Values) { v.Set("notifications_enabled", "on"); v.Set("failure_threshold", "101") },
	} {
		t.Run(name, func(t *testing.T) {
			v := values()
			change(v)
			if _, issues := Build(v); len(issues) == 0 {
				t.Fatal("unsafe form accepted")
			}
		})
	}
	v := values()
	v.Set("notifications_enabled", "on")
	c, issues := Build(v)
	if len(issues) > 0 || c.Notifications.FailureThreshold != 3 || c.Notifications.CooldownSeconds != 3600 {
		t.Fatal(c, issues)
	}
}
func TestConsoleCSRFBindingExpiryAndRendering(t *testing.T) {
	c, err := New("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.clock = func() time.Time { return now }
	token := c.Token("tenant-a", "actor-a")
	if !c.ValidToken("tenant-a", "actor-a", token) {
		t.Fatal("token refused")
	}
	for _, pair := range [][2]string{{"tenant-b", "actor-a"}, {"tenant-a", "actor-b"}} {
		if c.ValidToken(pair[0], pair[1], token) {
			t.Fatal("cross-principal token accepted")
		}
	}
	if c.ValidToken("tenant-a", "actor-a", token+"x") {
		t.Fatal("tampered token accepted")
	}
	now = now.Add(31 * time.Minute)
	if c.ValidToken("tenant-a", "actor-a", token) {
		t.Fatal("expired token accepted")
	}
	for _, origin := range []string{"http://example.com", "https://user:pass@localhost", "http://127.0.0.1:8080/?x=1", "http://127.0.0.1:8080/path"} {
		if _, err = New(origin); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	for _, entity := range []string{"user", "device", "event"} {
		var body bytes.Buffer
		if err = Render(&body, View{Token: "csrf", Entity: entity, Fields: MappingRows(entity), Values: values()}); err != nil || !strings.Contains(body.String(), "</html>") {
			t.Fatal("incomplete form rendering", err)
		}
	}
	var body bytes.Buffer
	if err = Render(&body, View{Token: "csrf", JSON: `<script>alert(1)</script>`, ID: "demo"}); err != nil || strings.Contains(body.String(), "<script>") {
		t.Fatal("output not escaped", err)
	}
}
