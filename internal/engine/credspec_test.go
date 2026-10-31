package engine

import (
	"reflect"
	"testing"
)

func TestCredentialSpec(t *testing.T) {
	cases := []struct {
		a      Auth
		fields []string
		hosts  []string
		user   bool
	}{
		{Auth{Type: "bearer", Secret: "s"}, []string{"value"}, []string{"api.v.com"}, false},
		{Auth{Type: "static", Secret: "s", Headers: []HeaderTemplate{{Name: "A", Value: "{{secret.key_id}}"}, {Name: "B", Value: "x {{secret.key}}"}, {Name: "C", Value: "{{secret.key}}"}}}, []string{"key_id", "key"}, []string{"api.v.com"}, false},
		{Auth{Type: "oauth2_client_credentials", Secret: "s", TokenURL: "https://acme.zslogin.net/oauth2/v1/token"}, []string{"client_id", "client_secret"}, []string{"acme.zslogin.net", "api.v.com"}, false},
		{Auth{Type: "oauth2_client_credentials", Secret: "s", ClientID: "abc", TokenURL: "https://api.v.com/token"}, []string{"client_secret"}, []string{"api.v.com"}, false},
		{Auth{Type: "basic", Secret: "s", Username: "your-username"}, []string{"value"}, []string{"api.v.com"}, true},
		{Auth{Type: "basic", Secret: "s", Username: "ops@corp.io"}, []string{"value"}, []string{"api.v.com"}, false},
	}
	for _, c := range cases {
		s := Credential(c.a, "https://api.v.com/v1/x")
		if !reflect.DeepEqual(s.Fields, c.fields) || !reflect.DeepEqual(s.Hosts, c.hosts) || s.Username != c.user {
			t.Errorf("%s: got %+v", c.a.Type, s)
		}
	}
	if Credential(Auth{Type: "none"}, "https://x") != nil {
		t.Error("none needs nothing")
	}
}
