package engine

import (
	"net/url"
	"strings"
)

// CredentialSpec is exactly what a human must hand over for a connector's
// auth, derived from the config (never from model prose): the secret's field
// names and the hosts it will be bound to.
type CredentialSpec struct {
	Secret string   `json:"secret"`
	Fields []string `json:"fields"` // "value" = one plain key
	Hosts  []string `json:"hosts"`  // exact hosts the secret may be sent to
	// Username: basic auth whose username is not in the config yet.
	Username bool `json:"username,omitempty"`
}

// Credential returns nil for auth "none".
func Credential(a Auth, apiURL string) *CredentialSpec {
	if a.Type == "" || a.Type == "none" {
		return nil
	}
	api := hostOf(apiURL)
	s := &CredentialSpec{Secret: a.Secret, Fields: []string{DefaultField}, Hosts: []string{api}}
	switch a.Type {
	case "static":
		s.Fields = nil
		seen := map[string]bool{}
		for _, h := range a.Headers {
			fs, _ := secretPlaceholders(h.Value)
			for _, f := range fs {
				if !seen[f] {
					seen[f] = true
					s.Fields = append(s.Fields, f)
				}
			}
		}
	case "basic":
		u := strings.ToLower(strings.TrimSpace(a.Username))
		s.Username = u == "" || strings.Contains(u, "your-") || strings.Contains(u, "example.")
	case "oauth2_client_credentials":
		s.Fields = []string{"client_secret"}
		if a.ClientID == "" {
			s.Fields = []string{"client_id", "client_secret"}
		}
		// the client secret goes to the token host; the token to the API host
		if t := hostOf(a.TokenURL); t != "" && t != api {
			s.Hosts = []string{t, api}
		}
	}
	return s
}

func hostOf(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
