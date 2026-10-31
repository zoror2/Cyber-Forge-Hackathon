// Package aidraft generates proposals from reviewed PUBLIC source descriptions.
// It deliberately has no store, secrets-service or tenant-record dependency.
package aidraft

import (
	"bytes"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const MaxSourceBytes = 24 << 10

var ErrSource = errors.New("invalid_public_source")

// Files are operator-reviewed public documentation excerpts and synthetic
// examples, not uploaded customer data. Adding a vendor requires a reviewed file.
type Source struct {
	ID               string          `json:"id"`
	Classification   string          `json:"classification"`
	Vendor           string          `json:"vendor"`
	Name             string          `json:"name"`
	DocumentationURL string          `json:"documentation_url"`
	Documentation    string          `json:"documentation"`
	Request          engine.Request  `json:"request"`
	Auth             engine.Auth     `json:"auth"`
	Entity           string          `json:"entity"`
	Example          json.RawMessage `json:"example"`
}
type PublicSource struct {
	ID               string `json:"id"`
	Vendor           string `json:"vendor"`
	Name             string `json:"name"`
	DocumentationURL string `json:"documentation_url"`
	SourceHash       string `json:"source_hash"`
}

func (s Source) Hash() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s Source) Summary() PublicSource {
	return PublicSource{s.ID, s.Vendor, s.Name, s.DocumentationURL, s.Hash()}
}
func strict(body []byte, dst any) error {
	if config.CheckJSON(body) != nil {
		return errors.New("invalid_json")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(dst)
}
func (s Source) Validate() error {
	raw, _ := json.Marshal(s)
	if len(raw) > MaxSourceBytes || !config.ValidID(s.ID) || s.Classification != "public_documentation_and_synthetic_examples" || strings.TrimSpace(s.Vendor) == "" || len(s.Vendor) > 200 || s.Name == "" || len(s.Name) > 200 || s.Documentation == "" || len(s.Example) == 0 {
		return ErrSource
	}
	if _, ok := config.Fields[s.Entity]; !ok {
		return ErrSource
	}
	for _, v := range []string{s.DocumentationURL, s.Request.URL} {
		u, e := url.Parse(v)
		if e != nil || u.RawQuery != "" || u.Fragment != "" || (egress.Policy{}).CheckURL(u) != nil || egress.CheckPort(u, []int{443}) != nil {
			return ErrSource
		}
	}
	if s.Auth.Secret != "" || s.Auth.Username != "" || s.Auth.ClientID != "" {
		return ErrSource
	}
	auth := s.Auth
	if auth.Type != "none" {
		auth.Secret = "vendor_credential"
	}
	if auth.Type == "basic" {
		auth.Username = "SET_LOCALLY"
	}
	c := engine.Connector{TenantID: "validation", ID: s.ID, Request: s.Request, Auth: auth}
	if c.Validate() != nil || config.CheckJSON(s.Example) != nil {
		return ErrSource
	}
	return nil
}
func LoadSources(dir string) (map[string]Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, ErrSource
	}
	out := map[string]Source{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || len(out) >= 100 {
			return nil, ErrSource
		}
		f, e := os.Open(filepath.Join(dir, entry.Name()))
		if e != nil {
			return nil, ErrSource
		}
		b, e := io.ReadAll(io.LimitReader(f, MaxSourceBytes+1))
		f.Close()
		if e != nil || len(b) > MaxSourceBytes {
			return nil, ErrSource
		}
		var s Source
		if strict(b, &s) != nil || s.Validate() != nil {
			return nil, ErrSource
		}
		if _, ok := out[s.ID]; ok {
			return nil, ErrSource
		}
		out[s.ID] = s
	}
	if len(out) == 0 {
		return nil, ErrSource
	}
	return out, nil
}
