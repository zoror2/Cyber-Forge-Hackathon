package app

import (
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
	"crypto/x509"
	"errors"
	"os"
	"strings"
)

// SIEM is opt-in per tenant (CB_SIEM_ENABLED_TENANTS). Explanations use the
// same AI provider and the same daily call + token budget as the drafter.
func SIEM(getenv func(string) string, model *ai.Client) (*api.SIEM, error) {
	enabled := strings.TrimSpace(getenv("CB_SIEM_ENABLED_TENANTS"))
	if enabled == "" {
		return nil, nil
	}
	tenants := map[string]bool{}
	for _, t := range strings.Split(enabled, ",") {
		t = strings.TrimSpace(t)
		if !config.ValidID(t) {
			return nil, errors.New("invalid SIEM tenant allowlist")
		}
		tenants[t] = true
	}
	var roots *x509.CertPool
	if path := getenv("CB_OPENSEARCH_CA_FILE"); path != "" {
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil, errors.New("OpenSearch CA unavailable")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("invalid OpenSearch CA")
		}
	}
	search, e := insights.NewSearch(getenv("CB_OPENSEARCH_URL"), getenv("CB_OPENSEARCH_USERNAME"), getenv("CB_OPENSEARCH_PASSWORD"), getenv("CB_ENV"), getenv("CB_OPENSEARCH_NAMESPACE"), roots)
	if e != nil {
		return nil, errors.New("invalid OpenSearch configuration")
	}
	s := &api.SIEM{Search: search, EnabledTenants: tenants}
	// no AI provider: findings still work, "explain" answers siem_disabled
	if model != nil && model.ModelID() != "" {
		s.Provider, s.DailyCalls, s.DailyTokens = model, model.DailyLimit, model.TokenLimit
	}
	return s, nil
}
