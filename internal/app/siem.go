package app

import (
	"configbridge/internal/aidraft"
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/pkg/config"
	"crypto/x509"
	"errors"
	"os"
	"strconv"
	"strings"
)

func SIEM(getenv func(string) string) (*api.SIEM, error) {
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
	provider, e := aidraft.NewGroq(getenv("GROQ_API_KEY"), getenv("CB_AI_MODEL"))
	if e != nil {
		return nil, errors.New("SIEM Groq configuration unavailable")
	}
	tokens, e := AITokenLimit(getenv)
	if e != nil {
		return nil, e
	}
	calls := 20
	if raw := getenv("CB_AI_DAILY_LIMIT"); raw != "" {
		var err error
		calls, err = strconv.Atoi(raw)
		if err != nil || calls < 1 || calls > 100 {
			return nil, errors.New("AI daily limit must be 1-100")
		}
	}
	return &api.SIEM{Search: search, Provider: provider, EnabledTenants: tenants, DailyTokens: tokens, DailyCalls: calls}, nil
}
