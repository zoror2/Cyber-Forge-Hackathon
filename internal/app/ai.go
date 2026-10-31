package app

import (
	"configbridge/internal/aidraft"
	"configbridge/internal/api"
	"configbridge/pkg/config"
	"errors"
	"strconv"
	"strings"
)

// Empty tenant allowlist is the kill switch. A provider key alone never enables AI.
func Drafting(getenv func(string) string) (*api.Drafting, error) {
	enabled := strings.TrimSpace(getenv("CB_AI_ENABLED_TENANTS"))
	if enabled == "" {
		return nil, nil
	}
	tenants := map[string]bool{}
	for _, tenant := range strings.Split(enabled, ",") {
		tenant = strings.TrimSpace(tenant)
		if !config.ValidID(tenant) {
			return nil, errors.New("invalid AI tenant allowlist")
		}
		tenants[tenant] = true
	}
	limit := 20
	if raw := getenv("CB_AI_DAILY_LIMIT"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return nil, errors.New("AI daily limit must be 1-100")
		}
	}
	dir := getenv("CB_AI_SOURCES_DIR")
	if dir == "" {
		dir = "public_sources"
	}
	sources, err := aidraft.LoadSources(dir)
	if err != nil {
		return nil, errors.New("reviewed public AI sources unavailable")
	}
	provider, err := aidraft.NewGroq(getenv("GROQ_API_KEY"), getenv("CB_AI_MODEL"))
	if err != nil {
		return nil, errors.New("Groq configuration unavailable")
	}
	return &api.Drafting{Provider: provider, Sources: sources, EnabledTenants: tenants, DailyLimit: limit}, nil
}
