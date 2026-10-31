package ai

import (
	"bytes"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type liveCredential struct{ value, host string }

func liveClient(t *testing.T) *Client {
	t.Helper()
	provider := os.Getenv("CB_LIVE_AI_PROVIDER")
	if provider == "" {
		provider = os.Getenv("CB_AI_PROVIDER")
	}
	model := os.Getenv("CB_LIVE_AI_MODEL")
	if model == "" {
		model = os.Getenv("CB_AI_MODEL")
	}
	if model == "" {
		t.Fatal("live model required")
	}
	if provider == "gemini" {
		if os.Getenv("GEMINI_API_KEY") == "" {
			t.Fatal("Gemini key required")
		}
		return NewGemini(os.Getenv("GEMINI_API_KEY"), model)
	}
	if os.Getenv("GROQ_API_KEY") == "" {
		t.Fatal("Groq key required")
	}
	c := New(os.Getenv("GROQ_API_KEY"), model)
	c.HTTP.Transport = liveQuotaObserver{t: t}
	return c
}

// A live-only diagnostic: print quota dimensions/numbers, never provider error
// bodies, key values or organization IDs. Restores the response for the adapter.
type liveQuotaObserver struct{ t *testing.T }

func (o liveQuotaObserver) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil || res.StatusCode != 429 && res.StatusCode != 400 {
		return res, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(raw))
	if readErr == nil {
		var body struct {
			Error struct {
				Message          string `json:"message"`
				Code             string `json:"code"`
				FailedGeneration string `json:"failed_generation"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &body) == nil {
			if res.StatusCode == 400 {
				generation := []byte(body.Error.FailedGeneration)
				if regexp.MustCompile(`^[a-z_]+$`).MatchString(body.Error.Code) {
					o.t.Logf("provider format error code=%s generated_bytes=%d generated_json_valid=%v", body.Error.Code, len(generation), json.Valid(generation))
				}
				return res, nil
			}
			facts := regexp.MustCompile(`(?i)\b(?:TPD|TPM|RPD|RPM)\b|\b(?:Limit|Used|Requested)\s*[:=]?\s*[0-9][0-9.,]*`).FindAllString(body.Error.Message, -1)
			o.t.Logf("provider quota facts=%v request_bytes=%d", facts, r.ContentLength)
		}
	}
	return res, nil
}

func (s liveCredential) Get(context.Context, string, string) (engine.Secret, error) {
	return engine.NewSecret(s.value, s.host), nil
}

// Opt-in, bounded public-data proof. Never run this as part of the offline gate.
// Actual authenticated vendor proof additionally requires the corresponding
// GITHUB_TOKEN/NVD_API_KEY; absence is reported, never called an auth success.
func TestReviewedLiveProviderAndThreePublicSources(t *testing.T) {
	if os.Getenv("CB_LIVE_REVIEWED") != "1" {
		t.Skip("set CB_LIVE_REVIEWED=1 for hosted AI and public vendor calls")
	}
	for _, tc := range []struct{ product, profile, key, host string }{
		{"GitHub", "github_public_contributors", "GITHUB_TOKEN", "api.github.com"},
		{"NVD", "nvd_kev_cves", "NVD_API_KEY", "services.nvd.nist.gov"},
		{"CISA", "cisa_kev", "", "raw.githubusercontent.com"},
	} {
		t.Run(tc.product, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
			defer cancel()
			c := liveClient(t)
			d, e := c.Draft(ctx, Request{Product: tc.product, Profile: tc.profile}, nil)
			if e != nil {
				t.Fatal("hosted draft:", e)
			}
			cfg, issues := config.Decode(d.Config)
			if len(issues) > 0 {
				t.Fatal(issues)
			}
			cfg.Request.URL = strings.ReplaceAll(strings.ReplaceAll(cfg.Request.URL, "your-owner", "octocat"), "your-repo", "Hello-World")
			if tc.key != "" && os.Getenv(tc.key) == "" {
				cfg.Auth = engine.Auth{Type: "none"}
				t.Log("public endpoint only: no real vendor credential supplied; authenticated-token success remains unverified")
			}
			if tc.key != "" && os.Getenv(tc.key) != "" {
				t.Log("using the supplied vendor credential (value withheld)")
			}
			cfg.Limits.MaxPages = 2
			cfg.Limits.MaxRunSeconds = 60
			cfg.Retry.MaxAttempts = 2
			if tc.product == "NVD" {
				cfg.Pagination.PageSize = 2
				cfg.Retry.BaseDelayMillis = 6000
			}
			if tc.product == "GitHub" {
				cfg.Request.Params["per_page"] = "2"
			}
			eng := engine.New(liveCredential{os.Getenv(tc.key), tc.host}, egress.Policy{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			accepted, rejected := 0, 0
			res, e := eng.Fetch(ctx, cfg.Connector("public-live-test"), func(p engine.Page) error {
				for i, row := range p.Items {
					_, bad := mapping.Map(row, cfg, "public-live-test", time.Now(), i)
					if bad != nil {
						rejected++
						t.Log("mapping rejection", bad.Field, bad.Reason)
					} else {
						accepted++
					}
				}
				return nil
			})
			if e != nil && !errors.Is(e, engine.ErrPageLimit) {
				t.Fatal("public collection:", e)
			}
			if accepted == 0 || rejected != 0 {
				t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
			}
			t.Logf("profile=%s contract=%s pages=%d accepted=%d rejected=%d bounded=%v reported_tokens=%d", tc.profile, d.Contract.Status, res.Pages, accepted, rejected, errors.Is(e, engine.ErrPageLimit), d.Usage.Total)
		})
	}
}
