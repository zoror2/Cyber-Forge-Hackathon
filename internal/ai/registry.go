package ai

import "strings"

// specRegistry: human-reviewed locations of vendors' OWN OpenAPI specs (on
// the vendor's domain or its official GitHub organization). It is only a
// location: the spec is still downloaded, parsed, picked from and verified
// like any other. TestLiveSpecRegistry re-checks every entry against the
// internet; remove an entry rather than let it point somewhere stale.
var specRegistry = map[string]string{
	"jira":                           atlassianJira,
	"jiracloud":                      atlassianJira,
	"jirasoftware":                   atlassianJira,
	"confluence":                     "https://developer.atlassian.com/cloud/confluence/swagger.v3.json",
	"bitbucket":                      "https://api.bitbucket.org/swagger.json",
	"okta":                           "https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/dist/current/management-minimal.yaml",
	"pagerduty":                      "https://raw.githubusercontent.com/PagerDuty/api-schema/main/reference/REST/openapiv3.json",
	"slack":                          "https://raw.githubusercontent.com/slackapi/slack-api-specs/master/web-api/slack_web_openapi_v2.json",
	"datadog":                        "https://raw.githubusercontent.com/DataDog/datadog-api-client-go/master/.generator/schemas/v2/openapi.yaml",
	"meraki":                         ciscoMeraki,
	"ciscomeraki":                    ciscoMeraki,
	"gitlab":                         "https://gitlab.com/gitlab-org/gitlab/-/raw/master/doc/api/openapi/openapi_v2.yaml",
	"jumpcloud":                      "https://docs.jumpcloud.com/api/2.0/index.yaml",
	"sentry":                         "https://raw.githubusercontent.com/getsentry/sentry-api-schema/main/openapi-derefed.json",
	"digitalocean":                   "https://api-engineering.nyc3.cdn.digitaloceanspaces.com/spec-ci/DigitalOcean-public.v2.yaml",
	"box":                            "https://raw.githubusercontent.com/box/box-openapi/main/openapi.json",
	"twilio":                         "https://raw.githubusercontent.com/twilio/twilio-oai/main/spec/json/twilio_api_v2010.json",
	"tenable":                        tenableVulns,
	"tenableio":                      tenableVulns,
	"tenablevulnerabilitymanagement": tenableVulns,
}

const (
	atlassianJira = "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json"
	ciscoMeraki   = "https://raw.githubusercontent.com/meraki/openapi/master/openapi/spec3.json"
	// a docs page that embeds its operation's OpenAPI document
	tenableVulns = "https://developer.tenable.com/reference/workbenches-vulnerabilities"
)

// productKey normalises a product name: "Jira Cloud" -> "jiracloud".
func productKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func reviewedSpec(product string) string { return specRegistry[productKey(product)] }
