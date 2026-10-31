package ai

import (
	"configbridge/configs"
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

var ErrProfileInput = errors.New("dataset_selection_required")

type DraftInput struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Location    string `json:"location"`
}
type Contract struct {
	Profile    string   `json:"profile"`
	Scope      string   `json:"scope"`
	Access     string   `json:"access"`
	Method     string   `json:"method"`
	Endpoint   string   `json:"endpoint"`
	Auth       string   `json:"authentication"`
	ItemsPath  string   `json:"items_path"`
	Pagination string   `json:"pagination"`
	Fields     []string `json:"response_fields"`
	Status     string   `json:"status"`
}
type reviewedProfile struct {
	id, product, scope, access, authHelp string
	raw                                  []byte
	sources, notes                       []string
	inputs                               []DraftInput
}

func selectProfile(r Request) (*reviewedProfile, error) {
	if r.Profile != "" && (len(r.DocumentationURLs) > 0 || r.Dataset != "" || r.Scope != "") {
		return nil, fmt.Errorf("%w: choose either a reviewed profile or an explicit dataset/scope with public references", ErrProfileInput)
	}
	// An explicit public reference + dataset uses the vendor-neutral flow.
	if len(r.DocumentationURLs) > 0 || r.Dataset != "" || r.Scope != "" {
		return nil, nil
	}
	product := strings.ToLower(strings.TrimSpace(r.Product))
	id := r.Profile
	isGit := strings.Contains(product, "github")
	isNVD := strings.Contains(product, "nvd") || product == "nist"
	isCISA := strings.Contains(product, "cisa") || product == "kev"
	if isGit && strings.Contains(product, "enterprise") {
		return nil, fmt.Errorf("%w: these reviewed datasets target public GitHub.com; Enterprise Server needs its own documented contract", ErrProfileInput)
	}
	if id == "" {
		switch {
		case isGit:
			if strings.Contains(product, "enterprise") {
				return nil, fmt.Errorf("%w: current reviewed GitHub datasets target public GitHub.com, not Enterprise Server", ErrProfileInput)
			}
			if strings.Contains(strings.ToLower(r.Details), "repo") {
				return nil, fmt.Errorf("%w: choose public repository contributors explicitly; repository objects are not supported by the current five OCSF classes", ErrProfileInput)
			}
			id = "github_public_users"
		case isNVD:
			id = "nvd_kev_cves"
		case isCISA:
			id = "cisa_kev"
		default:
			return nil, nil
		}
	}
	if !(isGit && strings.HasPrefix(id, "github_") || isNVD && id == "nvd_kev_cves" || isCISA && id == "cisa_kev") {
		return nil, fmt.Errorf("%w: dataset does not match the selected vendor", ErrProfileInput)
	}
	p := &reviewedProfile{id: id, access: "Public/free endpoint; no Enterprise subscription required."}
	switch id {
	case "github_public_users", "github_public_contributors", "github_public_members":
		p.product = "GitHub"
		p.raw = configs.GitHubMembers
		p.authHelp = "Create a fine-grained personal access token in GitHub Settings > Developer settings > Personal access tokens. This public-data endpoint requires no additional token permissions. A token cannot grant access its owner does not have. Store only its value locally as github_token; do not paste it into AI notes."
		p.sources = []string{"https://docs.github.com/en/rest/users/users#list-users", "https://docs.github.com/en/rest/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"}
		if id == "github_public_users" {
			p.scope = "Public GitHub user accounts, not repositories or organization membership."
		}
		if id == "github_public_contributors" {
			p.authHelp = "This public endpoint supports unauthenticated access. This profile uses a fine-grained personal access token; GitHub documents repository Metadata (read) permission for authenticated access. Select the intended repository and follow the linked permissions documentation. Store the token locally as github_token; never paste it into AI notes."
			p.scope = "Contributors (users) of one explicitly selected public repository; not repository objects."
			p.sources[0] = "https://docs.github.com/en/rest/repos/repos#list-repository-contributors"
			p.inputs = []DraftInput{{"owner", "Repository owner", "your-owner", "path"}, {"repo", "Public repository name", "your-repo", "path"}}
		}
		if id == "github_public_members" {
			p.scope = "Public members of one explicitly selected organization; not Enterprise-wide membership."
			p.sources[0] = "https://docs.github.com/en/rest/orgs/members#list-public-organization-members"
			p.inputs = []DraftInput{{"org", "Organization name", "your-org", "path"}}
		}
		p.notes = []string{p.scope, p.access, "The list response provides id/login/site_admin; email, account status and last_login are not supplied by this endpoint and are not invented.", "Bearer is correct for a fine-grained token. Invalid/expired/restricted tokens fail authentication; we do not substitute Enterprise endpoints."}
	case "nvd_kev_cves":
		p.product = "NVD"
		p.raw = configs.NVDKEVCVEs
		p.scope = "NVD CVE API 2.0: only CVEs in the CISA KEV subset (hasKev); not the complete NVD corpus."
		p.authHelp = "Request and activate a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key. Store it locally as nvd; the engine sends it in the apiKey header. Public access without a key is supported by NVD at lower limits, but this selected profile expects a key."
		p.sources = []string{"https://nvd.nist.gov/developers/vulnerabilities", "https://nvd.nist.gov/developers/start-here"}
		p.notes = []string{p.scope, "Pagination uses startIndex/resultsPerPage and the vulnerabilities array. CVSS 3.1 fields are optional; missing severity remains Unknown rather than being guessed."}
	case "cisa_kev":
		p.product = "CISA"
		p.raw = configs.CISAKEV
		p.scope = "Complete CISA KEV catalog from CISA's official GitHub mirror."
		p.authHelp = "No API key, account, organization or paid subscription is required."
		p.sources = []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://github.com/cisagov/kev-data"}
		p.notes = []string{p.scope, "The mirror is an explicit reviewed source, not a guessed fallback. The feed is one JSON document; records are in vulnerabilities.", "CISA KEV does not provide CVSS severity; severity stays Unknown."}
	default:
		return nil, fmt.Errorf("%w: unsupported reviewed dataset", ErrProfileInput)
	}
	return p, nil
}
func (p *reviewedProfile) configuration() (config.Config, error) {
	c, is := config.Decode(p.raw)
	if len(is) != 0 {
		return c, ErrUpstream
	}
	c.ID = p.id
	c.Name = p.scope
	c.Vendor = p.product
	if strings.HasPrefix(p.id, "github_") {
		c.Request.Headers["X-GitHub-Api-Version"] = "2026-03-10"
		c.Request.Params = map[string]string{"per_page": "30"}
		c.Pagination = engine.Pagination{Type: "link"}
		switch p.id {
		case "github_public_users":
			c.Request.URL = "https://api.github.com/users"
		case "github_public_contributors":
			c.Request.URL = "https://api.github.com/repos/your-owner/your-repo/contributors"
		case "github_public_members":
			c.Request.URL = "https://api.github.com/orgs/your-org/public_members"
		}
	}
	if p.id == "cisa_kev" {
		c.Request.URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	}
	return c, nil
}
func (c *Client) reviewedDraft(ctx context.Context, r Request, p *reviewedProfile, secrets []Secret) (*Draft, error) {
	base, e := p.configuration()
	if e != nil {
		return nil, e
	}
	if !r.Auto() && r.Data != base.Destination.Class {
		return nil, fmt.Errorf("%w: selected dataset produces %s, not %s", ErrProfileInput, base.Destination.Class, r.Data)
	}
	// Only a public reviewed template crosses this boundary. Customer notes,
	// stored credential names/hosts and path-input values stay on this server.
	msgs := []message{{Role: "system", Content: systemPrompt() + "\nFor this request the following reviewed contract is authoritative. Preserve its URL, auth, items_path, pagination and complete mapping exactly. Do not change dataset scope or invent Enterprise requirements."}, {Role: "user", Content: "Reviewed public config for the selected dataset: " + mustJSON(base) + "\nOfficial documentation: " + mustJSON(p.sources)}}
	var used meter
	out, err := c.call(ctx, msgs, &used)
	if err != nil {
		return nil, err
	}
	status := "reviewed_profile"
	candidate, issues := config.Decode([]byte(out.ConfigJSON))
	if len(issues) != 0 || !reflect.DeepEqual(candidate.Request, base.Request) || !reflect.DeepEqual(candidate.Auth, base.Auth) || candidate.ItemsPath != base.ItemsPath || !reflect.DeepEqual(candidate.Pagination, base.Pagination) || !reflect.DeepEqual(candidate.Destination, base.Destination) {
		status = "reviewed_profile_fallback"
	}
	// The returned execution contract is authoritative even if a syntactically
	// valid model proposal guessed another endpoint or omitted required fields.
	needed := []string{}
	for _, in := range p.inputs {
		needed = append(needed, in.Label+": fill this locally before testing the draft.")
	}
	needed = append(needed, p.authHelp)
	for _, s := range secrets {
		if s.Host == strings.TrimPrefix(strings.Split(base.Request.URL, "/")[2], "https://") && base.Auth.Type != "none" {
			base.Auth.Secret = s.Name
			break
		}
	}
	raw, _ := json.MarshalIndent(base, "", "  ")
	fields := []string{}
	seen := map[string]bool{}
	for _, field := range base.Destination.Mapping {
		if field.Path != nil && !seen[*field.Path] {
			fields = append(fields, *field.Path)
			seen[*field.Path] = true
		}
	}
	sort.Strings(fields)
	return &Draft{Config: raw, Data: base.Destination.Class, Notes: p.notes, Needed: needed, Optional: []string{"Review collection limits and schedule locally; the draft remains disabled."}, Sources: p.sources, Inputs: p.inputs, Contract: &Contract{Profile: p.id, Scope: p.scope, Access: p.access, Method: base.Request.Method, Endpoint: base.Request.URL, Auth: base.Auth.Type, ItemsPath: base.ItemsPath, Pagination: base.Pagination.Type, Fields: fields, Status: status}, Rounds: 1, Credential: engine.Credential(base.Auth, base.Request.URL), Usage: used.total()}, nil
}
