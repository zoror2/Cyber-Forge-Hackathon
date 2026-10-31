package engine

// This file attaches credentials to outgoing requests (FR-1).
// Rule: before a secret is used, its bound host is checked against the exact
// URL of THIS request. If they don't match, nothing is sent.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"configbridge/internal/egress"
)

// oauthToken is a cached OAuth2 access token. Kept in memory only, never stored.
type oauthToken struct {
	value   string
	expires time.Time // when we must fetch a new one
}

// authorize adds the right credential to req, based on c.Auth.Type.
//
//	none     -> nothing
//	static   -> headers built from secret fields, e.g. x-xdr-auth-id: {{secret.key_id}}
//	api_key  -> custom header:   X-API-Key: <secret>
//	bearer   -> Authorization:   Bearer <secret>
//	basic    -> Authorization:   Basic base64(username:secret)
//	oauth2   -> Authorization:   Bearer <short-lived token fetched with the client secret>
//
// It returns the credential ID of the secret it used ("" for none), so the
// caller can tag a later 401/403 with the right credential.
func (e *Engine) authorize(ctx context.Context, client *http.Client, c Connector, req *http.Request) (string, error) {
	a := c.Auth
	switch a.Type {
	case "none":
		return "", nil
	case "oauth2_client_credentials":
		tok, credID, err := e.oauthToken(ctx, client, c, req.URL)
		if err != nil {
			return credID, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return credID, nil
	}

	// Static credential types: fetch the secret AND verify its bound host
	// matches this request's URL before touching it.
	s, err := e.boundSecret(ctx, c.TenantID, a.Secret, req.URL)
	if err != nil {
		return "", err
	}
	switch a.Type {
	case "static":
		for _, h := range a.Headers {
			v, err := renderSecret(h.Value, s)
			if err != nil {
				return s.id, authErr(StatusIncomplete, a.Secret, s.id, fmt.Errorf("header %s: %w", h.Name, err))
			}
			req.Header.Set(h.Name, v)
		}
	case "api_key":
		req.Header.Set(a.Header, s.value())
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+s.value())
	case "basic":
		req.SetBasicAuth(a.Username, s.value())
	default:
		return s.id, fmt.Errorf("auth.type %q is not supported", a.Type)
	}
	return s.id, nil
}

// boundSecret loads a tenant's secret and refuses it unless one of its bound
// hosts matches target exactly. This is where secret-to-host binding is enforced.
func (e *Engine) boundSecret(ctx context.Context, tenantID, name string, target *url.URL) (Secret, error) {
	if e.Secrets == nil {
		return Secret{}, errors.New("no secret store configured")
	}
	if tenantID == "" { // never look up a secret without knowing whose it is
		return Secret{}, errors.New("missing tenant")
	}
	s, err := e.Secrets.Get(ctx, tenantID, name)
	if err != nil {
		// Only the NAME goes into the error, never the value.
		return Secret{}, authErr(StatusMissing, name, "", err)
	}
	if err := egress.CheckSecretHosts(s.hosts, target); err != nil {
		return Secret{}, authErr(StatusBindingMismatch, name, s.id, err) // still errors.Is(ErrBlocked)
	}
	return s, nil
}

// oauthToken gets an access token using the OAuth2 "client credentials" grant:
//
//  1. POST client_id + client_secret to token_url
//  2. receive {"access_token": "...", "expires_in": 3600}
//  3. use the access token as a Bearer token on API calls
//
// Security rules:
//   - the token URL must be one of the secret's bound hosts, on an allowed port
//   - the resulting access token may only be used on the secret's bound hosts
//     (for vendors like Wiz the secret is bound to both the token host and
//     the API host; for most vendors it's one host)
//   - tokens are cached in memory per tenant + connector, refreshed 30s early
//
// Returns the access token and the credential ID of the client secret used.
func (e *Engine) oauthToken(ctx context.Context, client *http.Client, c Connector, target *url.URL) (string, string, error) {
	a := c.Auth
	tokenURL, err := url.Parse(a.TokenURL)
	if err != nil {
		return "", "", errors.New("auth.token_url is invalid")
	}
	if err := e.Policy.CheckURL(tokenURL); err != nil { // token URL must be https too
		return "", "", err
	}
	if err := egress.CheckPort(tokenURL, c.Request.AllowedPorts); err != nil {
		return "", "", err
	}
	// Client secret may only go to the token endpoint's bound host...
	s, err := e.boundSecret(ctx, c.TenantID, a.Secret, tokenURL)
	if err != nil {
		return "", "", err
	}
	// ...and the token it produces may only be used on the secret's bound hosts.
	if err := egress.CheckSecretHosts(s.hosts, target); err != nil {
		return "", s.id, authErr(StatusBindingMismatch, a.Secret, s.id, err)
	}

	// Reuse a cached token if it hasn't expired.
	key := tokenKey(c)
	e.mu.Lock()
	cached, ok := e.tokens[key]
	e.mu.Unlock()
	if ok && e.now().Before(cached.expires) {
		return cached.value, s.id, nil
	}

	// Build the token request body: grant_type=client_credentials[&scope=...]
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(a.Scopes) > 0 {
		form.Set("scope", strings.Join(a.Scopes, " "))
	}
	for k, v := range a.ExtraParams { // e.g. audience=wiz-api (validated: never secret-looking)
		form.Set(k, v)
	}

	// Client ID: from the config, or else from the secret's "client_id" field.
	// Client secret: the "client_secret" field, or a single-value secret.
	clientID := a.ClientID
	if clientID == "" {
		clientID, _ = s.field("client_id")
	}
	clientSecret, ok := s.field("client_secret")
	if !ok {
		clientSecret = s.value()
	}
	if clientID == "" || clientSecret == "" {
		return "", s.id, authErr(StatusIncomplete, a.Secret, s.id, errors.New("oauth2 needs a client_id and a client_secret"))
	}
	if a.ClientAuthMethod == "client_secret_post" {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", s.id, errors.New("build token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: client id and secret are form-encoded, then sent as
	// HTTP Basic auth. (Encoding matters if the secret contains ":" or "%".)
	if a.ClientAuthMethod != "client_secret_post" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	resp, err := client.Do(req) // same egress-guarded client as API calls
	if err != nil {
		return "", s.id, scrub(err, tokenURL)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 64<<10) // token responses are tiny; cap at 64 KB
	if err != nil {
		return "", s.id, scrub(err, tokenURL)
	}
	if resp.StatusCode != http.StatusOK {
		// Wrapped StatusError lets retry logic treat token-endpoint 5xx as temporary.
		se := fmt.Errorf("token endpoint: %w", &StatusError{Code: resp.StatusCode})
		if status, ok := statusFromHTTP(resp.StatusCode, true); ok {
			return "", s.id, authErr(status, a.Secret, s.id, se)
		}
		return "", s.id, se
	}

	// Parse only the fields we need.
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"` // seconds
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", s.id, errors.New("token endpoint returned no access_token")
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return "", s.id, errors.New("token endpoint returned unsupported token_type")
	}

	// Cache it. Expire 30s early so we never send a token that dies mid-request.
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // vendor didn't say; assume short
	}
	e.mu.Lock()
	e.tokens[key] = oauthToken{value: tr.AccessToken, expires: e.now().Add(max(ttl-30*time.Second, 0))}
	e.mu.Unlock()
	return tr.AccessToken, s.id, nil
}

// tokenKey scopes cached tokens to tenant AND connector. Keying by connector
// alone would let two tenants with the same connector ID share a token.
// IDs are validated to [a-z0-9_-], so "/" cannot create collisions.
func tokenKey(c Connector) string { return c.TenantID + "/" + c.ID }

// dropToken forgets a cached token (called when the API answers 401, which
// usually means the token was revoked or expired early).
func (e *Engine) dropToken(c Connector) {
	e.mu.Lock()
	delete(e.tokens, tokenKey(c))
	e.mu.Unlock()
}
