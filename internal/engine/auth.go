package engine

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

type oauthToken struct {
	value   string
	expires time.Time
}

// authorize attaches credentials. Every secret is checked against its bound
// host for this exact request URL before it is attached.
func (e *Engine) authorize(ctx context.Context, client *http.Client, c Connector, req *http.Request) error {
	a := c.Auth
	switch a.Type {
	case "none":
		return nil
	case "oauth2_client_credentials":
		tok, err := e.oauthToken(ctx, client, c, req.URL)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}

	s, err := e.boundSecret(ctx, a.Secret, req.URL)
	if err != nil {
		return err
	}
	switch a.Type {
	case "api_key":
		req.Header.Set(a.Header, s.value())
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+s.value())
	case "basic":
		req.SetBasicAuth(a.Username, s.value())
	default:
		return fmt.Errorf("auth.type %q is not supported", a.Type)
	}
	return nil
}

func (e *Engine) boundSecret(ctx context.Context, name string, target *url.URL) (Secret, error) {
	if e.Secrets == nil {
		return Secret{}, errors.New("no secret store configured")
	}
	s, err := e.Secrets.Get(ctx, name)
	if err != nil {
		return Secret{}, fmt.Errorf("secret %q: %w", name, err)
	}
	if err := egress.CheckSecretHost(s.host, target); err != nil {
		return Secret{}, fmt.Errorf("secret %q: %w", name, err)
	}
	return s, nil
}

// oauthToken runs the client-credentials grant. The client secret goes only to
// its bound host, and the resulting access token goes only to that same host.
// Tokens live in memory only and are refreshed 30s before expiry.
func (e *Engine) oauthToken(ctx context.Context, client *http.Client, c Connector, target *url.URL) (string, error) {
	a := c.Auth
	tokenURL, err := url.Parse(a.TokenURL)
	if err != nil {
		return "", errors.New("auth.token_url is invalid")
	}
	if err := e.Policy.CheckURL(tokenURL); err != nil {
		return "", err
	}
	s, err := e.boundSecret(ctx, a.Secret, tokenURL)
	if err != nil {
		return "", err
	}
	if err := egress.CheckSecretHost(s.host, target); err != nil {
		return "", fmt.Errorf("oauth token for %q: %w", a.Secret, err)
	}

	e.mu.Lock()
	cached, ok := e.tokens[c.ID]
	e.mu.Unlock()
	if ok && e.now().Before(cached.expires) {
		return cached.value, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	if len(a.Scopes) > 0 {
		form.Set("scope", strings.Join(a.Scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("build token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: client id and secret are form-encoded before Basic auth.
	req.SetBasicAuth(url.QueryEscape(a.ClientID), url.QueryEscape(s.value()))

	resp, err := client.Do(req)
	if err != nil {
		return "", scrub(err, tokenURL)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 64<<10)
	if err != nil {
		return "", scrub(err, tokenURL)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: %w", &StatusError{Code: resp.StatusCode})
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("token endpoint returned no access_token")
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return "", fmt.Errorf("token endpoint returned unsupported token_type %q", tr.TokenType)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	e.mu.Lock()
	e.tokens[c.ID] = oauthToken{value: tr.AccessToken, expires: e.now().Add(max(ttl-30*time.Second, 0))}
	e.mu.Unlock()
	return tr.AccessToken, nil
}

func (e *Engine) dropToken(id string) {
	e.mu.Lock()
	delete(e.tokens, id)
	e.mu.Unlock()
}
