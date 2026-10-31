package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"configbridge/internal/api"
)

// browser is one signed-in console tab: a cookie jar and the API's Origin.
type browser struct {
	t      *testing.T
	base   string
	c      *http.Client
	origin bool
}

func (b *browser) do(method, path, body, bearer string, want int) map[string]any {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.base+path, strings.NewReader(body))
	if b.origin {
		req.Header.Set("Origin", b.base)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		b.t.Fatalf("%s %s got %d want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	out := map[string]any{}
	json.Unmarshal(raw, &out)
	return out
}
func iamEnv(t *testing.T, signup bool) (*environment, func() *browser) {
	e := setup(t)
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{},
		SessionKey: bytes.Repeat([]byte{7}, 32), InsecureCookies: true, OpenSignup: signup})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return e, func() *browser {
		jar, _ := cookiejar.New(nil)
		return &browser{t: t, base: srv.URL, c: &http.Client{Jar: jar}, origin: true}
	}
}

const pw = "correct horse battery"

func TestIAMAccountsUsersRolesKeysAndSessions(t *testing.T) {
	_, open := iamEnv(t, false)
	open().do("POST", "/accounts", `{"account":"acme","name":"Alice","email":"alice@acme.test","password":"`+pw+`"}`, "", 403)

	_, open = iamEnv(t, true)
	admin := open()
	me := admin.do("POST", "/accounts", `{"account":"acme","name":"Alice","email":"Alice@Acme.test","password":"`+pw+`"}`, "", 201)
	if me["role"] != "admin" || me["email"] != "alice@acme.test" {
		t.Fatal("signup", me)
	}
	open().do("POST", "/accounts", `{"account":"acme","name":"Mallory","email":"m@x.test","password":"`+pw+`"}`, "", 409) // no takeover
	open().do("POST", "/accounts", `{"account":"beta","name":"B","email":"b@x.test","password":"short"}`, "", 422)
	admin.do("GET", "/auth/me", "", "", 200) // session survives without any key in the page

	// sign-in: one answer for every failure
	open().do("POST", "/auth/login", `{"account":"acme","email":"alice@acme.test","password":"wrong password!!"}`, "", 401)
	open().do("POST", "/auth/login", `{"account":"acme","email":"nobody@acme.test","password":"`+pw+`"}`, "", 401)
	open().do("POST", "/auth/login", `{"account":"nope","email":"alice@acme.test","password":"`+pw+`"}`, "", 401)

	// admin creates a viewer and an editor
	viewer := admin.do("POST", "/iam/users", `{"name":"Vic Viewer","email":"vic@acme.test","role":"viewer","password":"`+pw+`"}`, "", 201)
	admin.do("POST", "/iam/users", `{"name":"Ed","email":"ed@acme.test","role":"editor","password":"`+pw+`"}`, "", 201)
	admin.do("POST", "/iam/users", `{"name":"Dup","email":"vic@acme.test","role":"viewer","password":"`+pw+`"}`, "", 409)
	admin.do("POST", "/iam/users", `{"name":"X","email":"x@acme.test","role":"superuser","password":"`+pw+`"}`, "", 422)
	vid := viewer["id"].(string)

	v := open()
	v.do("POST", "/auth/login", `{"account":"acme","email":"vic@acme.test","password":"`+pw+`"}`, "", 200)
	v.do("GET", "/runs", "", "", 200)
	v.do("POST", "/configs", `{}`, "", 403)
	v.do("GET", "/iam/users", "", "", 403)
	v.do("PATCH", "/iam/users/"+vid, `{"role":"admin"}`, "", 403) // no self-promotion

	// CSRF: a session write without Origin is refused
	v.origin = false
	v.do("POST", "/iam/users/"+vid+"/keys", `{"name":"ci"}`, "", 403)
	v.origin = true

	// own access keys: inherit the role, max two, can't touch others'
	k := v.do("POST", "/iam/users/"+vid+"/keys", `{"name":"ci"}`, "", 201)
	secret := k["secret"].(string)
	keyID := k["key"].(map[string]any)["id"].(string)
	v.do("POST", "/iam/users/"+vid+"/keys", `{"name":"ci-2"}`, "", 201)
	v.do("POST", "/iam/users/"+vid+"/keys", `{"name":"ci-3"}`, "", 409)
	cli := open()
	cli.origin = false
	cli.do("GET", "/runs", "", secret, 200)
	cli.do("POST", "/configs", `{}`, secret, 403)
	adminID := me["user_id"].(string)
	v.do("POST", "/iam/users/"+adminID+"/keys", `{"name":"steal"}`, "", 403)
	admin.do("GET", "/iam/users/"+vid+"/keys", "", "", 200)
	v.do("PATCH", "/iam/keys/"+keyID, `{"active":false}`, "", 204)
	cli.do("GET", "/runs", "", secret, 401)
	v.do("PATCH", "/iam/keys/"+keyID, `{"active":true}`, "", 204)
	cli.do("GET", "/runs", "", secret, 200)

	// deactivation ends the session and the user's keys at once
	admin.do("PATCH", "/iam/users/"+vid, `{"active":false}`, "", 204)
	v.do("GET", "/runs", "", "", 401)
	cli.do("GET", "/runs", "", secret, 401)
	open().do("POST", "/auth/login", `{"account":"acme","email":"vic@acme.test","password":"`+pw+`"}`, "", 401)

	// last active admin can't be demoted, disabled or removed
	admin.do("PATCH", "/iam/users/"+adminID, `{"role":"viewer"}`, "", 409)
	admin.do("PATCH", "/iam/users/"+adminID, `{"active":false}`, "", 409)
	admin.do("DELETE", "/iam/users/"+adminID, "", "", 409)

	// password change signs out every other session, keeps this one
	other := open()
	other.do("POST", "/auth/login", `{"account":"acme","email":"alice@acme.test","password":"`+pw+`"}`, "", 200)
	admin.do("POST", "/auth/password", `{"current_password":"wrong password!!","new_password":"another long secret"}`, "", 403)
	admin.do("POST", "/auth/password", `{"current_password":"`+pw+`","new_password":"another long secret"}`, "", 204)
	admin.do("GET", "/auth/me", "", "", 200)
	other.do("GET", "/auth/me", "", "", 401)

	admin.do("POST", "/auth/logout", "", "", 204)
	admin.do("GET", "/auth/me", "", "", 401)
}

func TestIAMSessionTokensCannotBeForgedOrMoved(t *testing.T) {
	_, open := iamEnv(t, true)
	a := open()
	a.do("POST", "/accounts", `{"account":"acme","name":"Alice","email":"alice@acme.test","password":"`+pw+`"}`, "", 201)
	b := open()
	b.do("POST", "/accounts", `{"account":"globex","name":"Gus","email":"gus@globex.test","password":"`+pw+`"}`, "", 201)

	u, _ := http.NewRequest("GET", a.base, nil)
	tok := cookieValue(a, "cb_access")
	parts := strings.Split(tok, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	moved := strings.Replace(string(body), `"acc":"acme"`, `"acc":"globex"`, 1)
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	for name, forged := range map[string]string{
		"other account": parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(moved)) + "." + parts[2],
		"alg none":      none + "." + parts[1] + ".",
		"bad signature": parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
	} {
		x := open()
		x.c.Jar.SetCookies(u.URL, []*http.Cookie{{Name: "cb_access", Value: forged}})
		x.t = t
		req, _ := http.NewRequest("GET", a.base+"/auth/me", nil)
		resp, err := x.c.Do(req)
		if err != nil || resp.StatusCode != 401 {
			t.Fatal(name, "accepted", resp.StatusCode)
		}
		resp.Body.Close()
	}
	// each account sees only itself
	if a.do("GET", "/auth/me", "", "", 200)["account"] != "acme" || b.do("GET", "/auth/me", "", "", 200)["account"] != "globex" {
		t.Fatal("account scoping")
	}
}

// cookieValue reads a cookie from the jar (the jar ignores Path for lookup
// only when asked for that path, so check both).
func cookieValue(b *browser, name string) string {
	for _, p := range []string{"/", "/auth/refresh"} {
		u, _ := http.NewRequest("GET", b.base+p, nil)
		for _, c := range b.c.Jar.Cookies(u.URL) {
			if c.Name == name {
				return c.Value
			}
		}
	}
	return ""
}

func TestIAMNoKeySignInAndRefreshRotation(t *testing.T) {
	_, open := iamEnv(t, true)
	// access keys are for APIs and scripts, never for console sign-in
	open().do("POST", "/auth/login", `{"api_key":"`+key("tenant-a")+`"}`, "", 400)

	a := open()
	a.do("POST", "/accounts", `{"account":"acme","name":"Alice","email":"alice@acme.test","password":"`+pw+`"}`, "", 201)
	access, r1 := cookieValue(a, "cb_access"), cookieValue(a, "cb_refresh")
	if access == "" || r1 == "" {
		t.Fatal("both tokens must be set as cookies")
	}
	// the refresh cookie is scoped to /auth/refresh: not sent to other paths
	u, _ := http.NewRequest("GET", a.base+"/runs", nil)
	for _, c := range a.c.Jar.Cookies(u.URL) {
		if c.Name == "cb_refresh" {
			t.Fatal("refresh token sent to /runs")
		}
	}
	a.do("POST", "/auth/refresh", "", "", 204)
	r2 := cookieValue(a, "cb_refresh")
	if r2 == r1 || r2 == "" {
		t.Fatal("refresh must rotate the refresh token")
	}
	a.do("GET", "/auth/me", "", "", 200)

	// an attacker replays the rotated-out refresh token: the session dies for both
	thief := open()
	ru, _ := http.NewRequest("GET", a.base+"/auth/refresh", nil)
	thief.c.Jar.SetCookies(ru.URL, []*http.Cookie{{Name: "cb_refresh", Value: r1, Path: "/auth/refresh"}})
	thief.do("POST", "/auth/refresh", "", "", 401)
	a.do("POST", "/auth/refresh", "", "", 401)
	a.do("GET", "/auth/me", "", "", 401) // access token of a revoked session is dead too

	// sign out revokes server-side: a copied refresh token is useless after
	b := open()
	b.do("POST", "/auth/login", `{"account":"acme","email":"alice@acme.test","password":"`+pw+`"}`, "", 200)
	copied := cookieValue(b, "cb_refresh")
	b.do("POST", "/auth/logout", "", "", 204)
	c := open()
	c.c.Jar.SetCookies(ru.URL, []*http.Cookie{{Name: "cb_refresh", Value: copied, Path: "/auth/refresh"}})
	c.do("POST", "/auth/refresh", "", "", 401)

	// garbage refresh cookie
	d := open()
	d.c.Jar.SetCookies(ru.URL, []*http.Cookie{{Name: "cb_refresh", Value: "acme.x.y", Path: "/auth/refresh"}})
	d.do("POST", "/auth/refresh", "", "", 401)
}
