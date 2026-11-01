package api

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"configbridge/internal/store"
	"configbridge/pkg/config"
)

// ---------- roles (managed policies) ----------
//
// Like AWS managed policies: each role is a fixed allow-list of actions and
// everything else is denied. Access keys inherit their owner's role.
var Roles = map[string][]string{
	"viewer":   {"read"},
	"operator": {"read", "connectors:run"},
	"editor":   {"read", "connectors:run", "configs:write", "secrets:write", "ai:draft"},
	"admin":    {"read", "connectors:run", "configs:write", "secrets:write", "ai:draft", "iam:read", "iam:write", "ai:audit"},
}

// action names what a request does. Unknown writes need iam:write (admin):
// a new route is denied to everyone else until it is classified here.
func action(method, path string) string {
	switch {
	case strings.HasPrefix(path, "/auth/"):
		return "self"
	case strings.HasPrefix(path, "/iam/keys/") || strings.HasPrefix(path, "/iam/users/") && strings.HasSuffix(path, "/keys"):
		return "iam:keys" // own keys for everyone; the handler checks ownership
	case strings.HasPrefix(path, "/iam/"):
		if method == http.MethodGet {
			return "iam:read"
		}
		return "iam:write"
	case path == "/ai/audit":
		return "ai:audit"
	case path == "/ai/draft", path == "/siem/ask", path == "/intel/research":
		return "ai:draft" // both send data to the model and spend the AI budget
	case path == "/siem/refresh":
		return "connectors:run"
	case strings.HasPrefix(path, "/configs/") && strings.HasSuffix(path, "/repair"):
		return "ai:draft"
	case method == http.MethodGet:
		return "read"
	case strings.HasPrefix(path, "/connectors/") && (strings.HasSuffix(path, "/run") || strings.HasSuffix(path, "/test")),
		strings.HasPrefix(path, "/configs/") && strings.HasSuffix(path, "/test"):
		return "connectors:run"
	case strings.HasPrefix(path, "/configs"):
		return "configs:write"
	case strings.HasPrefix(path, "/secrets/"):
		return "secrets:write"
	}
	return "iam:write"
}
func allowed(role, act string) bool {
	if act == "self" || act == "iam:keys" {
		return Roles[role] != nil
	}
	for _, a := range Roles[role] {
		if a == act {
			return true
		}
	}
	return false
}

// ---------- passwords ----------

const pbkdfIter = 600_000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	k, e := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if e != nil {
		return "", e
	}
	enc := base64.RawStdEncoding
	return "pbkdf2-sha256$" + strconv.Itoa(pbkdfIter) + "$" + enc.EncodeToString(salt) + "$" + enc.EncodeToString(k), nil
}

// dummyHash makes a sign-in for an unknown email cost the same as a real one,
// so response time doesn't reveal which emails exist.
var dummyHash, _ = hashPassword("configbridge-timing-equaliser")

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, e := strconv.Atoi(p[1])
	salt, e1 := base64.RawStdEncoding.DecodeString(p[2])
	want, e2 := base64.RawStdEncoding.DecodeString(p[3])
	if e != nil || e1 != nil || e2 != nil || iter < 100_000 || iter > 5_000_000 {
		return false
	}
	got, e := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return e == nil && subtle.ConstantTimeCompare(got, want) == 1
}
func passwordProblem(pw string) string {
	if len(pw) < 12 || len(pw) > 256 {
		return "password: 12-256 characters"
	}
	return ""
}

// ---------- session tokens (JWT, HS256) ----------

// Two HttpOnly, SameSite=Strict cookies; page scripts can read neither.
//
//	cb_access  short JWT (15 min), sent to every API path
//	cb_refresh opaque "<account>.<session>.<secret>" (7 days), sent ONLY to
//	           /auth/refresh; stored as a SHA-256 hash and rotated on each use
const (
	accessCookie  = "cb_access"
	refreshCookie = "cb_refresh"
	refreshPath   = "/auth/refresh"
	accessTTL     = 15 * time.Minute
	refreshTTL    = 7 * 24 * time.Hour
)

type claims struct {
	Sub string `json:"sub"` // user id
	Acc string `json:"acc"` // account (tenant)
	Sid string `json:"sid"` // session id: revoked session = dead access token
	Ver int    `json:"ver"` // must equal the user's token_version
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func signJWT(key []byte, c claims) string {
	body, _ := json.Marshal(c)
	msg := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// verifyJWT accepts only our exact HS256 header (no alg negotiation, so no
// "alg":"none" or key-confusion tricks) and an unexpired token.
func verifyJWT(key []byte, tok string, now time.Time) (claims, bool) {
	var c claims
	p := strings.Split(tok, ".")
	if len(tok) > 2048 || len(p) != 3 || p[0] != jwtHeader {
		return c, false
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[2])
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p[0] + "." + p[1]))
	if e != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return c, false
	}
	body, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil || json.Unmarshal(body, &c) != nil || now.Unix() >= c.Exp || c.Sub == "" || c.Sid == "" || !config.ValidID(c.Acc) {
		return c, false
	}
	return c, true
}
func (a *API) cookie(name, value, path string, expires time.Time) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: path, Expires: expires, HttpOnly: true, Secure: !a.InsecureCookies, SameSite: http.SameSiteStrictMode}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}
func (a *API) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, a.cookie(accessCookie, "", "/", time.Time{}))
	http.SetCookie(w, a.cookie(refreshCookie, "", refreshPath, time.Time{}))
}
func randToken() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}

// setTokens writes a fresh access JWT and the given refresh token.
func (a *API) setTokens(w http.ResponseWriter, acc, sid, user string, ver int, refresh string) {
	now := time.Now()
	c := claims{Sub: user, Acc: acc, Sid: sid, Ver: ver, Iat: now.Unix(), Exp: now.Add(accessTTL).Unix()}
	http.SetCookie(w, a.cookie(accessCookie, signJWT(a.SessionKey, c), "/", now.Add(accessTTL)))
	http.SetCookie(w, a.cookie(refreshCookie, acc+"."+sid+"."+refresh, refreshPath, now.Add(refreshTTL)))
}

// startSession creates a server-side session and sets both cookies.
func (a *API) startSession(ctx context.Context, w http.ResponseWriter, acc, user string, ver int) error {
	refresh, e := randToken()
	if e != nil {
		return e
	}
	sid, e := a.Store.ForTenant(acc).CreateSession(ctx, user, ver, refresh, refreshTTL)
	if e != nil {
		return e
	}
	a.setTokens(w, acc, sid, user, ver, refresh)
	return nil
}

// sessionCaller turns a valid access cookie into a caller. The session and the
// user are re-read on every request, so sign-out, deactivation, role changes
// and password resets apply at once instead of when the token expires.
func (a *API) sessionCaller(ctx context.Context, r *http.Request) (store.Caller, bool) {
	ck, e := r.Cookie(accessCookie)
	if e != nil || len(a.SessionKey) == 0 {
		return store.Caller{}, false
	}
	c, ok := verifyJWT(a.SessionKey, ck.Value, time.Now())
	if !ok {
		return store.Caller{}, false
	}
	scope := a.Store.ForTenant(c.Acc)
	if live, e := scope.SessionLive(ctx, c.Sid); e != nil || !live {
		return store.Caller{}, false
	}
	u, e := scope.User(ctx, c.Sub)
	if e != nil || !u.Active || u.Version != c.Ver {
		return store.Caller{}, false
	}
	return store.Caller{Tenant: c.Acc, Actor: "user:" + u.ID, Role: u.Role, UserID: u.ID, SessionID: c.Sid}, true
}

// refresh rotates the refresh token and issues a new access token. A token
// that was already rotated out revokes the session (it was copied).
func (a *API) refresh(w http.ResponseWriter, r *http.Request, failed func()) {
	ck, e := r.Cookie(refreshCookie)
	parts := []string{}
	if e == nil {
		parts = strings.SplitN(ck.Value, ".", 3)
	}
	if len(parts) != 3 || !config.ValidID(parts[0]) || len(parts[1]) > 64 || len(parts[2]) > 128 {
		a.clearSession(w)
		failed()
		fail(w, 401, "session_expired")
		return
	}
	next, e := randToken()
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	got, e := a.Store.ForTenant(parts[0]).RotateSession(r.Context(), parts[1], parts[2], next)
	if e != nil {
		a.clearSession(w)
		if !errors.Is(e, store.ErrNotFound) && !errors.Is(e, store.ErrSessionReuse) {
			dbFail(w, e)
			return
		}
		failed()
		fail(w, 401, "session_expired")
		return
	}
	a.setTokens(w, parts[0], parts[1], got.UserID, got.Version, next)
	w.WriteHeader(204)
}

// ---------- handlers ----------

func cleanEmail(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	a, e := mail.ParseAddress(s)
	return s, e == nil && a.Address == s && len(s) <= 254
}
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && len(s) <= 100 && !strings.ContainsAny(s, "\r\n\t<>")
}
func invalid(w http.ResponseWriter, detail string) {
	write(w, 422, map[string]string{"error": "invalid_input", "detail": detail})
}
func caller(r *http.Request) store.Caller { return r.Context().Value(callerKey{}).(store.Caller) }

type me struct {
	Account string   `json:"account"`
	UserID  string   `json:"user_id,omitempty"`
	Name    string   `json:"name"`
	Email   string   `json:"email,omitempty"`
	Role    string   `json:"role"`
	Actions []string `json:"actions"`
}

func (a *API) whoami(ctx context.Context, c store.Caller) (me, error) {
	out := me{Account: c.Tenant, Role: c.Role, Actions: Roles[c.Role], Name: "Account root key"}
	if c.UserID != "" {
		u, e := a.Store.ForTenant(c.Tenant).User(ctx, c.UserID)
		if e != nil {
			return out, e
		}
		out.UserID, out.Name, out.Email = u.ID, u.Name, u.Email
	}
	return out, nil
}

// signup creates an account and its first admin (like creating an AWS account
// and its root user). Open only when CB_SIGNUP=open in dev; otherwise it needs
// the platform operator token. Tenants can never create other accounts.
func (a *API) signup(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	operator := a.OperatorToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(a.OperatorToken)) == 1
	if !a.OpenSignup && !operator {
		fail(w, 403, "signup_disabled")
		return
	}
	var in struct {
		Account  string `json:"account"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		KMSKey   string `json:"kms_key_id"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	name, okName := cleanName(in.Name)
	email, okEmail := cleanEmail(in.Email)
	switch {
	case !config.ValidID(in.Account) || len(in.Account) < 3:
		invalid(w, "account: 3+ characters, lowercase a-z 0-9 _ - (e.g. acme)")
	case !okName:
		invalid(w, "name: 1-100 characters")
	case !okEmail:
		invalid(w, "email: a valid address")
	case passwordProblem(in.Password) != "":
		invalid(w, passwordProblem(in.Password))
	case in.KMSKey != "" && !operator:
		invalid(w, "kms_key_id: set by the platform operator only")
	default:
		hash, e := hashPassword(in.Password)
		if e != nil {
			fail(w, 503, "unavailable")
			return
		}
		var id string
		if operator {
			id, e = a.Store.CreateAccount(r.Context(), in.Account, in.KMSKey, name, email, hash)
		} else {
			limit := a.SignupMax // 0 = uncapped (development; production refuses to start without a cap)
			if limit == 0 {
				limit = 1 << 30
			}
			id, e = a.Store.CreateOpenAccount(r.Context(), in.Account, name, email, hash, limit)
		}
		if errors.Is(e, store.ErrSignupClosed) {
			fail(w, 403, "signup_closed")
			return
		}
		if errors.Is(e, store.ErrExists) {
			fail(w, 409, "account_exists")
			return
		}
		if e != nil {
			dbFail(w, e)
			return
		}
		// An operator creating an account for someone else doesn't get signed in.
		if !operator {
			if e = a.startSession(r.Context(), w, in.Account, id, 1); e != nil {
				dbFail(w, e)
				return
			}
		}
		write(w, 201, me{Account: in.Account, UserID: id, Name: name, Email: email, Role: "admin", Actions: Roles["admin"]})
	}
}

// login: account + email + password only. Sets the access and refresh cookies.
func (a *API) login(w http.ResponseWriter, r *http.Request, open func(who string) bool, failed func(who string)) {
	var in struct {
		Account  string `json:"account"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	email, _ := cleanEmail(in.Email)
	who := in.Account + "/" + email
	if len(who) > 400 || !open(who) {
		write(w, 429, map[string]string{"error": "too_many_attempts", "detail": "try again in a minute"})
		return
	}
	l, e := a.Store.LoginLookup(r.Context(), in.Account, email)
	hash := l.Hash
	if e != nil {
		hash = dummyHash
	}
	if !checkPassword(hash, in.Password) || e != nil || !l.Active || !config.ValidID(in.Account) {
		failed(who)
		fail(w, 401, "invalid_credentials") // same answer for unknown account, email, password or disabled user
		return
	}
	scope := a.Store.ForTenant(in.Account)
	scope.TouchLogin(r.Context(), l.ID)
	if e = a.startSession(r.Context(), w, in.Account, l.ID, l.Version); e != nil {
		dbFail(w, e)
		return
	}
	out, _ := a.whoami(r.Context(), store.Caller{Tenant: in.Account, Role: l.Role, UserID: l.ID})
	write(w, 200, out)
}

// logout revokes this browser's session server-side (found via the refresh
// cookie, so it works even after the access token expired) and clears both.
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if ck, e := r.Cookie(refreshCookie); e == nil {
		if p := strings.SplitN(ck.Value, ".", 3); len(p) == 3 && config.ValidID(p[0]) {
			a.Store.ForTenant(p[0]).RevokeSession(r.Context(), p[1])
		}
	}
	if ck, e := r.Cookie(accessCookie); e == nil {
		if c, ok := verifyJWT(a.SessionKey, ck.Value, time.Now()); ok {
			a.Store.ForTenant(c.Acc).RevokeSession(r.Context(), c.Sid)
		}
	}
	a.clearSession(w)
	w.WriteHeader(204)
}
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	out, e := a.whoami(r.Context(), caller(r))
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, out)
}

// changePassword: own password, current one required; ends every session
// (including this one) and starts a fresh one for this browser.
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if c.UserID == "" {
		fail(w, 409, "root_key_has_no_password")
		return
	}
	if p := passwordProblem(in.New); p != "" {
		invalid(w, "new_"+p)
		return
	}
	scope := a.scope(r)
	old, e := scope.PasswordHash(r.Context(), c.UserID)
	if e != nil || !checkPassword(old, in.Current) {
		fail(w, 403, "current_password_wrong")
		return
	}
	hash, e := hashPassword(in.New)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	ver, e := scope.SetPassword(r.Context(), c.UserID, hash)
	if e == nil {
		e = scope.RevokeUserSessions(r.Context(), c.UserID, "")
	}
	if e == nil {
		e = a.startSession(r.Context(), w, c.Tenant, c.UserID, ver)
	}
	if e != nil {
		dbFail(w, e)
		return
	}
	w.WriteHeader(204)
}
func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	l, o, ok := paging(w, r)
	if !ok {
		return
	}
	out, e := a.scope(r).Users(r.Context(), l, o)
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, out)
}

// createUser: admin adds a person with a role and an initial password to hand
// over out of band (the user should change it on first sign-in).
func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	name, okName := cleanName(in.Name)
	email, okEmail := cleanEmail(in.Email)
	switch {
	case !okName:
		invalid(w, "name: 1-100 characters")
	case !okEmail:
		invalid(w, "email: a valid address")
	case Roles[in.Role] == nil:
		invalid(w, "role: admin, editor, operator or viewer")
	case passwordProblem(in.Password) != "":
		invalid(w, passwordProblem(in.Password))
	default:
		hash, e := hashPassword(in.Password)
		if e != nil {
			fail(w, 503, "unavailable")
			return
		}
		u, e := a.scope(r).CreateUser(r.Context(), name, email, in.Role, hash, caller(r).Actor)
		if errors.Is(e, store.ErrExists) {
			fail(w, 409, "email_already_in_account")
			return
		}
		if e != nil {
			dbFail(w, e)
			return
		}
		write(w, 201, u)
	}
}
func iamFail(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrLastAdmin):
		fail(w, 409, "account_needs_an_active_admin")
	case errors.Is(e, store.ErrKeyQuota):
		fail(w, 409, "two_keys_per_user_max")
	case errors.Is(e, store.ErrNotFound):
		fail(w, 404, "not_found")
	default:
		dbFail(w, e)
	}
}
func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   *string `json:"name"`
		Role   *string `json:"role"`
		Active *bool   `json:"active"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if in.Name != nil {
		n, ok := cleanName(*in.Name)
		if !ok {
			invalid(w, "name: 1-100 characters")
			return
		}
		in.Name = &n
	}
	if in.Role != nil && Roles[*in.Role] == nil {
		invalid(w, "role: admin, editor, operator or viewer")
		return
	}
	if e := a.scope(r).UpdateUser(r.Context(), r.PathValue("id"), in.Name, in.Role, in.Active); e != nil {
		iamFail(w, e)
		return
	}
	w.WriteHeader(204)
}
func (a *API) resetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	if p := passwordProblem(in.Password); p != "" {
		invalid(w, p)
		return
	}
	hash, e := hashPassword(in.Password)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	if _, e = a.scope(r).SetPassword(r.Context(), r.PathValue("id"), hash); e != nil {
		iamFail(w, e)
		return
	}
	w.WriteHeader(204)
}
func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == caller(r).UserID {
		fail(w, 409, "cannot_delete_yourself")
		return
	}
	if e := a.scope(r).DeleteUser(r.Context(), r.PathValue("id")); e != nil {
		iamFail(w, e)
		return
	}
	w.WriteHeader(204)
}

// Keys: admins manage anyone's; every user may manage their own (a key can
// never do more than its owner's role, like IAM access keys).
func (a *API) keyOwnerOK(r *http.Request, user string) bool {
	c := caller(r)
	return allowed(c.Role, "iam:write") || (c.UserID != "" && c.UserID == user)
}
func (a *API) listKeys(w http.ResponseWriter, r *http.Request) {
	if !a.keyOwnerOK(r, r.PathValue("id")) {
		fail(w, 403, "forbidden")
		return
	}
	out, e := a.scope(r).Keys(r.Context(), r.PathValue("id"))
	if e != nil {
		dbFail(w, e)
		return
	}
	write(w, 200, out)
}
func (a *API) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !jsonBody(w, r, &in) {
		return
	}
	user := r.PathValue("id")
	if !a.keyOwnerOK(r, user) {
		fail(w, 403, "forbidden")
		return
	}
	name, ok := cleanName(in.Name)
	if !ok {
		invalid(w, "name: what the key is for, e.g. ci-pipeline")
		return
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		fail(w, 503, "unavailable")
		return
	}
	secret := "cbk_" + hex.EncodeToString(raw)
	k, e := a.scope(r).CreateKey(r.Context(), user, name, secret)
	if e != nil {
		iamFail(w, e)
		return
	}
	// The only time the key is ever shown; only its SHA-256 is stored.
	write(w, 201, map[string]any{"key": k, "secret": secret})
}
func (a *API) changeKey(w http.ResponseWriter, r *http.Request, del bool) {
	scope := a.scope(r)
	k, e := scope.Key(r.Context(), r.PathValue("key"))
	if e != nil {
		iamFail(w, e)
		return
	}
	if !a.keyOwnerOK(r, k.UserID) {
		fail(w, 403, "forbidden")
		return
	}
	if del {
		e = scope.DeleteKey(r.Context(), k.ID)
	} else {
		var in struct {
			Active bool `json:"active"`
		}
		if !jsonBody(w, r, &in) {
			return
		}
		e = scope.SetKeyActive(r.Context(), k.ID, in.Active)
	}
	if e != nil {
		iamFail(w, e)
		return
	}
	w.WriteHeader(204)
}
