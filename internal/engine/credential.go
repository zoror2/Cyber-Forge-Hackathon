package engine

// This file classifies credential problems so the platform can tell the
// RIGHT person exactly what to fix ("Ravi's GitHub key needs re-auth")
// instead of a generic "connector failed".
//
// Member B's side does:
//
//	var ae *engine.AuthError
//	if errors.As(err, &ae) {
//	    // update credential ae.CredentialID: status = ae.Status, notify its owner
//	}
//
// An AuthError never contains a secret value or a vendor response body.

import "fmt"

// Credential statuses reported by the engine. Each one has a different fix.
const (
	StatusMissing                 = "missing"                  // secret not in the store: add it
	StatusIncomplete              = "incomplete"               // a required field is missing: complete it
	StatusBindingMismatch         = "binding_mismatch"         // secret not bound to this host: fix the binding (also an egress block)
	StatusNeedsReauth             = "needs_reauth"             // vendor said 401 (or token endpoint refused): rotate / re-enter the key
	StatusInsufficientPermissions = "insufficient_permissions" // vendor said 403: grant the role/scope the template needs
)

// AuthError is a credential problem with its classification.
type AuthError struct {
	Status       string // one of the Status* constants
	Secret       string // secret NAME from the config (not the value)
	CredentialID string // credential record ID, "" if the store didn't set one
	Err          error  // underlying cause (StatusError, egress.ErrBlocked, ...)
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("credential %q: %s: %v", e.Secret, e.Status, e.Err)
}

// Unwrap keeps errors.Is / errors.As working on the cause, so a binding
// mismatch is still egress.ErrBlocked and a 401 is still a *StatusError.
func (e *AuthError) Unwrap() error { return e.Err }

func authErr(status, secret, credID string, err error) error {
	return &AuthError{Status: status, Secret: secret, CredentialID: credID, Err: err}
}

// statusFromHTTP maps a vendor (or token endpoint) HTTP status to a credential
// status. ok=false means "not a credential problem" (e.g. 500, 429).
// OAuth token endpoints answer a wrong client secret with 400 or 401
// (RFC 6749 §5.2, "invalid_client"), so tokenEndpoint treats 400 as re-auth too.
func statusFromHTTP(code int, tokenEndpoint bool) (string, bool) {
	switch {
	case code == 401, tokenEndpoint && code == 400:
		return StatusNeedsReauth, true
	case code == 403:
		return StatusInsufficientPermissions, true
	}
	return "", false
}
