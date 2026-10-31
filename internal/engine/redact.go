package engine

import (
	"errors"
	"fmt"
	"net/url"
)

// RedactURL keeps scheme, host and path only: no query string, no userinfo.
// Use it for every URL that reaches a log line or an error message.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

// scrub replaces the full URL that net/http puts into *url.Error messages
// with the redacted form, while keeping the wrapped cause for errors.Is.
func scrub(err error, u *url.URL) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, RedactURL(u), ue.Err)
	}
	return err
}
