package engine

// This file keeps URLs safe to log. Query strings often carry search terms,
// account IDs or (on badly designed APIs) keys, so we never log them.

import (
	"errors"
	"fmt"
	"net/url"
)

// RedactURL keeps only scheme://host/path. It drops:
//   - the query string (?token=...&q=...)
//   - any user:password@ part
//   - the #fragment
//
// Example: https://u:p@api.x.com/v1/users?key=abc  ->  https://api.x.com/v1/users
//
// Use it for EVERY URL that goes into a log line or an error message.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

// scrub fixes Go's HTTP errors, which embed the FULL URL in their message:
//
//	Get "https://api.x.com/v1?key=abc": context deadline exceeded
//
// becomes
//
//	Get https://api.x.com/v1: context deadline exceeded
//
// The original cause is kept with %w, so errors.Is / errors.As still work
// (e.g. errors.Is(err, egress.ErrBlocked) after a refused redirect).
func scrub(err error, u *url.URL) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, RedactURL(u), ue.Err)
	}
	return err
}
