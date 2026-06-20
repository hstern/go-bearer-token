// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

package bearer

import (
	"net/http"
	"sort"
	"strings"
)

// Challenge is a typed WWW-Authenticate: Bearer challenge (§3). The zero value
// is a valid bare challenge — String reports just "Bearer" — which is what a
// resource server returns, with a 401, for a request that carried no
// credentials. Set Error to one of the Error* codes to turn it into a §3.1
// error challenge; [Challenge.WriteHeader] then derives the status via
// [StatusFor].
//
// Auth-param values are emitted as quoted-strings with " and \ escaped. Only
// the attributes the spec defines are rendered from the named fields; Extra
// carries any additional auth-params (for example RFC 9728's resource_metadata),
// rendered after the named ones in sorted key order. Empty fields are omitted.
type Challenge struct {
	// Realm scopes the protection space (§3). Optional.
	Realm string
	// Scope is a space-delimited list of scopes that would satisfy the
	// resource (§3); typically set alongside ErrorInsufficientScope.
	Scope string
	// Error is a §3.1 error code: one of ErrorInvalidRequest,
	// ErrorInvalidToken, or ErrorInsufficientScope. Empty for a bare challenge.
	Error string
	// ErrorDescription is human-readable detail for a developer (§3.1). It
	// MUST NOT be shown to end users.
	ErrorDescription string
	// ErrorURI points to a human-readable page about the error (§3.1).
	ErrorURI string
	// Extra carries additional auth-params not modeled above, such as the
	// RFC 9728 resource_metadata parameter. Keys are rendered verbatim in
	// sorted order; values are quoted like the named fields.
	Extra map[string]string
}

// String renders the WWW-Authenticate header value, for example:
//
//	Bearer realm="example", error="invalid_token", error_description="The access token expired"
//
// A zero-value Challenge renders as "Bearer".
func (c Challenge) String() string {
	var b strings.Builder
	b.WriteString("Bearer")
	sep := " "

	write := func(key, val string) {
		if val == "" {
			return
		}
		b.WriteString(sep)
		sep = ", "
		b.WriteString(key)
		b.WriteString(`="`)
		b.WriteString(quote(val))
		b.WriteByte('"')
	}

	write("realm", c.Realm)
	write("error", c.Error)
	write("error_description", c.ErrorDescription)
	write("error_uri", c.ErrorURI)
	write("scope", c.Scope)

	if len(c.Extra) > 0 {
		keys := make([]string, 0, len(c.Extra))
		for k := range c.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			write(k, c.Extra[k])
		}
	}

	return b.String()
}

// WriteHeader sets WWW-Authenticate to c.String() on w and writes the HTTP
// status for c.Error (via [StatusFor]): a bare challenge and invalid_token
// yield 401, invalid_request 400, insufficient_scope 403. Like
// http.ResponseWriter.WriteHeader, it must be called before any body is
// written and only once.
func (c Challenge) WriteHeader(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", c.String())
	w.WriteHeader(StatusFor(c.Error))
}

// quote escapes the two characters a quoted-string may not contain literally,
// per RFC 7230: the backslash and the double quote.
func quote(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
