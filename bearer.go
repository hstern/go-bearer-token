// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

// Package bearer implements RFC 6750 — the OAuth 2.0 Bearer Token Usage
// profile: extracting a bearer token from an HTTP request (§2) and composing
// the WWW-Authenticate: Bearer challenge a resource server returns when it
// refuses one (§3).
//
// It owns exactly two things: the wire shape of bearer-token transport and the
// challenge response. It does not validate the token (that is the JWT profile,
// RFC 9068, or introspection, RFC 7662) and it does not make the authorization
// decision. The intended resource-server flow is:
//
//  1. extract the token from the request with [Token];
//  2. validate it (signature, claims, scope) with the appropriate library;
//  3. on failure, answer with a [Challenge] carrying the right §3.1 error code.
//
// # Extraction
//
// [Token] reads the Authorization: Bearer header (§2.1) by default. The other
// two transport methods are opt-in because the spec discourages them: the
// form-encoded body parameter (§2.2) via [WithFormBody], and the URI query
// parameter (§2.3) — which the spec marks SHOULD NOT — via [WithURIQuery]. A
// request presenting a token in more than one enabled location is rejected
// with [ErrMultipleTokens]: the §2 "more than one method" invalid_request.
//
// # Challenge
//
// [Challenge] is the typed WWW-Authenticate: Bearer value. Build one, then
// render it with [Challenge.String] or write it (header plus status) to an
// http.ResponseWriter with [Challenge.WriteHeader]. [StatusFor] maps a §3.1
// error code to its canonical HTTP status.
//
// Spec: https://www.rfc-editor.org/rfc/rfc6750.html
package bearer

import "net/http"

// SpecVersion is the version of the specification this package targets.
const SpecVersion = "RFC 6750"

// Error codes for the WWW-Authenticate: Bearer challenge (§3.1). Each has a
// canonical HTTP status; see [StatusFor].
const (
	// ErrorInvalidRequest (HTTP 400) — the request is malformed: a missing or
	// repeated parameter, or a token presented by more than one method (§2).
	ErrorInvalidRequest = "invalid_request"
	// ErrorInvalidToken (HTTP 401) — the access token is expired, revoked,
	// malformed, or otherwise invalid.
	ErrorInvalidToken = "invalid_token"
	// ErrorInsufficientScope (HTTP 403) — the token lacks the scope the
	// resource requires.
	ErrorInsufficientScope = "insufficient_scope"
)

// StatusFor returns the HTTP status code that accompanies a §3.1 error code:
// invalid_request → 400, invalid_token → 401, insufficient_scope → 403. The
// empty string (a bare challenge, sent with a 401 when a request carries no
// credentials) and any unrecognized code return 401.
func StatusFor(errCode string) int {
	switch errCode {
	case ErrorInvalidRequest:
		return http.StatusBadRequest
	case ErrorInvalidToken:
		return http.StatusUnauthorized
	case ErrorInsufficientScope:
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}
