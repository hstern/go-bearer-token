// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

package bearer

import (
	"errors"
	"mime"
	"net/http"
	"strings"
)

// Errors returned by [Token].
var (
	// ErrNoToken means no bearer token was present in any enabled location.
	// A resource server answers this with a bare WWW-Authenticate: Bearer
	// challenge and HTTP 401 (§3) — the request simply carried no credentials,
	// which is not itself a protocol error.
	ErrNoToken = errors.New("bearer: no bearer token in request")

	// ErrMultipleTokens means a token was presented in more than one place —
	// across methods, or repeated within one. This is the §2 "more than one
	// method" rule, an invalid_request (HTTP 400).
	ErrMultipleTokens = errors.New("bearer: token presented in multiple places")

	// ErrMalformedToken means a bearer token was present but does not match the
	// §2.1 b64token syntax (for example it contains a space or control byte),
	// or the Authorization: Bearer header carried no token at all. This is an
	// invalid_request (HTTP 400).
	ErrMalformedToken = errors.New("bearer: malformed bearer credentials")
)

// ExtractOption configures [Token]. The Authorization header (§2.1) is always
// read; options enable the spec's discouraged transport methods.
type ExtractOption func(*extractConfig)

type extractConfig struct {
	formBody bool
	uriQuery bool
}

// WithFormBody enables extraction from the form-encoded request body (§2.2):
// an access_token parameter in an application/x-www-form-urlencoded body. Per
// the spec this method is never honored on GET requests, and it parses the
// request body (via http.Request.ParseForm) as a side effect. It is opt-in
// because most resource servers do not accept tokens in the body.
func WithFormBody() ExtractOption {
	return func(c *extractConfig) { c.formBody = true }
}

// WithURIQuery enables extraction from the URI query string (§2.3): an
// access_token query parameter. The spec marks this method SHOULD NOT — query
// strings leak into logs, browser history, and Referer headers — so it is
// off by default. A server that enables it MUST send Cache-Control: no-store
// on responses to such requests (§2.3); this package does not set that header
// for you.
func WithURIQuery() ExtractOption {
	return func(c *extractConfig) { c.uriQuery = true }
}

// Token extracts the bearer token from an HTTP request per RFC 6750 §2. It
// reads the Authorization: Bearer header by default; pass [WithFormBody] and/or
// [WithURIQuery] to also accept the body and query-string methods.
//
// It returns [ErrNoToken] when no token is present, [ErrMultipleTokens] when a
// token appears in more than one enabled location (the §2 invalid_request), and
// [ErrMalformedToken] when a present token violates the §2.1 b64token syntax.
// Match these with errors.Is to choose the right [Challenge]. The returned
// token is the raw credential string; this package does not validate it.
func Token(r *http.Request, opts ...ExtractOption) (string, error) {
	var cfg extractConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	var found []string

	// §2.1 Authorization request header field — always read.
	tok, err := tokenFromHeader(r)
	if err != nil {
		return "", err
	}
	if tok != "" {
		found = append(found, tok)
	}

	// §2.2 Form-encoded body parameter — opt-in.
	if cfg.formBody {
		toks, err := tokensFromForm(r)
		if err != nil {
			return "", err
		}
		found = append(found, toks...)
	}

	// §2.3 URI query parameter — opt-in, discouraged.
	if cfg.uriQuery {
		toks, err := validTokens(r.URL.Query()["access_token"])
		if err != nil {
			return "", err
		}
		found = append(found, toks...)
	}

	switch len(found) {
	case 0:
		return "", ErrNoToken
	case 1:
		return found[0], nil
	default:
		return "", ErrMultipleTokens
	}
}

// tokenFromHeader reads the Authorization: Bearer header (§2.1). It returns the
// empty string (no error) when no Authorization header is present or its scheme
// is not Bearer — a resource server may support other schemes alongside Bearer.
// A Bearer header with a missing or syntactically invalid token is
// [ErrMalformedToken].
func tokenFromHeader(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", nil
	}
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", nil
	}
	token := strings.TrimSpace(rest)
	if token == "" || !isB64Token(token) {
		return "", ErrMalformedToken
	}
	return token, nil
}

// tokensFromForm reads access_token from an application/x-www-form-urlencoded
// request body (§2.2). It honors the spec's guards: never on GET (nor HEAD,
// which likewise has no request body), and only when the Content-Type is
// form-urlencoded. Non-form requests yield no token and no error.
func tokensFromForm(r *http.Request) ([]string, error) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil, nil
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		return nil, nil
	}
	if err := r.ParseForm(); err != nil {
		// A body we cannot parse carries no token we can trust.
		return nil, nil
	}
	// PostForm holds body parameters only, never the URL query — exactly the
	// §2.2 surface, kept distinct from the §2.3 query method.
	return validTokens(r.PostForm["access_token"])
}

// validTokens drops empty values and verifies each remaining one against the
// §2.1 b64token syntax, returning [ErrMalformedToken] on the first violation.
func validTokens(vals []string) ([]string, error) {
	var out []string
	for _, v := range vals {
		if v == "" {
			continue
		}
		if !isB64Token(v) {
			return nil, ErrMalformedToken
		}
		out = append(out, v)
	}
	return out, nil
}

// isB64Token reports whether s matches the §2.1 b64token grammar:
//
//	b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
func isB64Token(s string) bool {
	i := 0
	for i < len(s) && isB64Char(s[i]) {
		i++
	}
	if i == 0 {
		return false // need at least one non-padding character
	}
	for ; i < len(s); i++ {
		if s[i] != '=' {
			return false // only "=" padding may follow
		}
	}
	return true
}

func isB64Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		return true
	default:
		return false
	}
}
