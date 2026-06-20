// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

package bearer_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	bearer "github.com/hstern/go-bearer-token"
)

// Example_resourceServer shows the two halves of RFC 6750 a resource server
// uses: extract the token on the way in, and answer with a typed challenge when
// it has to refuse. Token validation (the middle step) belongs to another
// library and is elided here.
func Example_resourceServer() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		token, err := bearer.Token(r)
		switch {
		case errors.Is(err, bearer.ErrNoToken):
			// No credentials: a bare challenge with 401 (§3).
			bearer.Challenge{Realm: "example"}.WriteHeader(w)
			return
		case err != nil:
			// Malformed or multiply-presented token: invalid_request / 400.
			bearer.Challenge{
				Realm:            "example",
				Error:            bearer.ErrorInvalidRequest,
				ErrorDescription: err.Error(),
			}.WriteHeader(w)
			return
		}

		// ... validate token here (signature, claims, scope) ...
		_ = token
		_, _ = fmt.Fprintln(w, "ok")
	}

	// A request with no Authorization header gets the bare challenge.
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println("status:", w.Code)
	fmt.Println("challenge:", w.Header().Get("WWW-Authenticate"))
	// Output:
	// status: 401
	// challenge: Bearer realm="example"
}

// Example_invalidToken builds the canonical §3 challenge for a token that
// failed validation.
func Example_invalidToken() {
	c := bearer.Challenge{
		Realm:            "example",
		Error:            bearer.ErrorInvalidToken,
		ErrorDescription: "The access token expired",
	}
	fmt.Println(c)
	fmt.Println("status:", bearer.StatusFor(c.Error))
	// Output:
	// Bearer realm="example", error="invalid_token", error_description="The access token expired"
	// status: 401
}

// Example_insufficientScope advertises the scopes that would satisfy the
// resource (§3), paired with a 403.
func Example_insufficientScope() {
	c := bearer.Challenge{
		Error: bearer.ErrorInsufficientScope,
		Scope: "read write",
	}
	fmt.Println(c)
	fmt.Println("status:", bearer.StatusFor(c.Error))
	// Output:
	// Bearer error="insufficient_scope", scope="read write"
	// status: 403
}

// ExampleToken_query enables the discouraged §2.3 query-parameter method. A
// server that does this MUST also send Cache-Control: no-store.
func ExampleToken_query() {
	r := httptest.NewRequest(http.MethodGet, "/resource?access_token=mF_9.B5f-4.1JqM", nil)

	token, err := bearer.Token(r, bearer.WithURIQuery())
	fmt.Println(token, err)
	// Output: mF_9.B5f-4.1JqM <nil>
}
