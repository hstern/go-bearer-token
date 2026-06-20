// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

package bearer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChallengeString(t *testing.T) {
	tests := []struct {
		name string
		c    Challenge
		want string
	}{
		{
			name: "bare challenge",
			c:    Challenge{},
			want: "Bearer",
		},
		{
			name: "realm only",
			c:    Challenge{Realm: "example"},
			want: `Bearer realm="example"`,
		},
		{
			// The canonical §3 example for an expired token.
			name: "invalid_token with description",
			c:    Challenge{Realm: "example", Error: ErrorInvalidToken, ErrorDescription: "The access token expired"},
			want: `Bearer realm="example", error="invalid_token", error_description="The access token expired"`,
		},
		{
			name: "insufficient_scope carries scope",
			c:    Challenge{Realm: "example", Error: ErrorInsufficientScope, Scope: "read write"},
			want: `Bearer realm="example", error="insufficient_scope", scope="read write"`,
		},
		{
			name: "all named fields, deterministic order",
			c: Challenge{
				Realm:            "r",
				Scope:            "s",
				Error:            ErrorInvalidRequest,
				ErrorDescription: "d",
				ErrorURI:         "https://example.com/e",
			},
			want: `Bearer realm="r", error="invalid_request", error_description="d", error_uri="https://example.com/e", scope="s"`,
		},
		{
			name: "extra params sorted after named ones",
			c: Challenge{
				Error: ErrorInvalidToken,
				Extra: map[string]string{"resource_metadata": "https://rs.example.com/.well-known", "audience": "https://rs.example.com/"},
			},
			want: `Bearer error="invalid_token", audience="https://rs.example.com/", resource_metadata="https://rs.example.com/.well-known"`,
		},
		{
			name: "value with quote and backslash is escaped",
			c:    Challenge{ErrorDescription: `a "quote" and a \slash`},
			want: `Bearer error_description="a \"quote\" and a \\slash"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("String() =\n  %s\nwant\n  %s", got, tt.want)
			}
		})
	}
}

func TestChallengeWriteHeader(t *testing.T) {
	tests := []struct {
		name       string
		c          Challenge
		wantStatus int
	}{
		{"bare challenge is 401", Challenge{Realm: "x"}, http.StatusUnauthorized},
		{"invalid_request is 400", Challenge{Error: ErrorInvalidRequest}, http.StatusBadRequest},
		{"invalid_token is 401", Challenge{Error: ErrorInvalidToken}, http.StatusUnauthorized},
		{"insufficient_scope is 403", Challenge{Error: ErrorInsufficientScope}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.c.WriteHeader(w)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != tt.c.String() {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.c.String())
			}
		})
	}
}

func TestStatusFor(t *testing.T) {
	tests := []struct {
		code string
		want int
	}{
		{ErrorInvalidRequest, http.StatusBadRequest},
		{ErrorInvalidToken, http.StatusUnauthorized},
		{ErrorInsufficientScope, http.StatusForbidden},
		{"", http.StatusUnauthorized},
		{"something_unknown", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		if got := StatusFor(tt.code); got != tt.want {
			t.Errorf("StatusFor(%q) = %d, want %d", tt.code, got, tt.want)
		}
	}
}

func TestSpecVersion(t *testing.T) {
	if SpecVersion != "RFC 6750" {
		t.Fatalf("SpecVersion = %q, want RFC 6750", SpecVersion)
	}
}
