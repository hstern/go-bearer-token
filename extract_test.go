// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0

package bearer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTokenFromHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr error
	}{
		{"canonical", "Bearer mF_9.B5f-4.1JqM", "mF_9.B5f-4.1JqM", nil},
		{"lowercase scheme", "bearer abc123", "abc123", nil},
		{"mixed-case scheme", "BeArEr abc123", "abc123", nil},
		{"extra spaces after scheme", "Bearer   abc123", "abc123", nil},
		{"trailing space tolerated", "Bearer abc123 ", "abc123", nil},
		{"jwt with dots and base64url", "Bearer eyJhbGci.eyJzdWIi.c2ln-_", "eyJhbGci.eyJzdWIi.c2ln-_", nil},
		{"base64 padding", "Bearer YWJjZA==", "YWJjZA==", nil},
		{"no header", "", "", ErrNoToken},
		{"other scheme is ignored", "Basic dXNlcjpwYXNz", "", ErrNoToken},
		{"bearer without token", "Bearer", "", ErrMalformedToken},
		{"bearer with only spaces", "Bearer    ", "", ErrMalformedToken},
		{"token with internal space", "Bearer ab cd", "", ErrMalformedToken},
		{"token with illegal char", "Bearer abc,def", "", ErrMalformedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			got, err := Token(r)
			if got != tt.want {
				t.Errorf("token = %q, want %q", got, tt.want)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenFormBody(t *testing.T) {
	form := url.Values{"access_token": {"form-tok"}}.Encode()

	t.Run("disabled by default", func(t *testing.T) {
		r := newForm(http.MethodPost, "/", form)
		if _, err := Token(r); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken (form ignored without opt-in)", err)
		}
	})

	t.Run("extracted when enabled", func(t *testing.T) {
		r := newForm(http.MethodPost, "/", form)
		got, err := Token(r, WithFormBody())
		if err != nil || got != "form-tok" {
			t.Fatalf("Token = %q, %v; want form-tok, nil", got, err)
		}
	})

	t.Run("never on GET", func(t *testing.T) {
		// A GET cannot carry a form-body token per §2.2, even with the option.
		r := httptest.NewRequest(http.MethodGet, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := Token(r, WithFormBody()); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken (GET body must be ignored)", err)
		}
	})

	t.Run("ignored without form content-type", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"access_token":"x"}`))
		r.Header.Set("Content-Type", "application/json")
		if _, err := Token(r, WithFormBody()); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken (non-form body ignored)", err)
		}
	})

	t.Run("content-type with charset param", func(t *testing.T) {
		r := newForm(http.MethodPost, "/", form)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		got, err := Token(r, WithFormBody())
		if err != nil || got != "form-tok" {
			t.Fatalf("Token = %q, %v; want form-tok, nil", got, err)
		}
	})

	t.Run("query in body request is not read as form", func(t *testing.T) {
		// access_token is in the URL query, not the body; WithFormBody only.
		r := newForm(http.MethodPost, "/?access_token=querytok", "other=1")
		if _, err := Token(r, WithFormBody()); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken (query must not satisfy form method)", err)
		}
	})
}

func TestTokenURIQuery(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=qtok", nil)
		if _, err := Token(r); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken (query ignored without opt-in)", err)
		}
	})

	t.Run("extracted when enabled", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=qtok", nil)
		got, err := Token(r, WithURIQuery())
		if err != nil || got != "qtok" {
			t.Fatalf("Token = %q, %v; want qtok, nil", got, err)
		}
	})

	t.Run("malformed query token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=has%20space", nil)
		if _, err := Token(r, WithURIQuery()); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("err = %v, want ErrMalformedToken", err)
		}
	})

	t.Run("empty query value is no token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=", nil)
		if _, err := Token(r, WithURIQuery()); !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken", err)
		}
	})
}

func TestTokenMultipleMethods(t *testing.T) {
	t.Run("header and query", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=qtok", nil)
		r.Header.Set("Authorization", "Bearer htok")
		if _, err := Token(r, WithURIQuery()); !errors.Is(err, ErrMultipleTokens) {
			t.Fatalf("err = %v, want ErrMultipleTokens", err)
		}
	})

	t.Run("header and body", func(t *testing.T) {
		r := newForm(http.MethodPost, "/", url.Values{"access_token": {"form-tok"}}.Encode())
		r.Header.Set("Authorization", "Bearer htok")
		if _, err := Token(r, WithFormBody()); !errors.Is(err, ErrMultipleTokens) {
			t.Fatalf("err = %v, want ErrMultipleTokens", err)
		}
	})

	t.Run("repeated query parameter", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?access_token=a&access_token=b", nil)
		if _, err := Token(r, WithURIQuery()); !errors.Is(err, ErrMultipleTokens) {
			t.Fatalf("err = %v, want ErrMultipleTokens", err)
		}
	})

	t.Run("all three methods at once", func(t *testing.T) {
		r := newForm(http.MethodPost, "/?access_token=qtok", url.Values{"access_token": {"form-tok"}}.Encode())
		r.Header.Set("Authorization", "Bearer htok")
		if _, err := Token(r, WithFormBody(), WithURIQuery()); !errors.Is(err, ErrMultipleTokens) {
			t.Fatalf("err = %v, want ErrMultipleTokens", err)
		}
	})
}

// newForm builds a urlencoded-body request with the right Content-Type.
func newForm(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}
