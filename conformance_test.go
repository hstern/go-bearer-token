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

// TestConformance walks the normative RFC 6750 §2 transport scenarios end to
// end, naming each by the section it exercises. Options are enabled per case so
// the discouraged methods are only ever active when a server opts in.
func TestConformance(t *testing.T) {
	tests := []struct {
		name    string
		req     func() *http.Request
		opts    []ExtractOption
		want    string
		wantErr error
	}{
		{
			name: "§2.1 authorization header is the default",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer mF_9.B5f-4.1JqM")
				return r
			},
			want: "mF_9.B5f-4.1JqM",
		},
		{
			name: "§2.2 form body, opt-in",
			req: func() *http.Request {
				return newForm(http.MethodPost, "/", url.Values{"access_token": {"mF_9.B5f-4.1JqM"}}.Encode())
			},
			opts: []ExtractOption{WithFormBody()},
			want: "mF_9.B5f-4.1JqM",
		},
		{
			name: "§2.2 GET MUST NOT use the body method",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("access_token=mF_9"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			opts:    []ExtractOption{WithFormBody()},
			wantErr: ErrNoToken,
		},
		{
			name: "§2.2 malformed body token is invalid_request",
			req: func() *http.Request {
				// "a b" survives urlencoding and decodes back to a space-bearing value.
				return newForm(http.MethodPost, "/", url.Values{"access_token": {"a b"}}.Encode())
			},
			opts:    []ExtractOption{WithFormBody()},
			wantErr: ErrMalformedToken,
		},
		{
			name: "§2.3 query parameter, opt-in",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/resource?access_token=mF_9.B5f-4.1JqM", nil)
			},
			opts: []ExtractOption{WithURIQuery()},
			want: "mF_9.B5f-4.1JqM",
		},
		{
			name: "§2 more than one method is invalid_request",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/?access_token=qtok", nil)
				r.Header.Set("Authorization", "Bearer htok")
				return r
			},
			opts:    []ExtractOption{WithURIQuery()},
			wantErr: ErrMultipleTokens,
		},
		{
			name: "§3 no credentials returns ErrNoToken",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantErr: ErrNoToken,
		},
		{
			name: "§2.1 padding-only credential is malformed",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer ===")
				return r
			},
			wantErr: ErrMalformedToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Token(tt.req(), tt.opts...)
			if got != tt.want {
				t.Errorf("token = %q, want %q", got, tt.want)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestExtractionErrorsMapToStatus is the bridge the package is built for: an
// extraction error chooses the challenge a resource server sends back.
func TestExtractionErrorsMapToStatus(t *testing.T) {
	tests := []struct {
		err        error
		errorCode  string
		wantStatus int
	}{
		{ErrNoToken, "", http.StatusUnauthorized},
		{ErrMultipleTokens, ErrorInvalidRequest, http.StatusBadRequest},
		{ErrMalformedToken, ErrorInvalidRequest, http.StatusBadRequest},
	}
	for _, tt := range tests {
		// The empty errorCode is the bare-challenge case for ErrNoToken.
		if got := StatusFor(tt.errorCode); got != tt.wantStatus {
			t.Errorf("StatusFor(%q) = %d, want %d", tt.errorCode, got, tt.wantStatus)
		}
	}
}
