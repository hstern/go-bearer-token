# AGENTS.md — go-bearer-token

Go library implementing RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage.

Two responsibilities, and only these two: extract a bearer token from an HTTP
request (§2) and compose the `WWW-Authenticate: Bearer` challenge (§3). Token
validation and the authorization decision live in other libraries; this one is
upstream of them.

## Copyright header

Every `.go` file (including tests) starts with exactly:

```go
// Copyright 2026 The go-bearer-token Authors
// SPDX-License-Identifier: Apache-2.0
```

No per-file license preamble beyond the SPDX tag; the full text is in `LICENSE`.
`README.md`, `AGENTS.md`, `CHANGELOG.md`, and workflow YAML do not carry it.

## Dependencies

- **Runtime: standard library only.** No third-party runtime dependency. Any
  proposal for one needs a justification in the PR and the default answer is no.
- **Tests: standard library only.** `net/http/httptest` is the harness.
- **Build-time tooling: unconstrained**, but invoked via `go run` with a pinned
  version (see the `vuln` workflow); it never lands in users' `go.sum`.
- **`go.mod`**: module path stays `github.com/hstern/go-bearer-token`, no `/vN`
  suffix for v0.x/v1.x (Go SemVer rule). Go 1.26+.

## Design posture

- **Wire fidelity over shortcuts.** Token syntax is validated against the §2.1
  `b64token` ABNF; the challenge is a spec-faithful `quoted-string`.
- **Stdlib `net/http`, no framework glue.** Works with `chi`, `gorilla/mux`,
  etc. without special-casing.
- **The discouraged transport methods are opt-in.** Header is always on; form
  body (§2.2) and query string (§2.3) require `WithFormBody` / `WithURIQuery`.
  Keep it that way — the spec discourages both.
- **Distinguish absent from malformed.** `ErrNoToken` (bare 401) and
  `ErrMalformedToken` / `ErrMultipleTokens` (invalid_request, 400) map to
  different challenges; never collapse them.

## Local checks before a PR

```bash
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
```

CI runs `static` (gofmt + vet + build), `test` (race + coverage), and `lint`
(golangci-lint), plus a `vuln` (govulncheck) workflow.
