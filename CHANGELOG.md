# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Token(r, ...ExtractOption)` — RFC 6750 §2 extraction. Reads the
  `Authorization: Bearer` header (§2.1) by default; `WithFormBody` enables the
  form-encoded body parameter (§2.2, never on GET) and `WithURIQuery` enables
  the discouraged URI query parameter (§2.3). Enforces the §2 single-method
  rule and validates token syntax against the §2.1 `b64token` grammar.
- Typed extraction errors `ErrNoToken` (bare 401 challenge), `ErrMultipleTokens`
  and `ErrMalformedToken` (both `invalid_request` / 400), matchable with
  `errors.Is`.
- `Challenge` — the typed `WWW-Authenticate: Bearer` value (§3) with `Realm`,
  `Scope`, `Error`, `ErrorDescription`, `ErrorURI`, and an `Extra` map for
  additional auth-params (for example RFC 9728 `resource_metadata`). `String`
  renders the header value as an escaped `quoted-string`; `WriteHeader` sets the
  header and the status on an `http.ResponseWriter`.
- `StatusFor` and the `ErrorInvalidRequest` / `ErrorInvalidToken` /
  `ErrorInsufficientScope` constants — the §3.1 error codes and their canonical
  HTTP statuses (400 / 401 / 403).
- `const SpecVersion = "RFC 6750"`.
