# go-bearer-token

typed extraction of OAuth 2.0 bearer tokens from HTTP requests, and composition
of the `WWW-Authenticate: Bearer` challenge response.

Implements **RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token
Usage** (Proposed Standard, 2012-10).
Spec: <https://www.rfc-editor.org/rfc/rfc6750.html>

## What this library is and is not

A resource server speaks RFC 6750 at two moments: when a request *arrives*
(pull the bearer token out of it, §2) and when it is *refused* (tell the client
how, via a `WWW-Authenticate: Bearer` challenge with a typed error code, §3).
This library owns exactly those two halves — the wire shape of bearer-token
transport and the challenge response. Zero non-test dependencies: standard
library only.

It does **not**:

- **Validate the token.** Verifying a JWT access token is
  [`go-access-tokens`](https://github.com/hstern/go-access-tokens) (RFC 9068);
  validating an opaque token is
  [`go-token-introspection`](https://github.com/hstern/go-token-introspection)
  (RFC 7662). This library is upstream of both: it extracts the credential
  string and hands it on.
- **Make the authorization decision** (are the scopes satisfied? who is the
  subject?).
- **Terminate TLS.** RFC 6750 §1 requires it, but that is transport
  configuration, not this library.

## Status

Pre-v0.1.0. The public API is not yet stable.

## Install

```bash
go get github.com/hstern/go-bearer-token
```

## Quickstart

### Extract a token (§2)

The `Authorization: Bearer` header (§2.1) is read by default. The other two
transport methods the spec defines are discouraged, so they are opt-in:

```go
import bearer "github.com/hstern/go-bearer-token"

token, err := bearer.Token(r)                       // §2.1 header only
token, err := bearer.Token(r, bearer.WithFormBody()) // also §2.2 form body
token, err := bearer.Token(r, bearer.WithURIQuery()) // also §2.3 query string
```

`Token` enforces the §2 rules for you: the form-body method is never honored on
`GET`, a token presented in more than one enabled location is rejected, and a
present-but-malformed credential is reported distinctly from an absent one:

```go
token, err := bearer.Token(r)
switch {
case errors.Is(err, bearer.ErrNoToken):
	// No credentials — answer with a bare challenge and 401.
	bearer.Challenge{Realm: "example"}.Respond(w)
	return
case err != nil:
	// errors.Is(err, bearer.ErrMultipleTokens) or ErrMalformedToken —
	// both are an invalid_request (400).
	bearer.Challenge{Realm: "example", Error: bearer.ErrorInvalidRequest,
		ErrorDescription: err.Error()}.Respond(w)
	return
}

// ... validate token (signature, claims, scope) with another library ...
```

> The §2.3 query-string method leaks tokens into logs, browser history, and
> `Referer` headers; the spec marks it **SHOULD NOT**. A server that enables it
> with `WithURIQuery` MUST send `Cache-Control: no-store` on those responses
> (§2.3) — this library does not set that header for you.

### Compose a challenge (§3)

`Challenge` is the typed `WWW-Authenticate: Bearer` value. The zero value is a
valid bare challenge (`Bearer`); set `Error` to one of the §3.1 codes to make it
an error challenge.

```go
c := bearer.Challenge{
	Realm:            "example",
	Error:            bearer.ErrorInvalidToken,
	ErrorDescription: "The access token expired",
}

c.String()       // Bearer realm="example", error="invalid_token", error_description="The access token expired"
c.SetHeader(w)   // sets only the WWW-Authenticate header — you write the status/body
c.Respond(w)     // sets the header and writes the status (here, 401); no body
```

Use `Respond` for the common bodyless challenge; use `SetHeader` when the
response also carries a body (for example a JSON error document), so the
challenge composes with your own status and body.

The three error codes carry their canonical HTTP status (§3.1):

| Code                                 | Status | Meaning                                  |
| ------------------------------------ | ------ | ---------------------------------------- |
| `bearer.ErrorInvalidRequest` (400)   | 400    | malformed request / more than one method |
| `bearer.ErrorInvalidToken` (401)     | 401    | token expired, revoked, or invalid       |
| `bearer.ErrorInsufficientScope` (403)| 403    | token lacks the required scope           |

`bearer.StatusFor(code)` returns the status for a code; an empty or unknown code
(the bare-challenge case) returns 401.

### Extension parameters

`Challenge.Extra` carries auth-params beyond the ones RFC 6750 names — for
example the RFC 9728 `resource_metadata` parameter — rendered after the named
fields in sorted key order:

```go
c := bearer.Challenge{
	Error: bearer.ErrorInvalidToken,
	Extra: map[string]string{"resource_metadata": "https://rs.example.com/.well-known/oauth-protected-resource"},
}
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
