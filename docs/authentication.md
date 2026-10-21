# Authenticated projects

ShenSec supports existing Bearer/Cookie/API-key credentials and automatic JSON/form login with CSRF, verification and bounded renewal. This page covers existing-credential profiles; see [automatic login, refresh and role comparisons](identity-workflows.md) for the managed session workflow. Browser-driven interactive login and challenges are not automated.

## Portable TOML example

```toml
schema_version = 1
name = "Staging API"
targets = ["https://staging.example/api/me", "https://staging.example/api/settings"]
workers = 4
timeout = 10.0
threshold = "HIGH"
check_options = true
allow_cross_origin = false

[auth]
profile = "qa-admin"
required = true
bearer_env = "APP_TOKEN"
# cookie_env = "APP_COOKIE"
origins = ["https://staging.example"]
verify_url = "https://staging.example/api/me"
verify_status = 200
verify_header = "X-Authenticated"
verify_value = "true"

[auth.header_env]
"X-API-Key" = "APP_API_KEY"

[auth.headers]
Accept = "application/json"
```

Use only the mechanisms your application needs. An environment reference is resolved before network requests. A missing variable fails with its name, without displaying its value. Header names and single-line ASCII values are validated. Literal Authorization, Cookie, key/token/secret headers are rejected; use `header_env` or the dedicated credential references. Fixed `headers` and verification marker values are configuration data, so do not put secrets there.

`verify_header` and `verify_value` are optional and must be supplied together. Choose a marker your application actually returns; the example header is illustrative. The verification request does not follow redirects. A login redirect, unexpected status, or wrong success marker stops the audit. Without such a marker, HTTP 200 alone cannot distinguish every login page from an authenticated response. `authentication: applied` records credential attachment, rather than claiming server-side acceptance.

## Desktop sessions

In the Credentials tab, enter environment references or paste a token/Cookie into the masked session fields. A `Bearer ` prefix and `Cookie:` prefix are accepted. Paste once and scan repeatedly: credentials are reused in memory for the same project/profile/scope. They are cleared when switching projects, pressing **Clear session credentials**, or closing the app. Changing the credential scope/source invalidates the cached values.

The project records `required = true` after using session credentials, so reopening it cannot silently perform an anonymous audit. Provide the credentials again, or explicitly choose the intended authentication configuration. Closing and restarting never restores credential values from history.

## Origin boundaries and session isolation

- The default credential scope is the **first target's exact origin**. Add other intended origins explicitly. Ports and schemes are part of an origin; suffix lookalikes do not match.
- Authenticated targets outside that scope fail before sending a request. Authenticated redirects cannot leave it, even when generic cross-origin following is enabled. Credentials are rebuilt for each request instead of copying redirect request headers.
- Credentials require HTTPS, except loopback fixtures. `allow_http = true` is an explicit development setting for another HTTP origin. TLS certificate validation remains enabled.
- Each target has separate origin-scoped Cookie jars. A worker's reused HTTP client cannot carry one target's cookies into the next. Same-origin redirects can update a session Cookie within the scan. Environment/pasted values remain the starting credentials on the next scan; refresh them when the application invalidates them.
- Runtime credential values, known encoded variants, and response Cookie values are removed from supported finding/evidence/error fields before reports and history are written. This is literal redaction, not a general data-loss-prevention engine. Avoid secrets in target paths/query strings or unrelated response content; arbitrary transformations cannot all be recognized.

Use separate `profile` names for roles such as anonymous, user, and admin. Credential rotation within the same profile and configuration does not change issue identities. Context also captures credential sources, fixed headers, origin scope, and verification settings, so disabling verification cannot silently count as the same coverage. Changing authentication context prevents the baseline gate from interpreting role/configuration differences as fixes; establish a reviewed baseline for the intended profile.

## Local storage

SQLite stores project configuration snapshots, audit results, history metadata, and accepted baseline IDs. It does not store the runtime credential object or session input values. The database is local, without cloud synchronization or application-level encryption; protect the workspace like other local project data. `.env` files are not loaded automatically. Use the process environment, a secret manager, or desktop session fields.
