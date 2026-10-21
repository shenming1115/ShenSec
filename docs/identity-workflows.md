# Automatic login, renewal and role comparisons

Version 0.5 shares these features across the desktop, CLI, Python API, history, baselines and reports. Try the complete workflow without real accounts:

```bash
uv run --locked --extra gui shensec demo --identities --gui
```

The loopback fixture signs in as admin, record owner and another user, with an anonymous control. It expires tokens, rotates refresh tokens, observes three unexpected access paths, fixes server authorization, expires sessions again, and rechecks eight expectations. The final run has three resolved access findings, no unverified findings and four successful session renewals. These are controlled fixture observations.

## Desktop setup

1. **Targets**: add the exact endpoints you intend to inspect.
2. **Credentials**: choose a primary profile and configure an identity verification URL. Use a response header marker or JSON assertion, such as `/account/id="admin-1"`. Automatic login requires this positive proof; a status-200 login page is insufficient.
3. **Auto login**: enable sign-in, enter the login URL, select JSON/form, and map request fields to environment variable names. For example: `username=APP_USERNAME`, `password=APP_PASSWORD`.
4. Supply the environment values before launch, or enter the optional **Session account / Session secret** values in the login editor. These inputs override the selected variable names in memory only. **Test sign-in** (`Ctrl+L`) checks login/verification without scanning endpoints or writing a history run. A successful session is reused by later audits.
5. **Roles & access**: add named identities. Use **Copy primary** as a starting point. Each authenticated role needs a verification URL and a header/JSON identity assertion. For ownership checks, assert the actual account ID rather than only a broad role category. Add an anonymous role as a control if appropriate.
6. Add explicit access expectations: endpoint, GET/HEAD method, expected allow/deny for every role, and at least one success response assertion. Run the audit and inspect **Permission matrix** and **Sessions**.

Role dialogs also accept temporary account/secret values for automatic login, or masked Bearer/Cookie values. When needed, the desktop generates a role-specific environment reference to save, while retaining the actual value only in memory. **Copy primary** can reuse already entered temporary credentials. Clear session credentials, switch projects, or close the app to discard runtime session references. Values are not written to the SQLite workspace, TOML/JSON config exports or reports. The workspace still contains target URLs, role names, configured identity assertions and observations; those are project data.

Changing an entered account/secret forces a new login. Changing login configuration or credential scope invalidates the corresponding cached session. Static Bearer/Cookie sources and automatic login cannot be combined in one profile; remove the static source and clear pasted credentials when switching modes.

![Actual permission matrix from the controlled pre-fix fixture](permissions-workbench.png)

[Login editor](login-workbench.png) · [Session activity](sessions-workbench.png)

## A JSON login recipe

This is a primary-profile excerpt; root `targets` and other project settings go before the tables. A complete four-role example is in [examples/identities.toml](../examples/identities.toml). Edit its URLs, account IDs and JSON pointers to match your application.

```toml
[auth]
profile = "primary-admin"
required = true
origins = ["https://app.example"]
verify_url = "https://app.example/me"
verify_json_pointer = "/account/id"
verify_json_value = "admin-1"

[auth.login]
url = "https://app.example/login"
encoding = "json"
token_pointer = "/access_token"
refresh_pointer = "/refresh_token"
expires_pointer = "/expires_in"
refresh_url = "https://app.example/refresh"
refresh_encoding = "form"
refresh_field = "refresh_token"
max_renewals = 3

[auth.login.fields_env]
username = "APP_ADMIN_USERNAME"
password = "APP_ADMIN_PASSWORD"
```

Pointers use JSON Pointer syntax, including `~1` for `/` and `~0` for `~`. Nested token fields such as `/data/access_token` are supported. The login response must match `success_status` (default 200). Access tokens must be nonempty single-line ASCII strings. `expires_in`, when present, must be a positive finite number of seconds. JWT contents are not trusted as an expiry source; use the configured response lifetime or reactive recovery.

Refresh posts the captured refresh token under `refresh_field`. Form refresh requests add `grant_type=refresh_token`; JSON refresh requests send the token field and explicitly configured extra fields. Additional client credentials can use `refresh_fields_env`. Refresh success requires HTTP 200. A returned refresh token replaces the previous one; omission retains the existing token. HTTP 400/401/403 from refresh falls back to one new login within the renewal budget. Other transport, response or verification failures stop recovery instead of repeatedly posting passwords or rotating tokens blindly.

Automatic login fields, refresh credentials, access/refresh tokens, CSRF tokens and managed cookies stay in memory. Reports never include authentication response bodies. Password/token literal reflection redaction is applied to scanner evidence; it is not a general filter for arbitrary transformations or unrelated sensitive application data.

## Form login and CSRF

Set `encoding = "form"` for URL-encoded login fields. In JSON configuration set `token_pointer` to `null`; in the desktop choose **Session cookie**. In TOML, `token_pointer = ""` selects cookie mode. Empty strings similarly disable optional default refresh/expiry pointers or the refresh token field, so exports preserve these choices when round-tripped.

Optional `csrf_url` performs a scoped GET before login. The manager extracts exactly one hidden input named `csrf_field`, or reads `csrf_pointer` from a JSON response. It submits that value in the named field, or in `csrf_header` if configured. Cookies from initialization carry into the login request. Ambiguous/missing CSRF values fail clearly.

A form login may return a configured 302/303 success status and session cookies; redirects are not followed. The separate verification URL/assertion establishes actual success. Cookie domain, path, Secure and expiry rules are preserved. For cookie-based refresh endpoints set `refresh_field` to null (empty in the desktop); otherwise renewal can sign in again using the recipe. Browser-executed JavaScript, interactive OAuth authorization/PKCE, CAPTCHA and MFA challenges are not automated by this HTTP recipe engine.

Applications requiring additional Origin/Referer headers can configure public `[auth.headers]` or environment header references. Login/refresh endpoints and CSRF field selection are explicit; the tool does not infer arbitrary browser workflows.

## Renewal behavior

Within an audit, all workers for one identity share a single renewal operation. Near expiry, a worker renews before sending the next request. The default advance window is 30 seconds, capped at 20% of a short token lifetime to avoid immediate-refresh loops. A rejected safe request can trigger one recovery and one replay; concurrent stale 401 responses use the generation already refreshed by another worker.

GET, HEAD and OPTIONS are eligible for recovery/replay. A configured expected 401 is not automatically replayed. POST/PUT/PATCH/DELETE can benefit from proactive renewal, but are never automatically replayed after a 401. Role comparisons use only GET/HEAD, even when the primary audit contains explicit write plans.

The default renewal budget is three attempts per identity per audit, counting refresh/login recovery attempts. A new audit resets the budget and activity counters while retaining a usable in-memory session. A cached automatic session is verified before reuse. A denial response in a role probe is verified again for authenticated roles so that an expired identity cannot silently count as a correct denial.

Login, CSRF, refresh, verification and probes share the project's per-origin rate budget. Pacing and lock waits check cancellation. In-flight HTTP operations remain bounded by the configured timeout. Authentication and JSON assertion responses are streamed with a 256 KiB limit and request identity encoding; compressed responses that ignore this request are rejected. Bodies are used only for the configured assertions, then discarded.

## Interpret the matrix and baseline

Every expectation names all configured roles (2–8), an exact URL already in project targets, and a success header and/or JSON scalar assertion. Success requires both the configured allowed status and all supplied assertions. A 200 HTML login page, missing JSON field, mismatched assertion, redirect or unexpected status is **unverified**, not evidence of a bypass. Allowed statuses are 2xx; denial statuses default to 401/403, with explicit 404 supported.

- Expected deny + matching success response: **HIGH**, `SEC-ACCESS-UNEXPECTED-ALLOW`.
- Expected allow + verified denial: **MEDIUM**, `SEC-ACCESS-UNEXPECTED-DENY`.
- Invalid identity, network failure or ambiguous response: coverage error; gate exit 2.

The severity threshold still controls the gate. For example, use `--fail-on MEDIUM` if an expected-access denial must fail CI as well. A matrix violation remains visible even below the configured threshold. A reviewed baseline intentionally accepts existing findings under `--only-new`.

Role definitions, login source references and expectation/assertion settings form comparison context. Changing/removing them requires baseline review; skipped or unverified permission checks never become claimed fixes. Password and token values are excluded from this context to permit normal rotation. Identity assertions must therefore describe the intended actual accounts, and payload/account changes that alter the test's meaning should receive a reviewed baseline.

History and JSON/HTML/Markdown reports preserve the matrix and session activity. SARIF includes access findings plus safe session/count metadata. Neither matrix observations nor header checks prove that every possible resource or authorization path is secure; only the explicit expectations were tested.

## CLI and Python

```bash
uv run shensec auth test --config identities.toml
uv run shensec auth test --config identities.toml --role owner
uv run shensec audit --config identities.toml --format json --output current.json
uv run shensec report current.json --format html --output current.html
```

`auth test` prints safe activity metadata, without scanning configured target/permission endpoints. Static profiles need a verification URL. Stateless CLI runs sign in on each invocation; desktop sessions remain in memory across runs. Python callers can retain a `RuntimeAuth` and role-runtime dictionary across `audit_project` calls for the same behavior.

The protocol building blocks follow [HTTPX client/cookie behavior](https://www.python-httpx.org/advanced/clients/), [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) and the configured subset of [refresh-token exchange](https://www.rfc-editor.org/rfc/rfc6749#section-6). This is not a full OAuth authorization client.
