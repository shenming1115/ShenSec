# Scope, limitations, and compatibility

## What a result means

ShenSec audits response configuration and inspects local JWTs. It does not crawl, exploit, fuzz, brute force, or prove application security. CORS, HTTP methods, and infrastructure indicators need application context. Missing browser headers are not evidence that XSS or authorization bypass exists.

- Default CORS inspection identifies wildcard Allow-Origin. Optional two-origin GET/HEAD probes observe reflection, credential headers and Vary. Browser preflight, cookie policy and response sensitivity are not verified.
- CSP parsing and cookie rules are bounded heuristics rather than full browser policy implementations. CSP nonce/hash interactions, all browser fallback rules, malformed/duplicate cookie attributes, and every cookie prefix constraint are not exhaustively evaluated.
- Explicit non-HTML content types skip document-only checks. An absent Content-Type is treated as potentially HTML. HSTS is checked only on HTTPS; cleartext final responses get a transport observation.
- Cookie evidence omits the cookie value. Other evidence, target paths, and query strings may still contain application-specific data; select target URLs accordingly.
- JWT signatures, issuer/audience trust, revocation, and actual server acceptance are not verified. Expiration uses the local clock. Key references and sensitive claim names are heuristic observations.
- GET/HEAD and explicitly configured POST/PUT/PATCH/DELETE plans inspect response headers without retaining bodies. Request bodies use environment references, are limited to 1 MiB and can change state. One plan per URL is supported. Small declared uncompressed bodies up to 16 KiB may be drained for connection reuse; other bodies are closed. A response may differ from what a browser sees. Existing credentials and JSON/form automatic login are supported, including CSRF, configured refresh-token exchange and re-login. Login/identity JSON assertions read at most 256 KiB without retaining bodies. Browser scripting, interactive OAuth authorization, CAPTCHA and MFA are not automated. Role probes use only explicit GET/HEAD cases with verified identities and success assertions; they do not enumerate resources or infer a complete authorization policy.
- Same-origin redirects and conventional same-host HTTP→HTTPS upgrades are followed. Other origins require opt-in. Redirect loops are capped at ten. No DNS pinning or network address allowlist is provided; use trusted target lists in your authorized environment.
- Timeouts apply to individual HTTP operations. A multi-hop or multi-target audit can take longer than `--timeout`. Workers limit concurrency. Optional shared per-origin pacing limits admission rate; bounded safe-method retries handle selected transient failures and Retry-After. Pacing/backoff waits are cancellable. Cooperative cancellation stops new work and checks between operations; it cannot instantly interrupt an in-flight blocking request.

## Coverage and gates

`status` distinguishes complete, partial, and failed inspections. Final responses outside configured expected statuses (default: 2xx) and unresolved redirects are execution errors. A failed OPTIONS request makes coverage partial; 405/501 responses are accepted as unsupported OPTIONS. Advertised methods are observations, rather than proof that the methods work or bypass authorization.

Errors and incomplete coverage exit 2, even with `--only-new`. An omitted target or a previously flagged rule that was skipped is never marked resolved. Removed targets require scope review and prevent a passing baseline gate. A fresh successful baseline should be established after deliberate scope or check changes.

Authentication, request-plan and configured role/expectation context are part of coverage. Body environment values are excluded; keep inputs stable or review a new baseline after changing their meaning. See [API workflows](api-workflows.md) for import, exception and SARIF boundaries. Switching from authenticated to anonymous scans, changing a role/profile or changing credential scope cannot silently count as fixes. `authentication: applied` means credentials were attached, rather than proving their acceptance. Use a verification URL and application-specific success marker where appropriate. Session credentials and history boundaries are described in [the authentication guide](authentication.md).

History is stored transactionally in local SQLite. The workbench lists the latest 200 runs per project; data is not automatically deleted. The database is not application-encrypted and should be handled as local project data. Failed/cancelled runs can be reviewed but cannot become accepted baselines. A history-storage failure preserves the completed audit for report export.

Baseline identity uses normalized requested URL, rule ID, and the finding's location (or title when location is absent). Evidence text and severity are excluded; increases in severity are reported as regressions. Redirect cookie locations include their source URL, name, path, and domain. Duplicate observations with the same identity are collapsed in comparison and gate decisions; scan reports retain the full list.

## API and behavior changes since 0.2.1

- Risk and severity totals are computed properties. Read them as before; change findings to change the summary. Assigning `risk_rating` or `severity_counts` directly is no longer supported. Old serialized summary values are ignored and recomputed.
- New `ScanResult` metadata includes kind, status, final URL, redirect chain, checks, warnings, and error. `AuditResult` uses `schema_version: 1` and a list of scan results.
- JSON reports from individual scans can be loaded as baselines. Reports from older versions do not carry coverage metadata, and rule/location changes can cause a one-time comparison difference. Establish a new reviewed baseline for the upgraded scanner.
- Failed scans retain `SEC-SCAN-ERR` for compatibility, but at INFO severity with an explicit error status. Network failure is not a critical vulnerability.
- Plain HTTP now produces `SEC-TRANSPORT-HTTP` rather than a missing-HSTS observation. SameSite=None without Secure is MEDIUM, reflecting browser rejection rather than demonstrated critical compromise.
- CLI JSON stdout is now machine-readable, without progress banners. Errors/incomplete scans exit 2. `audit` defaults to the HIGH policy threshold; `scan` and `jwt` require explicit `--fail-on` to fail on findings.
- Other-origin redirects require explicit opt-in. TLS verification remains enabled.
- HTML output escapes target-controlled content, with no external assets or scripts. Markdown also escapes active markup. Existing custom consumers should handle the new fields and status separately from risk.

## Implementation references

Summaries use Pydantic's [computed fields](https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.computed_field). HTTP resource management follows the HTTPX [client](https://www.python-httpx.org/advanced/clients/) and [streaming response](https://www.python-httpx.org/quickstart/#streaming-responses) APIs. HTML uses Jinja's [explicit autoescape configuration](https://jinja.palletsprojects.com/en/stable/api/#autoescaping).
