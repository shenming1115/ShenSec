# API projects and CI

The CLI, Python API and desktop share project settings. Version 0.4.0b1 adds request plans, OpenAPI import, active CORS checks, pacing, retries, expiring exceptions and SARIF without new runtime dependencies.

## Import an API

```bash
uv run shensec import-openapi examples/openapi.json --server https://staging.example.com/v1 --param path.user_id=42 --output api-project.toml
```

Review the file, configure authentication, then run `shensec audit --config api-project.toml`. Desktop: **API requests → Import OpenAPI JSON**. Import merges targets and preserves existing overrides; skipped operations and reasons appear below the request table.

Supported: local OpenAPI 3.0/3.1 **JSON** up to 5 MiB, local parameter references, path/operation parameter overrides, scalar path/query bindings and required-query schema defaults. Bindings are URL-encoded; unbound optional parameters are omitted. `--server` explicitly replaces document deployment definitions and must include any API prefix. External references are never fetched. Missing bindings, required header/cookie parameters and unsupported operations are reported as skipped. Security declarations require credentials unless an anonymous alternative exists; configure the intended source before scanning.

Import creates GET/HEAD plans without sending requests. GET wins when both share a URL. Other methods are listed for manual review; explicitly configure supported methods in the request editor or config.

## Request configuration

```toml
name = "Staging API"
targets = ["https://staging.example.com/v1/search"]
workers = 4
check_options = true
check_cors = false
threshold = "HIGH"

[auth]
required = true
bearer_env = "APP_TOKEN"
origins = ["https://staging.example.com"]

[network]
requests_per_second = 5
retries = 2
backoff = 0.5
max_retry_after = 10

[[requests]]
url = "https://staging.example.com/v1/search"
method = "POST"
body_env = "SEARCH_BODY"
content_type = "application/json"
expected_status = [200]

[[exceptions]]
rule_id = "SEC-HDR-001"
target = "https://staging.example.com/v1/*"
reason = "TLS edge migration tracked in SEC-42"
expires = "2026-12-01"
```

Provide `APP_TOKEN` and `SEARCH_BODY` through process environment variables. The body can contain `{"query":"sample"}`. Body values are not saved in configuration/history. JSON is validated before any audit requests; bodies are limited to 1 MiB. Payloads and individual JSON string values are registered for literal reflection redaction. This does not detect all transformations or unrelated sensitive information.

Explicit methods: GET, HEAD, POST, PUT, PATCH, DELETE. URLs without overrides use GET. One plan per normalized URL is supported; use separate projects for different methods/identities on one URL. Plan URLs must exist in `targets`; GET/HEAD bodies are rejected. Explicit write methods can change application state: choose an appropriate test endpoint and payload.

Redirect method semantics apply (POST→GET after 303; POST remains POST after 307). Bodies cannot cross an origin boundary. Empty `expected_status` accepts final 2xx responses; explicit codes can also test intended denial responses. Method, body-variable reference, content type and expected-status changes invalidate comparison context. Body environment **values** are excluded: keep inputs stable or establish a new baseline when changing their meaning.

## Pacing and retries

Desktop **Speed & reliability** edits `[network]`. Defaults: unlimited rate, one retry, 0.5-second exponential backoff, 10-second maximum retry wait. A positive requests-per-second budget is shared by workers for an exact scheme/host/port origin, including authentication preflight, redirects, OPTIONS and CORS probes. Worker limits and connection reuse still apply.

Only GET/HEAD/OPTIONS retry transport errors and HTTP 429/502/503/504. POST/PUT/PATCH/DELETE are sent once. Retry-After seconds/dates are honored up to the maximum wait; long server delays are capped. `retry_count` and `request_count` are recorded. Exhaustion remains a failure. Pacing/backoff waits are cancellable; in-flight blocking requests remain bounded by their operation timeout.

## CORS verification

Enable **Probe CORS** or `check_cors = true`. Two extra GET/HEAD requests send unrelated `.invalid` Origin headers to each eligible configured endpoint. Those names are never contacted. Probes use scoped credentials and isolated cookies, without retaining response bodies. Other request methods are ineligible.

Reflection of both origins is HIGH when both responses enable credentialed browser access, LOW otherwise. Missing `Vary: Origin` is separately reported for varying reflection. Rejected 4xx probe responses indicate rejection. Redirects, transport failures and 5xx leave coverage incomplete. This does not implement browser preflight, cookie policy, response-sensitivity analysis or exploit verification. Disabling a previously finding-producing probe yields unverified observations, never claimed fixes.

## Expiring exceptions

Select a current finding → **Accept selected finding** → reason and date → review **Rule exceptions** → save/rescan. Recorded history stays unchanged. Reasons require eight meaningful characters. Dates use the local calendar and remain active through the expiry day. URL matching is case-sensitive with shell-style globs.

Evidence and raw risk counts remain in all reports. Active exceptions remove matched findings from gate violations; execution errors cannot be waived. Expiry/removal of a previously accepted exception becomes a regression even under `--only-new`. Regression gates otherwise accept existing baseline findings, so review full reports when assessing total risk.

## SARIF and GitHub

```bash
uv run shensec audit --config api-project.toml --format sarif --sarif-source api-project.toml --output security.sarif
```

Without a source anchor, SARIF uses logical HTTP resource locations. GitHub needs physical locations to display alerts. `--sarif-source` must be an existing repository-relative file containing every target URL literally. Alerts point to actual URL declarations, not inferred vulnerable source code. Missing declarations cause an output error; commit the configuration for useful annotations.

Output includes fingerprints, rule metadata, baseline states, accepted exceptions and execution status. Upload complete audits only; retain incomplete results as build artifacts. See [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html), and the [OpenAPI specification](https://spec.openapis.org/oas/v3.1.0) for the formats underlying these integrations.

To produce multiple formats without repeating requests, first save JSON, then use `shensec report current.json --format sarif --sarif-source api-project.toml --output security.sarif` or `shensec report current.json --format html --output security.html`. Conversion is offline and preserves the input report.
