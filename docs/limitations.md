# Known limitations

These observations describe the current implementation and are tracked separately from structural cleanup. Scanner behavior and the public API were preserved.

- `analyze_response` collects findings but leaves severity counts empty and risk at the model default. Only `scan_target` aggregates the HTTP scan summary.
- CLI JWT findings are appended after scan aggregation. They appear in detailed reports but do not update the summary counts or overall rating.
- The CLI can exit successfully after a failed connection. Consumers should inspect status code `0` and `SEC-SCAN-ERR`.
- CORS checks currently identify only a wildcard allowed origin. They do not test origin reflection, credentials, or preflight enforcement.
- Header and cookie parsing uses simple string rules; findings require contextual review, including HSTS findings on plain HTTP targets.
- JWT inspection does not verify signatures or server behavior. Expiration uses the local clock, and claim checks are heuristic rather than complete validation.
- WAF/CDN identification and advertised HTTP method findings are hints, not proof of protection or exploitability.
- HTML rendering currently does not enable Jinja2 autoescaping. Reports can contain target-controlled text; review generated HTML before opening it in a browser or sharing it. Harden rendering in a dedicated follow-up with regression coverage.

## Documentation assets

- `gui_dashboard.png` shows a successful scan from the current GUI against a controlled localhost target.
- `cli_demo.png` presents selected lines captured from the real CLI output of the same controlled scan.
- Both screenshots contain only loopback addresses and deterministic security findings; no token, credential, personal data, or production target is present.
- The README's test badge records the verified local result (26 passing tests). After the workflow is pushed and a GitHub Actions run is verified, replace it with the workflow's live status badge. The version badge refers to local package metadata, not a published PyPI release.
