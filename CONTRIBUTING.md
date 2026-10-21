# Contributing to ShenSec

Good contributions improve repeatability, useful remediation, and everyday developer workflows. Bug reports with a controlled reproduction are especially helpful.

## Set up and verify

```bash
uv sync --locked --extra gui
uv run pytest
uv build
```

Use `QT_QPA_PLATFORM=offscreen` for headless GUI checks. Tests use mock transports or their own loopback servers. Do not add tests that depend on public websites, production credentials, or an external service being available.

For transport changes, verify credential origin boundaries, Cookie isolation, cancellation, and the real localhost fixture. For rule changes, include the relevant positive and negative application contexts and stable rule/location identities. For GUI changes, exercise the actual worker/history/baseline workflow, then regenerate and inspect `docs/workbench.png` with `examples/capture_workbench.py`.

Keep runtime credentials outside configuration/results. Never paste tokens, cookies, real target data, or an unredacted workspace database into an issue, fixture, screenshot, or pull request. Preserve explicit coverage/error status rather than returning a passing gate for missing checks.

## Useful next contributions

- Focused browser-policy parsing with realistic fixtures.
- More SARIF consumer fixtures, OpenAPI parameter coverage and clearer remediation examples.
- Secret-manager integrations and deliberate token refresh workflows.
- Accessibility, keyboard navigation, localization, and packaging improvements.

Explain the user-visible problem, resulting behavior, and relevant validation in pull requests. The benchmark is available for transport changes; report its scope alongside any performance numbers.
