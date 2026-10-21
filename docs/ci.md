# CI security regression gate

Start the application under test and wait for its health check before running ShenSec. Keep the reviewed JSON baseline and target list in your repository. Use stable target URLs between runs.

For authenticated endpoints, use `--config shensec.toml` instead of `--targets` and provide the environment references through the CI secret store, for example `env: { APP_TOKEN: "${{ secrets.STAGING_API_TOKEN }}" }` on the audit step. Use a project-specific authentication verification URL/marker. The desktop SQLite workspace is not needed in stateless CI. See [authentication configuration](authentication.md).

```yaml
- name: Install ShenSec from this checkout
  run: uv sync --locked

# Start your application here and wait for readiness.

- name: Audit security regressions
  run: >-
    uv run shensec audit
    --targets targets.txt
    --baseline security-baseline.json
    --only-new
    --fail-on HIGH
    --format json
    --output security-current.json

- name: Render the recorded audit as HTML
  if: always()
  run: >-
    uv run python -c
    "from pathlib import Path; from shensec import load_baseline, generate_report;
    Path('security-current.html').write_text(generate_report(load_baseline('security-current.json'), 'html'), encoding='utf-8')"

- name: Retain audit reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: security-audit
    path: |
      security-current.json
      security-current.html
```

The audit step exits 1 when the severity policy fails and 2 for incomplete coverage or input/execution/output errors. Reports are generated before severity/coverage exits, so the `always()` artifact step can retain them. If input validation failed before a report existed, the render step also fails with a missing-file error; the original audit error remains the primary diagnostic.

When creating the initial baseline, a HIGH finding can cause exit 1 while still writing valid JSON. Review and accept that report deliberately. Replace a baseline only after reviewing the complete report, target scope, and intended changes; do not automatically overwrite it on every CI run.

## Optional GitHub SARIF upload

The `report` command converts recorded JSON offline, avoiding a second scan of explicit write requests. The anchor file must contain each target URL literally. Upload complete audits only; keep incomplete reports as build artifacts. Source anchors identify the configured endpoint declaration, rather than an inferred vulnerable application source line.

```yaml
permissions:
  contents: read
  security-events: write
  actions: read

# In your job steps, after application readiness:
steps:
  - name: Audit once and record the exit code
    id: audit
    shell: bash
    run: |
      set +e
      uv run shensec audit --config shensec.toml --format json --output security-current.json
      code=$?
      echo "code=$code" >> "$GITHUB_OUTPUT"
      exit "$code"

  - name: Convert completed audit to SARIF
    if: always() && (steps.audit.outputs.code == '0' || steps.audit.outputs.code == '1')
    run: uv run shensec report security-current.json --format sarif --sarif-source shensec.toml --output security.sarif

  - name: Upload completed SARIF
    if: always() && (steps.audit.outputs.code == '0' || steps.audit.outputs.code == '1')
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: security.sarif
      category: shensec-web-configuration
```

This is a steps excerpt for an existing workflow with checkout, dependency installation, application startup and the report artifact step. Supply authentication through the CI secret store. The original audit still fails the job on policy violations or incomplete coverage.
