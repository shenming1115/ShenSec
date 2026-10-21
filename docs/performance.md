# Reproducible performance checks

Run from the source checkout:

```bash
uv run python examples/benchmark.py --targets 24 --rounds 3 --workers 4
```

The script starts an authenticated HTTP/1.1 loopback fixture, then compares **per-target HTTP client construction** with **per-worker client reuse**. Both use the same checks, timeout, target list, credentials, and bounded-body handling. It verifies identical finding fingerprints and counts TCP connections accepted by the server. No third-party website is contacted.

Sample from Windows / Python 3.13.3, 2026-10-21:

```json
{
  "scope": "authenticated loopback HTTP/1.1, small bounded bodies",
  "targets": 24,
  "workers": 4,
  "rounds": 3,
  "per_target_client_median_ms": 7307.74,
  "per_worker_client_median_ms": 1379.49,
  "speedup": 5.3,
  "per_target_connections": [24, 24, 24],
  "per_worker_connections": [4, 4, 4],
  "findings_identical": true
}
```

This isolates one optimization; it is not a release-to-release or general internet performance guarantee. CPU load, certificate-store initialization, TLS, proxies, target latency, rate limits, response framing, and body size affect results. Real targets that close connections or return large/unknown-length bodies may not reuse TCP connections.

The scanner drains at most 16 KiB of a declared small, uncompressed response without retaining the body. Other response bodies are closed. A thread owns its client and uses target-local Cookie jars, so pooling does not require sharing sessions across targets. At most `workers` tasks are queued/running. Cancellation prevents further scheduling and checks between HTTP operations; an in-flight request can continue until its operation timeout.

The workbench uses a `QAbstractTableModel` and proxy filters rather than allocating a widget for every finding cell. A regression test exercises filtering 5000 findings. SQLite indexes history by project and time and reads metadata separately from full reports. The UI displays the latest 200 runs; records remain in the database.
