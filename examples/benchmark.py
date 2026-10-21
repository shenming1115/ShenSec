"""Reproducible loopback benchmark; no third-party service or credentials needed.

Compare per-target HTTP client creation with per-worker client reuse.
This is a local transport microbenchmark, not an internet scan speed claim.
"""

import argparse
import json
from statistics import median
from time import perf_counter

from shensec import AuthConfig, scan_many
from shensec.demo import local_site


def benchmark(target_count=24, rounds=3, workers=4):
    timings = {"per_target": [], "per_worker": []}
    connections = {"per_target": [], "per_worker": []}
    with local_site() as (url, server):
        server.hardened = True
        targets = [f"{url}/api/item/{index}" for index in range(target_count)]
        auth = AuthConfig(bearer_env="SHENSEC_DEMO_TOKEN", origins=[url])
        reference = None
        for _ in range(rounds):
            for label, reuse in (("per_target", False), ("per_worker", True)):
                before = server.connections
                start = perf_counter()
                audit = scan_many(targets, workers=workers, timeout=3, auth=auth, reuse_clients=reuse)
                timings[label].append((perf_counter() - start) * 1000)
                connections[label].append(server.connections - before)
                if audit.failed_targets:
                    raise RuntimeError("Benchmark target did not complete.")
                observations = [sorted(f.fingerprint for f in result.findings) for result in audit.results]
                if reference is None:
                    reference = observations
                assert observations == reference, "Optimization changed audit findings"
    old, new = median(timings["per_target"]), median(timings["per_worker"])
    return {
        "scope": "authenticated loopback HTTP/1.1, small bounded bodies",
        "targets": target_count, "workers": workers, "rounds": rounds,
        "per_target_client_median_ms": round(old, 2), "per_worker_client_median_ms": round(new, 2),
        "speedup": round(old / new, 2),
        "per_target_connections": connections["per_target"], "per_worker_connections": connections["per_worker"],
        "findings_identical": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=int, default=24)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.targets <= 1000 or not 1 <= args.rounds <= 10 or not 1 <= args.workers <= 16:
        parser.error("Use 1..1000 targets, 1..10 rounds, and 1..16 workers")
    print(json.dumps(benchmark(args.targets, args.rounds, args.workers), indent=2))
