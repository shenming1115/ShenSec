"""Target parsing shared by the CLI, scanner, and baseline comparison."""

import httpx


def normalize_target(value: str) -> str:
    value = value.strip()
    try:
        url = httpx.URL(value)
        _ = url.port
    except (httpx.InvalidURL, ValueError) as exc:
        raise ValueError("Invalid target URL; use an absolute http:// or https:// URL.") from exc
    if url.scheme not in {"http", "https"} or not url.host:
        raise ValueError("Target must be an absolute http:// or https:// URL.")
    if url.userinfo:
        raise ValueError("Credentials in target URLs are not supported.")
    # raw_path preserves encoded slashes/query values while normalizing an empty path.
    return str(url.copy_with(raw_path=url.raw_path, fragment=None))


def parse_targets(lines: list[str]) -> list[str]:
    """One URL per line; ignore blanks/comments and keep first-seen order."""
    targets = []
    for number, line in enumerate(lines, 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            target = normalize_target(value)
        except ValueError as exc:
            raise ValueError(f"Target line {number}: {exc}") from exc
        if target not in targets:
            targets.append(target)
    if not targets:
        raise ValueError("Provide at least one target URL or a non-empty targets file.")
    return targets
