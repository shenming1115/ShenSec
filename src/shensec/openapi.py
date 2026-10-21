"""Offline OpenAPI 3.0/3.1 JSON import with explicit deployment and bindings."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import quote, urlencode

from .project import ProjectConfig
from .requests import RequestSpec
from .targets import normalize_target
from .auth import AuthConfig


@dataclass
class ImportResult:
    config: ProjectConfig
    skipped: list[str]


def import_openapi(path: str | Path, server: str, bindings: dict[str, str] | None = None) -> ImportResult:
    path = Path(path)
    if path.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("OpenAPI files are limited to 5 MiB.")
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, RecursionError):
        raise ValueError("OpenAPI import requires a valid JSON document.") from None
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith(("3.0.", "3.1.")):
        raise ValueError("Supported OpenAPI versions: 3.0 and 3.1 (JSON).")
    base = normalize_target(server).rstrip('/')
    if '?' in base or '{' in base:
        raise ValueError("Use an explicit deployment URL without query parameters or server variables.")
    bindings = bindings or {}
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object.")
    plans, skipped, seen = [], [], set()
    require_auth = False

    def resolve(value):
        visited = set()
        while isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/") or ref in visited or len(visited) >= 20:
                raise ValueError("Unresolved, external, or cyclic reference")
            visited.add(ref)
            value = doc
            for token in ref[2:].split('/'):
                if not isinstance(value, dict):
                    raise ValueError("Unresolved reference")
                value = value.get(token.replace('~1', '/').replace('~0', '~'))
        if not isinstance(value, dict):
            raise ValueError("Expected an OpenAPI object")
        return value

    for route, raw_item in paths.items():
        if not isinstance(route, str) or not route.startswith('/') or route.startswith('//') or '?' in route or '#' in route:
            skipped.append(f"{route}: unsupported path")
            continue
        try:
            item = resolve(raw_item)
        except ValueError as exc:
            skipped.append(f"{route}: {exc}")
            continue
        for method in ("get", "head", "post", "put", "patch", "delete", "options", "trace"):
            if method not in item:
                continue
            label = f"{method.upper()} {route}"
            if method not in {"get", "head"}:
                skipped.append(f"{label}: review and configure this method explicitly")
                continue
            try:
                operation = resolve(item[method])
                security = operation.get("security", doc.get("security", []))
                params = {}
                for raw in list(item.get("parameters", [])) + list(operation.get("parameters", [])):
                    param = resolve(raw)
                    params[(param.get("in"), param.get("name"))] = param
                expanded, query = route, []
                for (location, name), param in params.items():
                    if not isinstance(name, str):
                        raise ValueError("Parameter has no valid name")
                    required = location == "path" or param.get("required", False)
                    if location not in {"path", "query"}:
                        if required:
                            raise ValueError(f"Required {location} parameter {name}: configure a request manually")
                        continue
                    value = bindings.get(f"{location}.{name}", bindings.get(name))
                    if value is None and required:
                        value = resolve(param.get("schema", {})).get("default")
                    if value is None:
                        if required:
                            raise ValueError(f"Missing binding: {location}.{name}")
                        continue
                    if not isinstance(value, (str, int, float, bool)):
                        raise ValueError(f"Complex parameter {name}: configure a URL manually")
                    value = str(value).lower() if isinstance(value, bool) else str(value)
                    if location == "path":
                        if not value or value in {".", ".."}:
                            raise ValueError(f"Invalid path binding: {name}")
                        expanded = expanded.replace('{' + name + '}', quote(value, safe=""))
                    else:
                        query.append((name, value))
                if re.search(r"[{}]", expanded):
                    raise ValueError("Path template has unresolved parameters")
                url = normalize_target(base + expanded + ('?' + urlencode(query) if query else ''))
                if url in seen:
                    skipped.append(f"{label}: duplicate URL; GET takes precedence over HEAD")
                    continue
                if len(plans) >= 1000:
                    raise ValueError("Project limit of 1000 targets reached")
                plans.append(RequestSpec(url=url, method=method.upper()))
                # An empty security requirement is an anonymous alternative.
                if isinstance(security, list) and security and all(bool(item) for item in security):
                    require_auth = True
                seen.add(url)
            except (ValueError, TypeError, AttributeError) as exc:
                skipped.append(f"{label}: {exc}")
    if not plans:
        raise ValueError("No ready GET/HEAD endpoints. " + "; ".join(skipped[:8]))
    info = doc.get("info") or {}
    title = info.get("title", "Imported API") if isinstance(info, dict) else "Imported API"
    config = ProjectConfig(name=str(title)[:100] or "Imported API", targets=[p.url for p in plans], requests=plans, auth=AuthConfig(required=require_auth))
    return ImportResult(config, skipped)
