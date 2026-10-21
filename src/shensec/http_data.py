"""Small, explicitly requested response assertions; bodies never enter reports."""

import json
from threading import Event
import httpx


def read_bounded(response: httpx.Response, event: Event, limit: int = 262144) -> bytes:
    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
        raise ValueError("Authentication/assertion responses must use identity content encoding.")
    declared = response.headers.get("content-length", "")
    if declared.isdecimal() and (len(declared) > 9 or int(declared) > limit):
        raise ValueError("Authentication/assertion response exceeds 256 KiB.")
    data = bytearray()
    for chunk in response.iter_bytes(chunk_size=4096):
        if event.is_set():
            raise ValueError("Cancelled during response inspection.")
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("Authentication/assertion response exceeds 256 KiB.")
    return bytes(data)


def json_document(data: bytes):
    def invalid_constant(value):
        raise ValueError("Non-finite JSON constant.")
    try:
        return json.loads(data, parse_constant=invalid_constant)
    except (ValueError, RecursionError):
        raise ValueError("Expected a valid JSON response; content was not retained.") from None


def json_pointer(data, pointer: str):
    try:
        for token in pointer[1:].split('/'):
            token = token.replace('~1', '/').replace('~0', '~')
            if isinstance(data, list) and (not token.isdecimal() or len(token) > 1 and token.startswith('0')):
                raise ValueError("Invalid array index.")
            data = data[int(token)] if isinstance(data, list) and token.isdecimal() else data[token]
        return data
    except (KeyError, IndexError, TypeError, ValueError):
        raise ValueError("Configured JSON pointer was absent; content was not retained.") from None
