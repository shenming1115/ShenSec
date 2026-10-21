"""Explicit request plans. Payload values remain in environment variables."""

from hashlib import sha256
import json
import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .targets import normalize_target


class RequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    body_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    content_type: str = Field(default="application/json", pattern=r"^[A-Za-z0-9!#$&^_.+/-]+$")
    expected_status: list[int] = Field(default_factory=list, max_length=20)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value):
        return normalize_target(value)

    @field_validator("expected_status")
    @classmethod
    def valid_status(cls, values):
        if any(not 200 <= value <= 599 for value in values):
            raise ValueError("Expected statuses must be HTTP 200–599.")
        return sorted(set(values))

    @model_validator(mode="after")
    def valid_body(self):
        if self.body_env and self.method in {"GET", "HEAD"}:
            raise ValueError("GET/HEAD request plans cannot contain a body.")
        return self

    @property
    def context(self) -> str | None:
        # Keep default GET plans compatible with older baselines.
        if self.method == "GET" and not self.body_env and not self.expected_status:
            return None
        data = self.model_dump(exclude={"url"})
        return sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:24]

    def payload(self) -> bytes | None:
        if not self.body_env:
            return None
        value = os.environ.get(self.body_env)
        if not value:
            raise ValueError(f"Request body variable {self.body_env} is missing or empty.")
        encoded = value.encode("utf-8")
        if len(encoded) > 1024 * 1024:
            raise ValueError("Request bodies are limited to 1 MiB.")
        if self.content_type == "application/json" or self.content_type.endswith("+json"):
            try:
                json.loads(value)
            except ValueError:
                raise ValueError(f"Request body variable {self.body_env} must contain valid JSON.") from None
        return encoded


def payload_secrets(payload: bytes | None) -> set[str]:
    """Redact the complete payload and individual JSON string values if reflected."""
    if payload is None:
        return set()
    text = payload.decode("utf-8")
    secrets = {text}
    def walk(value):
        if isinstance(value, str) and value:
            secrets.add(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    try:
        walk(json.loads(text))
    except ValueError:
        pass
    return secrets
