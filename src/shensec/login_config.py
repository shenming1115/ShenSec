"""Portable automatic login recipes, containing environment references only."""

import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from .targets import normalize_target


def env_fields(values: dict[str, str]) -> dict[str, str]:
    for key, value in values.items():
        if not key or len(key) > 100 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("Login fields map request field names to environment variable names.")
    return values


class LoginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    encoding: Literal["json", "form"] = "json"
    fields_env: dict[str, str] = Field(default_factory=dict, max_length=30)
    success_status: int = Field(default=200, ge=200, le=399)
    token_pointer: str | None = "/access_token"
    refresh_pointer: str | None = "/refresh_token"
    expires_pointer: str | None = "/expires_in"
    refresh_url: str | None = None
    refresh_encoding: Literal["json", "form"] = "form"
    refresh_field: str | None = "refresh_token"
    refresh_fields_env: dict[str, str] = Field(default_factory=dict, max_length=30)
    refresh_skew: float = Field(default=30, ge=0, le=300, allow_inf_nan=False)
    max_renewals: int = Field(default=3, ge=0, le=20)
    csrf_url: str | None = None
    csrf_field: str = Field(default="csrf_token", min_length=1, max_length=100)
    csrf_header: str | None = None
    csrf_pointer: str | None = None

    @field_validator("url", "refresh_url", "csrf_url")
    @classmethod
    def normalize_url(cls, value, info):
        if not value and info.field_name == "url":
            raise ValueError("Login URL is required.")
        return normalize_target(value) if value else None

    @field_validator("token_pointer", "refresh_pointer", "expires_pointer", "refresh_field", mode="before")
    @classmethod
    def nullable_string(cls, value):
        # TOML has no null: an explicit empty string disables a default pointer/field.
        return None if value == "" else value

    @field_validator("fields_env", "refresh_fields_env")
    @classmethod
    def validate_fields(cls, values):
        return env_fields(values)

    @field_validator("token_pointer", "refresh_pointer", "expires_pointer", "csrf_pointer")
    @classmethod
    def validate_pointer(cls, value):
        if value is not None and (not value.startswith('/') or len(value) > 300 or re.search(r"~(?![01])", value)):
            raise ValueError("Use a JSON pointer such as /data/access_token.")
        return value

    @field_validator("csrf_header")
    @classmethod
    def validate_header(cls, value):
        if value and (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", value) or value.lower() in {"host", "cookie", "authorization", "content-length", "transfer-encoding", "connection"}):
            raise ValueError("Unsupported CSRF header.")
        return value

    @model_validator(mode="after")
    def no_duplicate_fields(self):
        if self.csrf_url and self.csrf_field in self.fields_env and not self.csrf_header:
            raise ValueError("The CSRF field cannot also contain a login credential.")
        if self.refresh_field and self.refresh_field in self.refresh_fields_env:
            raise ValueError("The refresh token field is supplied by the session manager.")
        return self
