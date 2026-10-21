"""Portable project configuration with no saved credential values."""

import json
from pathlib import Path
import tomllib

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .auth import AuthConfig
from .models import Severity
from .targets import parse_targets
from .requests import RequestSpec
from .network import NetworkPolicy
from .policy import RuleException
from .access import RoleConfig, PermissionCase


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1, le=1)
    name: str = Field(default="My project", min_length=1, max_length=100)
    targets: list[str] = Field(min_length=1, max_length=1000)
    workers: int = Field(default=4, ge=1, le=16)
    timeout: float = Field(default=10, ge=0.1, le=120, allow_inf_nan=False)
    check_options: bool = True
    check_cors: bool = False
    allow_cross_origin: bool = False
    threshold: Severity = Severity.HIGH
    auth: AuthConfig = Field(default_factory=AuthConfig)
    requests: list[RequestSpec] = Field(default_factory=list, max_length=1000)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    exceptions: list[RuleException] = Field(default_factory=list, max_length=1000)
    roles: list[RoleConfig] = Field(default_factory=list, max_length=8)
    permissions: list[PermissionCase] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_requests(self):
        urls = [request.url for request in self.requests]
        if len(urls) != len(set(urls)):
            raise ValueError("Configure one request plan per URL; use separate projects for different methods on the same URL.")
        if set(urls) - set(self.targets):
            raise ValueError("Every request URL must also appear in targets.")
        names = [role.name for role in self.roles]
        if len(names) != len(set(names)):
            raise ValueError("Role names must be unique.")
        if len({case.id for case in self.permissions}) != len(self.permissions):
            raise ValueError("Permission expectation IDs must be unique.")
        if self.permissions and len(names) < 2:
            raise ValueError("Permission comparisons require at least two roles.")
        for case in self.permissions:
            if case.url not in self.targets or set(case.expectations) != set(names):
                raise ValueError("Every permission URL must be a target and expectations must include exactly the configured roles.")
        return self

    @field_validator("targets")
    @classmethod
    def normalize_targets(cls, values):
        return parse_targets(values)


def validation_message(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, item['loc']))}: {item['msg']}" for item in exc.errors(include_input=False))


def load_project(path: str | Path) -> ProjectConfig:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
        data = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
        return ProjectConfig.model_validate(data)
    except ValidationError as exc:
        raise ValueError(validation_message(exc)) from None
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read project configuration: {type(exc).__name__}.") from None


def project_toml(config: ProjectConfig) -> str:
    lines = ["# ShenSec project. Credentials are environment references only."]
    def emit(data, prefix=""):
        for key, value in data.items():
            if value is None and prefix.endswith('"login"') and key in {"token_pointer", "refresh_pointer", "expires_pointer", "refresh_field"}:
                value = ""
            if value is not None and not isinstance(value, dict) and not (isinstance(value, list) and value and isinstance(value[0], dict)):
                lines.append(f"{json.dumps(key)} = {json.dumps(value, ensure_ascii=False)}")
        for key, value in data.items():
            path = f"{prefix}.{json.dumps(key)}" if prefix else json.dumps(key)
            if isinstance(value, dict) and value:
                lines.append(f"\n[{path}]")
                emit(value, path)
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for entry in value:
                    lines.append(f"\n[[{path}]]")
                    emit(entry, path)
    emit(config.model_dump(mode="json"))
    return "\n".join(lines) + "\n"
