"""Typed configuration and normalized record definitions."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequestConfig(StrictModel):
    method: Literal["GET"]
    url: str
    params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=20, gt=0, le=120)


class AuthConfig(StrictModel):
    type: Literal["none"] = "none"


class ResponseConfig(StrictModel):
    items_path: str = ""


class PaginationConfig(StrictModel):
    type: Literal["none"] = "none"


class ScheduleConfig(StrictModel):
    enabled: bool = False
    interval_seconds: int = Field(default=900, ge=1)


class FieldMapping(StrictModel):
    path: str | None = None
    constant: Any = None
    required: bool = False
    default: Any = None
    transform: Literal["string", "integer", "datetime", "lookup"] | None = None
    format: str | None = None
    timezone: str | None = None
    precision: Literal["date"] | None = None
    lookup: dict[str, Any] | None = None

    @model_validator(mode="after")
    def one_source(self):
        has_path = self.path is not None
        has_constant = "constant" in self.model_fields_set
        if has_path == has_constant:
            raise ValueError("provide exactly one of path or constant")
        if self.transform == "lookup" and self.lookup is None:
            raise ValueError("lookup transform requires lookup table")
        return self


class DestinationConfig(StrictModel):
    entity: Literal["event"]
    mapping: dict[str, FieldMapping]


class LimitsConfig(StrictModel):
    max_response_bytes: int = Field(default=10_485_760, gt=0)


class RetryConfig(StrictModel):
    max_attempts: int = Field(default=1, ge=1, le=1)
    base_delay_seconds: float = 0
    max_backoff_seconds: float = 0


class ConnectionConfig(StrictModel):
    version: Literal[1]
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    name: str
    enabled: bool = True
    request: RequestConfig
    auth: AuthConfig = Field(default_factory=AuthConfig)
    response: ResponseConfig
    pagination: PaginationConfig = Field(default_factory=PaginationConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    destination: DestinationConfig
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)

    @model_validator(mode="after")
    def mapping_fields_match_entity(self):
        allowed = {"id", "type", "severity", "timestamp", "description"}
        unexpected = set(self.destination.mapping) - allowed
        if unexpected:
            raise ValueError(f"unsupported Event mapping fields: {', '.join(sorted(unexpected))}")
        missing = allowed - set(self.destination.mapping)
        if missing:
            raise ValueError(f"missing Event mappings: {', '.join(sorted(missing))}")
        return self


class EventRecord(StrictModel):
    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"]
    timestamp: datetime
    description: str
    source: str = Field(min_length=1)
    fetched_at: datetime
    timestamp_precision: str | None = None

    @model_validator(mode="before")
    @classmethod
    def require_id_with_clear_message(cls, value):
        if isinstance(value, dict) and (value.get("id") is None or value.get("id") == ""):
            raise ValueError("id: required field is missing")
        return value


Record = EventRecord

