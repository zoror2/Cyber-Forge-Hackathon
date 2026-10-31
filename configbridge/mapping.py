"""Extract fields from provider JSON and validate common event records."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any

from pydantic import ValidationError

from .schemas import ConnectionConfig, EventRecord


def get_path(value: Any, path: str) -> Any:
    if not path:
        return value
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise KeyError(path)
    return value


def get_items(payload: Any, path: str) -> list[Any]:
    items = get_path(payload, path)
    if not isinstance(items, list):
        raise ValueError(f"response.items_path '{path}' must point to an array")
    return items


def _transform(value: Any, spec) -> Any:
    if spec.transform == "string":
        return str(value)
    if spec.transform == "integer":
        return int(value)
    if spec.transform == "lookup":
        return spec.lookup.get(str(value), value)
    if spec.transform == "datetime":
        if spec.format:
            parsed = datetime.strptime(str(value), spec.format)
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            if not spec.timezone:
                raise ValueError("naive datetime requires a configured timezone")
            parsed = parsed.replace(tzinfo=ZoneInfo(spec.timezone))
        return parsed.astimezone(timezone.utc)
    return value


def map_record(item: Any, config: ConnectionConfig, fetched_at: datetime) -> EventRecord:
    values = {}
    for name, spec in config.destination.mapping.items():
        try:
            value = get_path(item, spec.path) if spec.path is not None else spec.constant
        except KeyError:
            value = None
        if value is None:
            if spec.required:
                raise ValueError(f"{name}: required field is missing")
            value = spec.default
        elif spec.transform:
            try:
                value = _transform(value, spec)
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError(f"{name}: cannot apply {spec.transform} transform") from exc
        values[name] = value
    values["source"] = config.id
    values["fetched_at"] = fetched_at
    if any(spec.precision == "date" and name == "timestamp" for name, spec in config.destination.mapping.items()):
        values["timestamp_precision"] = "date"
    try:
        return EventRecord.model_validate(values)
    except ValidationError as exc:
        if any(error["type"] == "value_error" and "id: required field is missing" in error["msg"]
               for error in exc.errors()):
            raise ValueError("id: required field is missing") from exc
        first = exc.errors()[0]
        field = ".".join(str(p) for p in first["loc"])
        raise ValueError(f"{field}: {first['msg']}") from exc

