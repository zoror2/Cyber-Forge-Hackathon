"""Safe YAML reading with duplicate-key detection and strict schema validation."""

from pathlib import Path
import yaml
from pydantic import ValidationError

from .schemas import ConnectionConfig

MAX_CONFIG_BYTES = 256_000


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


def _construct_timestamp(loader, node):
    # Keep YAML date scalars as strings so Pydantic reports config values consistently.
    return loader.construct_scalar(node)


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
UniqueKeyLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_timestamp)


def load_config(path: str | Path) -> ConnectionConfig:
    content = Path(path).read_bytes()
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("config exceeds 256 KB limit")
    try:
        raw = yaml.load(content, Loader=UniqueKeyLoader)
        if not isinstance(raw, dict):
            raise ValueError("config root must be a YAML object")
        return ConnectionConfig.model_validate(raw)
    except (yaml.YAMLError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid config: {exc}") from exc

