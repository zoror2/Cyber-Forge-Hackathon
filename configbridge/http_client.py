"""One injectable HTTP fetch for Milestone 1; policy and retries come later."""

import httpx

from .schemas import ConnectionConfig


def fetch_json(config: ConnectionConfig, client: httpx.Client | None = None):
    owns_client = client is None
    client = client or httpx.Client(follow_redirects=False)
    try:
        response = client.get(config.request.url, params=config.request.params,
                              headers=config.request.headers, timeout=config.request.timeout_seconds)
        response.raise_for_status()
        if len(response.content) > config.limits.max_response_bytes:
            raise ValueError("response exceeds configured byte limit")
        try:
            return response.json()
        except ValueError as exc:
            raise ValueError("response is not valid JSON") from exc
    finally:
        if owns_client:
            client.close()

