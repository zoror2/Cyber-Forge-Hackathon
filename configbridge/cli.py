"""Command-line entry point for validating and running one connection."""

import argparse
import json
from pathlib import Path

import httpx

from .config import load_config
from .runner import run_config
from .store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(prog="configbridge")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "run"):
        cmd = sub.add_parser(command)
        cmd.add_argument("config")
        if command == "run":
            cmd.add_argument("--db", default="data/configbridge.sqlite3")
            cmd.add_argument("--fixture", help="read fixture JSON instead of making an HTTP request")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "validate":
            print(f"Valid config: {config.id} ({config.name})")
            return 0
        client = None
        if args.fixture:
            fixture_body = Path(args.fixture).read_bytes()
            def respond(request):
                return httpx.Response(200, content=fixture_body, request=request,
                                      headers={"content-type": "application/json"})
            client = httpx.Client(transport=httpx.MockTransport(respond))
        try:
            result = run_config(config, Store(args.db), client)
        finally:
            if client:
                client.close()
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        parser.exit(1, f"ConfigBridge error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

