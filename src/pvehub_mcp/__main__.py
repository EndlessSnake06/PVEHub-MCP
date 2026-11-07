"""CLI entrypoint."""

from __future__ import annotations

import argparse
import logging
import sys

import anyio
import uvicorn

from .config import load_settings
from .policy import Policy
from .server import PVEHub, build_http_app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pvehub-mcp", description="PVE + PBS MCP server")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--transport", choices=["http", "stdio"], help="override PVEHUB_TRANSPORT")
    parser.add_argument("--host", help="override PVEHUB_HOST")
    parser.add_argument("--port", type=int, help="override PVEHUB_PORT")
    parser.add_argument("--config", help="YAML config file (default: /config/config.yaml)")
    parser.add_argument("--env-file", help="optional .env file for local development")
    parser.add_argument("--log-level", help="override PVEHUB_LOG_LEVEL")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        from . import __version__

        print(__version__)
        return 0
    if args.config:
        import os

        os.environ["PVEHUB_CONFIG_FILE"] = args.config
    try:
        settings = load_settings(args.env_file)
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.transport:
        settings.transport = args.transport
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    if args.log_level:
        settings.log_level = args.log_level
    try:
        policy = Policy.load(settings.policy_file)
    except Exception as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    hub = PVEHub(settings, policy)
    mcp = hub.build()

    if settings.transport == "http":
        app = build_http_app(hub)
        uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level.lower())
        return 0

    async def run_stdio() -> None:
        await hub.initialize()
        try:
            await mcp.run_stdio_async()
        finally:
            await hub.close()

    anyio.run(run_stdio)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
