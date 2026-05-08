from __future__ import annotations

import argparse

import uvicorn

from app.core.logging import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Blue Team backend development server.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-reload", action="store_true", help="Disable uvicorn auto-reload.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        access_log=False,
        log_config=None,
    )


if __name__ == "__main__":
    main()
