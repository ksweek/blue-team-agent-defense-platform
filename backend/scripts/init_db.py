import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings
from app.db.session import ping_database
from app.services.bootstrap import init_database


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize or validate the Blue Team database.")
    parser.add_argument(
        "--mode",
        choices=("setup", "schema", "validate"),
        default="setup",
        help=(
            "setup=create schema + baseline defaults and optionally sample data, "
            "schema=create schema + baseline defaults only, "
            "validate=connectivity check only"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        print(f"Environment: {settings.app_env}")
        print(f"Bootstrap mode: {args.mode}")
        print(f"Database backend: {settings.database_backend}")
        print(f"Database url: {settings.database_summary}")
        init_database(mode=args.mode)
        ping_database()
        if args.mode == "validate":
            print("Database connectivity validated.")
        else:
            print("Database bootstrap completed and connectivity validated.")
        return 0
    except Exception as exc:
        print(f"Database initialization failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
