from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
TEST_ROOT = Path(tempfile.mkdtemp(prefix="blue-team-regression-")).resolve()
TEST_DB_PATH = TEST_ROOT / "app.db"


def configure_test_environment() -> None:
    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))

    os.environ["APP_ENV"] = "test"
    os.environ["BOOTSTRAP_MODE"] = "auto"
    os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"
    os.environ["DATABASE_ECHO"] = "false"
    os.environ["DATABASE_POOL_PRE_PING"] = "true"
    os.environ["SEED_SAMPLE_DATA"] = "true"
    os.environ["TASK_WORKER_EMBEDDED"] = "false"
    os.environ["AI_PROVIDER"] = "disabled"
    os.environ["AI_BASE_URL"] = "https://api.openai.com/v1"
    os.environ["AI_API_KEY"] = ""
    os.environ["AI_MODEL"] = ""
    os.environ["JWT_SECRET"] = "blue-team-regression-secret"
    os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "admin_123"
    os.environ["BOOTSTRAP_ANALYST_PASSWORD"] = "analyst123"
    os.environ["APP_LOG_LEVEL"] = "WARNING"
