from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import TEST_ROOT, configure_test_environment

configure_test_environment()

from app.main import app  # noqa: E402
from app.services.task_worker import stop_task_worker  # noqa: E402


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
    stop_task_worker()


@pytest.fixture(scope="session")
def admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin_123"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()["data"]
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_root() -> Iterator[None]:
    yield
    shutil.rmtree(TEST_ROOT, ignore_errors=True)
