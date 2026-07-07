from __future__ import annotations

import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import configure_test_environment

configure_test_environment()

from fastapi.testclient import TestClient

from app.api.routes import auth as auth_routes
from app.main import app
from app.services.task_worker import stop_task_worker
from backend.tests.run_backend_tests_cn import print_table


def test_concurrent_email_registration_flows(client: TestClient, monkeypatch):
    rows = run_concurrent_registration(client, monkeypatch, worker_count=4)

    assert len(rows) == 4
    assert all(row["结果"] == "通过" for row in rows), rows
    assert len({row["用户名"] for row in rows}) == 4


def run_concurrent_registration(client: TestClient, monkeypatch: Any, *, worker_count: int) -> list[dict[str, str]]:
    captured_codes: dict[tuple[str, str], str] = {}
    captured_codes_lock = Lock()

    def fake_send_auth_code(db, *, recipient: str, code: str, purpose: str):
        with captured_codes_lock:
            captured_codes[(purpose, recipient)] = code
        return {"recipient": recipient, "subject": "test"}

    monkeypatch.setattr(auth_routes, "send_auth_verification_email", fake_send_auth_code)

    unique = uuid.uuid4().hex[:10]

    def register_one(index: int) -> dict[str, str]:
        started_at = time.perf_counter()
        username = f"concurrent_{unique}_{index}"
        email = f"concurrent-{unique}-{index}@example.com"
        password = f"register_{unique}_{index}"
        statuses: list[str] = []
        result = "通过"
        detail = "注册和登录均成功"

        try:
            send_register_code = client.post(
                "/api/auth/send-code",
                json={"purpose": "register", "username": username, "email": email},
            )
            statuses.append(f"发码:{send_register_code.status_code}")
            send_register_code.raise_for_status()
            with captured_codes_lock:
                register_code = captured_codes[("register", email)]

            register = client.post(
                "/api/auth/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password,
                    "code": register_code,
                    "real_name": f"Concurrent User {index}",
                },
            )
            statuses.append(f"注册:{register.status_code}")
            register.raise_for_status()
            if register.json()["data"]["user"]["username"] != username:
                raise AssertionError("注册返回的用户名不一致")

            login = client.post("/api/auth/login", json={"username": username, "password": password})
            statuses.append(f"登录:{login.status_code}")
            login.raise_for_status()
        except Exception as exc:
            result = "失败"
            detail = str(exc)

        return {
            "序号": str(index + 1),
            "用户名": username,
            "邮箱": email,
            "接口状态": "，".join(statuses) or "-",
            "耗时(秒)": f"{time.perf_counter() - started_at:.2f}",
            "结果": result,
            "详情": detail,
        }

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(register_one, index) for index in range(worker_count)]
        return sorted((future.result() for future in as_completed(futures)), key=lambda row: int(row["序号"]))


class _MonkeyPatch:
    def setattr(self, target, name: str, value: Any | None = None) -> None:
        if value is None:
            old_value = target
            dotted = str(name)
            module_name, attribute_name = dotted.rsplit(".", 1)
            module = __import__(module_name, fromlist=[attribute_name])
            setattr(module, attribute_name, old_value)
            return
        setattr(target, name, value)


def main() -> int:
    worker_count = 8
    with TestClient(app) as client:
        rows = run_concurrent_registration(client, _MonkeyPatch(), worker_count=worker_count)
    stop_task_worker()

    passed = sum(1 for row in rows if row["结果"] == "通过")
    failed = len(rows) - passed
    print_table(
        "并发测试汇总",
        [
            {
                "脚本": "backend/tests/test_concurrent_auth_flows.py",
                "测试内容": "并发执行 8 组认证邮件注册登录流程，检查验证码隔离和账号创建结果",
                "并发数": str(worker_count),
                "通过": str(passed),
                "失败": str(failed),
                "结果": "通过" if failed == 0 else "失败",
            }
        ],
    )
    print_table("并发明细", rows)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
