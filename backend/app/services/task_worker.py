from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta
from time import monotonic
from typing import Any

from sqlalchemy import func

from ..core.config import settings
from ..db.session import SessionLocal
from ..models import AttackTask, TaskRuntimeLog, User
from .ai_endpoints import task_ai_endpoint_snapshot
from .audit import append_audit_log
from .event_status import EVENT_STATUS_INTERCEPTED, EVENT_STATUS_SUSPICIOUS
from .model_provider import ProviderConfigurationError, ProviderExecutionError
from .policy_enforcer import append_task_authorization_snapshot, authorize_task_preflight, serialize_authorization_decision
from .task_runner import TaskExecutionInterrupted, execute_attack_task_pipeline, record_task_outcome
from .time_utils import format_beijing, utc_now

logger = logging.getLogger("app.worker")

_worker_lock = threading.Lock()
_worker_stop_event = threading.Event()
_worker_threads: list[threading.Thread] = []
_worker_active_tasks: dict[str, int] = {}
_last_maintenance_at = 0.0
_task_runtime_log_limit = 200
_RUNNING_TASK_INTERRUPT_STATUS = {"pause_requested", "cancel_requested"}
_RUNNING_TASK_INTERRUPT_TARGET = {
    "pause_requested": "paused_ready",
    "cancel_requested": "cancelled",
}


def _preflight_deny_blocks_task(task: AttackTask) -> bool:
    ai_endpoint = task_ai_endpoint_snapshot(task) or {}
    if not ai_endpoint:
        return True
    protection_enabled = bool(ai_endpoint.get("protection_enabled", True))
    protection_mode = str(ai_endpoint.get("protection_mode") or "").strip().lower()
    if not protection_enabled or protection_mode in {"observe", "off"}:
        return False
    return True


def append_task_runtime_log(
    task_id: int,
    *,
    level: str,
    stage: str,
    message: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "offset": 0,
        "time": format_beijing(utc_now()) or "",
        "level": level,
        "stage": stage,
        "message": message,
        "metadata": dict(metadata or {}),
    }

    db = SessionLocal()
    try:
        current_max = db.query(func.max(TaskRuntimeLog.log_offset)).filter(TaskRuntimeLog.task_id == task_id).scalar() or 0
        entry["offset"] = int(current_max) + 1
        log_item = TaskRuntimeLog(
            task_id=task_id,
            log_offset=entry["offset"],
            level=level,
            stage=stage,
            message=message,
        )
        log_item.set_meta(entry["metadata"])
        db.add(log_item)
        db.flush()

        total = db.query(TaskRuntimeLog).filter(TaskRuntimeLog.task_id == task_id).count()
        if total > _task_runtime_log_limit:
            overflow = total - _task_runtime_log_limit
            stale_ids = [
                item.id
                for item in db.query(TaskRuntimeLog.id)
                .filter(TaskRuntimeLog.task_id == task_id)
                .order_by(TaskRuntimeLog.log_offset.asc(), TaskRuntimeLog.id.asc())
                .limit(overflow)
                .all()
            ]
            if stale_ids:
                db.query(TaskRuntimeLog).filter(TaskRuntimeLog.id.in_(stale_ids)).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("task runtime log append failed | task_id=%s stage=%s", task_id, stage)
    finally:
        db.close()

    return dict(entry)


def task_runtime_log_snapshot(task_id: int, *, after: int = 0, limit: int = 100) -> dict[str, Any]:
    normalized_after = max(after, 0)
    normalized_limit = max(1, min(limit, 500))

    db = SessionLocal()
    try:
        rows = (
            db.query(TaskRuntimeLog)
            .filter(TaskRuntimeLog.task_id == task_id)
            .filter(TaskRuntimeLog.log_offset > normalized_after)
            .order_by(TaskRuntimeLog.log_offset.asc(), TaskRuntimeLog.id.asc())
            .limit(normalized_limit + 1)
            .all()
        )
        current_max = db.query(func.max(TaskRuntimeLog.log_offset)).filter(TaskRuntimeLog.task_id == task_id).scalar() or 0
        task = db.get(AttackTask, task_id)
    finally:
        db.close()

    with _worker_lock:
        is_active = task_id in _worker_active_tasks.values()

    selected_rows = rows[:normalized_limit]
    selected = [
        {
            "offset": item.log_offset,
            "time": format_beijing(item.created_at) or "",
            "level": item.level,
            "stage": item.stage,
            "message": item.message,
            "metadata": item.meta,
        }
        for item in selected_rows
    ]

    return {
        "task_id": task_id,
        "items": selected,
        "count": len(selected),
        "next_offset": int(current_max),
        "has_more": len(rows) > len(selected_rows),
        "active": is_active,
        "queued": bool(task is not None and task.status == "queued"),
    }


def start_task_worker() -> None:
    with _worker_lock:
        alive = [thread for thread in _worker_threads if thread.is_alive()]
        if alive:
            logger.debug("worker start skipped | status=already_running threads=%s", len(alive))
            return

        _worker_stop_event.clear()
        _worker_threads.clear()
        _worker_active_tasks.clear()

        concurrency = max(1, settings.task_worker_concurrency)
        for index in range(concurrency):
            thread = threading.Thread(
                target=_worker_loop,
                args=(index + 1,),
                name=f"attack-task-worker-{index + 1}",
                daemon=True,
            )
            thread.start()
            _worker_threads.append(thread)

    logger.info(
        "worker started | threads=%s poll_interval=%.2fs stale_seconds=%s max_attempts=%s",
        len(_worker_threads),
        settings.task_worker_poll_interval,
        settings.task_worker_stale_seconds,
        settings.task_worker_max_attempts,
    )


def stop_task_worker() -> None:
    with _worker_lock:
        threads = [thread for thread in _worker_threads if thread.is_alive()]
        if not threads:
            logger.debug("worker stop skipped | status=not_running")
            _worker_threads.clear()
            _worker_active_tasks.clear()
            return
        _worker_stop_event.set()

    for thread in threads:
        thread.join(timeout=5)

    with _worker_lock:
        _worker_threads.clear()
        _worker_active_tasks.clear()

    logger.info("worker stopped | threads=%s", len(threads))


def run_worker_forever() -> None:
    start_task_worker()
    try:
        while not _worker_stop_event.wait(1):
            with _worker_lock:
                if not any(thread.is_alive() for thread in _worker_threads):
                    break
    except KeyboardInterrupt:
        logger.info("worker interrupted by keyboard")
    finally:
        stop_task_worker()


def enqueue_attack_task(task_id: int) -> bool:
    start_task_worker()
    db = SessionLocal()
    try:
        task = db.get(AttackTask, task_id)
        if task is None:
            logger.warning("task enqueue skipped | task_id=%s reason=task_not_found", task_id)
            return False
        if task.status != "queued":
            logger.info("task enqueue skipped | task_id=%s reason=status_not_queued status=%s", task_id, task.status)
            return False
    finally:
        db.close()

    append_task_runtime_log(
        task_id,
        level="info",
        stage="queue",
        message="Task is ready for worker pickup.",
    )
    logger.info("task queued | task_id=%s", task_id)
    return True


def release_task_queue_slot(task_id: int) -> bool:
    logger.info("task queue release noop | task_id=%s reason=db_polling_worker", task_id)
    return False


def task_worker_snapshot() -> dict[str, Any]:
    db = SessionLocal()
    try:
        queued_tasks = db.query(AttackTask).filter(AttackTask.status == "queued").count()
        scheduled_tasks = db.query(AttackTask).filter(AttackTask.status == "scheduled").count()
        running_tasks = db.query(AttackTask).filter(AttackTask.status == "running").count()
        paused_tasks = db.query(AttackTask).filter(AttackTask.status.in_(("paused_ready", "paused_queued", "paused_scheduled"))).count()
        dead_letter_tasks = db.query(AttackTask).filter(AttackTask.status == "dead_letter").count()
    finally:
        db.close()

    with _worker_lock:
        alive_threads = [thread for thread in _worker_threads if thread.is_alive()]
        active_task_ids = list(_worker_active_tasks.values())

    if alive_threads:
        status = "running"
    elif settings.task_worker_embedded:
        status = "stopped"
    else:
        status = "external"

    return {
        "status": status,
        "worker_mode": "embedded" if settings.task_worker_embedded else "external",
        "worker_threads": len(alive_threads),
        "active_task_ids": active_task_ids,
        "queued_tasks": queued_tasks,
        "scheduled_tasks": scheduled_tasks,
        "running_tasks": running_tasks,
        "paused_tasks": paused_tasks,
        "dead_letter_tasks": dead_letter_tasks,
    }


def _worker_loop(worker_index: int) -> None:
    worker_name = f"worker-{worker_index}"
    logger.info("worker loop started | worker=%s", worker_name)

    while not _worker_stop_event.is_set():
        try:
            _perform_worker_maintenance()
            task_id = _claim_next_task(worker_name)
            if task_id is None:
                _worker_stop_event.wait(settings.task_worker_poll_interval)
                continue

            with _worker_lock:
                _worker_active_tasks[worker_name] = task_id
            try:
                _run_task(task_id, worker_name=worker_name)
            finally:
                with _worker_lock:
                    _worker_active_tasks.pop(worker_name, None)
        except Exception:
            logger.exception("worker loop iteration failed | worker=%s", worker_name)
            _worker_stop_event.wait(settings.task_worker_poll_interval)

    logger.info("worker loop stopped | worker=%s", worker_name)


def _perform_worker_maintenance() -> None:
    global _last_maintenance_at

    now = monotonic()
    if now - _last_maintenance_at < max(settings.task_worker_poll_interval, 1):
        return

    with _worker_lock:
        if now - _last_maintenance_at < max(settings.task_worker_poll_interval, 1):
            return
        _last_maintenance_at = now

    _enqueue_due_scheduled_tasks()
    _recover_stale_running_tasks()


def _enqueue_due_scheduled_tasks() -> None:
    db = SessionLocal()
    now = utc_now()
    try:
        due_tasks = (
            db.query(AttackTask)
            .filter(AttackTask.status == "scheduled")
            .filter(AttackTask.scheduled_at.isnot(None))
            .filter(AttackTask.scheduled_at <= now)
            .order_by(AttackTask.scheduled_at.asc(), AttackTask.id.asc())
            .limit(settings.task_worker_recovery_limit)
            .all()
        )
        due_ids: list[int] = []
        for item in due_tasks:
            item.status = "queued"
            item.scheduled_at = None
            item.last_heartbeat_at = now
            due_ids.append(item.id)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("worker schedule release failed")
        return
    finally:
        db.close()

    for task_id in due_ids:
        append_task_runtime_log(
            task_id,
            level="info",
            stage="schedule",
            message="Scheduled task reached execution time and is ready for pickup.",
        )
    if due_ids:
        logger.info("worker scheduled release | count=%s task_ids=%s", len(due_ids), due_ids)


def _recover_stale_running_tasks() -> None:
    stale_before = utc_now() - timedelta(seconds=max(settings.task_worker_stale_seconds, 30))
    db = SessionLocal()
    try:
        stale_tasks = (
            db.query(AttackTask)
            .filter(AttackTask.status == "running")
            .filter(AttackTask.execution_mode == "worker")
            .filter(AttackTask.latest_report_id.is_(None))
            .filter(
                (AttackTask.last_heartbeat_at.is_(None)) | (AttackTask.last_heartbeat_at < stale_before)
            )
            .order_by(AttackTask.updated_at.asc(), AttackTask.id.asc())
            .limit(settings.task_worker_recovery_limit)
            .all()
        )
        recovered_ids: list[int] = []
        for item in stale_tasks:
            item.status = "queued"
            item.started_at = None
            item.finished_at = None
            item.last_heartbeat_at = utc_now()
            item.result_summary = "Task was recovered after stale worker detection."
            item.raw_response = json.dumps({"status": "recovered", "reason": "stale_worker"}, ensure_ascii=False)
            recovered_ids.append(item.id)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("worker stale recovery failed")
        return
    finally:
        db.close()

    for task_id in recovered_ids:
        append_task_runtime_log(
            task_id,
            level="warn",
            stage="recovery",
            message="Task was recovered after stale worker detection and returned to the queue.",
        )
    if recovered_ids:
        logger.warning("worker recovered stale tasks | count=%s task_ids=%s", len(recovered_ids), recovered_ids)


def _claim_next_task(worker_name: str) -> int | None:
    db = SessionLocal()
    try:
        candidate_ids = [
            item.id
            for item in (
                db.query(AttackTask.id)
                .filter(AttackTask.status == "queued")
                .order_by(AttackTask.created_at.asc(), AttackTask.id.asc())
                .limit(settings.task_worker_recovery_limit)
                .all()
            )
        ]

        for task_id in candidate_ids:
            updated = (
                db.query(AttackTask)
                .filter(AttackTask.id == task_id)
                .filter(AttackTask.status == "queued")
                .update(
                    {
                        AttackTask.status: "running",
                        AttackTask.started_at: utc_now(),
                        AttackTask.last_heartbeat_at: utc_now(),
                        AttackTask.scheduled_at: None,
                    },
                    synchronize_session=False,
                )
            )
            if updated:
                db.commit()
                logger.info("task claimed | task_id=%s worker=%s", task_id, worker_name)
                append_task_runtime_log(
                    task_id,
                    level="info",
                    stage="queue",
                    message="Task was claimed by a worker.",
                    metadata={"worker": worker_name},
                )
                return task_id

        db.rollback()
        return None
    except Exception:
        db.rollback()
        logger.exception("task claim failed | worker=%s", worker_name)
        return None
    finally:
        db.close()


def _run_task(task_id: int, *, worker_name: str) -> None:
    db = SessionLocal()
    try:
        task = db.get(AttackTask, task_id)
        if task is None:
            logger.warning("task execution skipped | task_id=%s reason=task_not_found", task_id)
            return
        if task.status != "running":
            logger.info(
                "task execution skipped | task_id=%s reason=status_not_running status=%s",
                task_id,
                task.status,
            )
            return

        logger.info(
            "task execution start | task_id=%s worker=%s task_name=%s attack_type=%s target=%s",
            task.id,
            worker_name,
            task.task_name,
            task.attack_type,
            task.target_agent,
        )
        append_task_runtime_log(
            task.id,
            level="info",
            stage="execution",
            message="Task execution started.",
            metadata={
                "worker": worker_name,
                "task_name": task.task_name,
                "attack_type": task.attack_type,
                "target_agent": task.target_agent,
            },
        )

        preflight_action = {
            "action_type": "task_execution",
            "runtime_name": task.runtime_name,
            "runtime_task_ref": task.runtime_task_ref,
            "metadata": {"source": "worker", "worker": worker_name},
        }
        preflight = authorize_task_preflight(db, task, preflight_action)
        append_task_authorization_snapshot(task, action=preflight_action, decision=preflight)
        append_task_runtime_log(
            task.id,
            level="info",
            stage="preflight",
            message=f"Preflight authorization decision: {preflight.decision}.",
            metadata={"summary": preflight.summary, "worker": worker_name},
        )

        if preflight.decision == "deny" and _preflight_deny_blocks_task(task):
            now = format_beijing(utc_now()) or ""
            serialized_preflight = serialize_authorization_decision(preflight)
            raw_response = json.dumps({"preflight_authorization": serialized_preflight}, ensure_ascii=False)
            task, event, report = record_task_outcome(
                db,
                task,
                summary=preflight.summary,
                raw_response=raw_response,
                task_status="done",
                event_type="preflight_block",
                event_level="high",
                event_status=EVENT_STATUS_INTERCEPTED,
                event_source="policy-enforcer/preflight",
                event_detail=preflight.detail,
                hit_rules=preflight.matched_rules,
                raw_input=json.dumps({"action": preflight_action, "context": preflight.context}, ensure_ascii=False),
                result=preflight.summary,
                operation_logs=[
                    {"operator": worker_name, "action": "task_started", "time": now},
                    {"operator": "policy_enforcer", "action": "preflight_denied", "time": now},
                ],
                report_type="preflight_block",
                created_by=task.created_by or 1,
                create_report=True,
            )
            user = _audit_user_for_task(db, task)
            if user is not None:
                append_audit_log(
                    db,
                    user,
                    "attack-tasks",
                    "worker-preflight-denied",
                    f"worker denied task {task.task_name} during preflight",
                )
            db.commit()
            logger.warning(
                "task execution denied by preflight | task_id=%s event_id=%s report_id=%s",
                task.id,
                event.id if event is not None else "-",
                report.id if report is not None else "-",
            )
            append_task_runtime_log(
                task.id,
                level="warn",
                stage="preflight",
                message="Task execution was denied during preflight authorization.",
                metadata={
                    "event_id": event.id if event is not None else None,
                    "report_id": report.id if report is not None else None,
                    "worker": worker_name,
                },
            )
            return
        if preflight.decision == "deny":
            append_task_runtime_log(
                task.id,
                level="warn",
                stage="preflight",
                message="Preflight returned deny, but endpoint protection is observe/off, so the task continues for attack testing.",
                metadata={"summary": preflight.summary, "worker": worker_name},
            )

        signal = _running_task_control_signal(task.id)
        if signal is not None:
            _mark_interrupted_task(db, task, signal)
            db.commit()
            append_task_runtime_log(
                task.id,
                level="warn",
                stage="control",
                message=f"Task execution stopped because {signal} was requested.",
                metadata={"worker": worker_name},
            )
            return

        serialized_preflight = serialize_authorization_decision(preflight)
        control_check = _build_control_check(task.id)
        append_task_runtime_log(
            task.id,
            level="info",
            stage="pipeline",
            message="Task entered the execution pipeline.",
            metadata={"worker": worker_name},
        )
        task, event, report = execute_attack_task_pipeline(
            db,
            task,
            authorization_decision=serialized_preflight,
            control_check=control_check,
        )
        _clear_task_retry_state(task)
        user = _audit_user_for_task(db, task)
        if user is not None:
            append_audit_log(db, user, "attack-tasks", "worker-complete", f"worker completed task {task.task_name}")
        db.commit()
        logger.info(
            "task execution complete | task_id=%s event_id=%s report_id=%s result=%s",
            task.id,
            event.id,
            report.id if report is not None else "-",
            task.result_summary,
        )
        append_task_runtime_log(
            task.id,
            level="info",
            stage="pipeline",
            message="Task execution pipeline completed.",
            metadata={
                "worker": worker_name,
                "event_id": event.id,
                "report_id": report.id if report is not None else None,
                "result_summary": task.result_summary,
            },
        )
    except TaskExecutionInterrupted as exc:
        db.rollback()
        interrupted_task = db.get(AttackTask, task_id)
        if interrupted_task is not None:
            _mark_interrupted_task(db, interrupted_task, exc.signal)
            user = _audit_user_for_task(db, interrupted_task)
            if user is not None:
                append_audit_log(
                    db,
                    user,
                    "attack-tasks",
                    "worker-interrupted",
                    f"worker interrupted task {interrupted_task.task_name}: {exc.signal}",
                )
            db.commit()
            logger.warning(
                "task execution interrupted | task_id=%s signal=%s",
                interrupted_task.id,
                exc.signal,
            )
            append_task_runtime_log(
                interrupted_task.id,
                level="warn",
                stage="control",
                message=f"Task execution interrupted by {exc.signal}.",
                metadata={"worker": worker_name},
            )
        else:
            logger.warning("task execution interrupted | task_id=%s signal=%s task_name=-", task_id, exc.signal)
    except Exception as exc:
        db.rollback()
        failed_task = db.get(AttackTask, task_id)
        if failed_task is not None:
            retry_state = (
                _schedule_retry_or_dead_letter(db, failed_task, str(exc))
                if _is_retryable_worker_failure(exc)
                else _mark_task_failed_without_retry(db, failed_task, exc)
            )
            user = _audit_user_for_task(db, failed_task)
            if user is not None:
                append_audit_log(
                    db,
                    user,
                    "attack-tasks",
                    "worker-failed",
                    f"worker failed task {failed_task.task_name}: {exc}",
                )
            db.commit()
            if retry_state == "failed":
                logger.warning(
                    "task execution failed without retry | task_id=%s task_name=%s error=%s",
                    failed_task.id,
                    failed_task.task_name,
                    exc,
                )
            else:
                logger.exception(
                    "task execution failed | task_id=%s task_name=%s retry_state=%s",
                    failed_task.id,
                    failed_task.task_name,
                    retry_state,
                )
            if retry_state == "retry_scheduled":
                append_task_runtime_log(
                    failed_task.id,
                    level="warn",
                    stage="pipeline",
                    message=f"Task execution failed and was scheduled for retry: {exc}",
                    metadata={"worker": worker_name},
                )
            elif retry_state == "dead_letter":
                append_task_runtime_log(
                    failed_task.id,
                    level="error",
                    stage="pipeline",
                    message=f"Task execution failed and moved to dead letter: {exc}",
                    metadata={"worker": worker_name},
                )
            else:
                append_task_runtime_log(
                    failed_task.id,
                    level="error",
                    stage="pipeline",
                    message=f"Task execution failed without retry: {exc}",
                    metadata={"worker": worker_name},
                )
        else:
            logger.exception("task execution failed | task_id=%s task_name=-", task_id)
            append_task_runtime_log(
                task_id,
                level="error",
                stage="pipeline",
                message=f"Task execution failed before the task record could be reloaded: {exc}",
                metadata={"worker": worker_name},
            )
    finally:
        db.close()


def _build_control_check(task_id: int):
    next_heartbeat_at = 0.0

    def check() -> str | None:
        nonlocal next_heartbeat_at

        now = monotonic()
        if now >= next_heartbeat_at:
            _touch_task_heartbeat(task_id)
            next_heartbeat_at = now + max(settings.task_worker_heartbeat_interval, 1)
        return _running_task_control_signal(task_id)

    return check


def _touch_task_heartbeat(task_id: int) -> None:
    db = SessionLocal()
    try:
        task = db.get(AttackTask, task_id)
        if task is None or task.status not in {"running", "pause_requested", "cancel_requested"}:
            return
        task.last_heartbeat_at = utc_now()
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("task heartbeat touch failed | task_id=%s", task_id)
    finally:
        db.close()


def _running_task_control_signal(task_id: int) -> str | None:
    db = SessionLocal()
    try:
        task = db.get(AttackTask, task_id)
        if task is None:
            return None
        if task.status in _RUNNING_TASK_INTERRUPT_STATUS:
            return task.status
        return None
    finally:
        db.close()


def _mark_interrupted_task(db, task: AttackTask, signal: str) -> None:
    now = utc_now()
    if signal == "pause_requested":
        task.status = _RUNNING_TASK_INTERRUPT_TARGET[signal]
        task.result_summary = "Task was paused during execution."
        task.raw_response = json.dumps({"status": "paused", "reason": "pause_requested"}, ensure_ascii=False)
        task.started_at = None
        task.finished_at = None
    else:
        task.status = _RUNNING_TASK_INTERRUPT_TARGET.get(signal, "cancelled")
        task.result_summary = "Task was cancelled during execution."
        task.raw_response = json.dumps({"status": "cancelled", "reason": signal}, ensure_ascii=False)
        task.finished_at = now
    task.scheduled_at = None
    task.last_heartbeat_at = now
    task.latest_event_id = None
    task.latest_report_id = None
    db.flush()


def _is_retryable_worker_failure(exc: Exception) -> bool:
    if isinstance(exc, ProviderConfigurationError):
        return False
    if isinstance(exc, ProviderExecutionError):
        return bool(exc.retryable)
    return True


def _failure_payload_from_exception(exc: Exception, *, attempt: int | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "failed",
        "reason": str(exc),
        "retryable": _is_retryable_worker_failure(exc),
    }
    if attempt is not None:
        payload["attempt"] = attempt
    if isinstance(exc, ProviderConfigurationError):
        payload["failure_type"] = "provider_configuration"
    if isinstance(exc, ProviderExecutionError):
        payload["failure_type"] = exc.failure_type
        if exc.status_code is not None:
            payload["status_code"] = exc.status_code
    return payload


def _worker_failure_hit_rules(exc: Exception) -> list[str]:
    hit_rules = ["worker-failed"]
    if isinstance(exc, ProviderConfigurationError):
        hit_rules.append("provider-configuration")
    elif isinstance(exc, ProviderExecutionError):
        hit_rules.append("provider-retryable" if exc.retryable else "provider-non-retryable")
        if exc.failure_type:
            hit_rules.append(exc.failure_type)
    return hit_rules


def _mark_task_failed_without_retry(db, task: AttackTask, exc: Exception) -> str:
    params = dict(task.params)
    retry_state = dict(params.get("worker_retry") or {})
    attempts = int(retry_state.get("attempts") or 0) + 1
    retry_state.update(
        {
            "attempts": attempts,
            "max_attempts": max(1, int(retry_state.get("max_attempts") or settings.task_worker_max_attempts)),
            "last_error": str(exc),
            "last_failed_at": format_beijing(utc_now()) or "",
            "retryable": False,
            "terminal_state": "failed",
        }
    )
    params["worker_retry"] = retry_state
    task.set_params(params)

    now = format_beijing(utc_now()) or ""
    record_task_outcome(
        db,
        task,
        summary=f"Task execution failed without retry: {exc}",
        raw_response=json.dumps(_failure_payload_from_exception(exc, attempt=attempts), ensure_ascii=False),
        task_status="failed",
        event_type="worker_failed",
        event_level="medium",
        event_status=EVENT_STATUS_SUSPICIOUS,
        event_source="task-worker/non-retryable",
        event_detail=str(exc),
        hit_rules=_worker_failure_hit_rules(exc),
        raw_input=json.dumps(task.params, ensure_ascii=False),
        result=str(exc),
        operation_logs=[
            {"operator": "worker", "action": "task_failed", "time": now},
            {"operator": "worker", "action": "non_retryable_failure", "time": now},
        ],
        report_type="worker_failed",
        created_by=task.created_by or 1,
        create_report=True,
    )
    return "failed"


def _schedule_retry_or_dead_letter(db, task: AttackTask, reason: str) -> str:
    params = dict(task.params)
    retry_state = dict(params.get("worker_retry") or {})
    attempts = int(retry_state.get("attempts") or 0) + 1
    max_attempts = max(1, int(retry_state.get("max_attempts") or settings.task_worker_max_attempts))
    retry_state["attempts"] = attempts
    retry_state["max_attempts"] = max_attempts
    retry_state["last_error"] = reason
    retry_state["last_failed_at"] = format_beijing(utc_now()) or ""

    now = utc_now()
    if attempts < max_attempts:
        delay_seconds = max(1, settings.task_worker_retry_delay_seconds) * (2 ** (attempts - 1))
        retry_at = now + timedelta(seconds=delay_seconds)
        retry_state["next_retry_at"] = format_beijing(retry_at) or ""
        params["worker_retry"] = retry_state
        task.set_params(params)
        task.status = "scheduled"
        task.scheduled_at = retry_at
        task.started_at = None
        task.finished_at = None
        task.last_heartbeat_at = now
        task.result_summary = f"Task execution failed and was scheduled for retry {attempts}/{max_attempts}."
        task.raw_response = json.dumps(
            {
                "status": "retry_scheduled",
                "reason": reason,
                "attempt": attempts,
                "max_attempts": max_attempts,
                "next_retry_at": retry_state["next_retry_at"],
            },
            ensure_ascii=False,
        )
        task.latest_event_id = None
        task.latest_report_id = None
        db.flush()
        return "retry_scheduled"

    retry_state["dead_letter"] = True
    retry_state["dead_letter_at"] = format_beijing(now) or ""
    params["worker_retry"] = retry_state
    task.set_params(params)
    task, event, report = record_task_outcome(
        db,
        task,
        summary=f"Task moved to dead letter after {attempts} failed attempts.",
        raw_response=json.dumps(
            {
                "status": "dead_letter",
                "reason": reason,
                "attempt": attempts,
                "max_attempts": max_attempts,
            },
            ensure_ascii=False,
        ),
        task_status="dead_letter",
        event_type="worker_dead_letter",
        event_level="medium",
        event_status=EVENT_STATUS_SUSPICIOUS,
        event_source="task-worker/retry",
        event_detail=reason,
        hit_rules=["worker-retry", "dead-letter"],
        raw_input=json.dumps(task.params, ensure_ascii=False),
        result=reason,
        operation_logs=[
            {"operator": "worker", "action": "task_failed", "time": format_beijing(now) or ""},
            {"operator": "worker", "action": "dead_lettered", "time": format_beijing(now) or ""},
        ],
        report_type="worker_dead_letter",
        created_by=task.created_by or 1,
        create_report=True,
    )
    return "dead_letter"


def _clear_task_retry_state(task: AttackTask) -> None:
    params = dict(task.params)
    if "worker_retry" not in params:
        return
    params.pop("worker_retry", None)
    task.set_params(params)


def _audit_user_for_task(db, task: AttackTask) -> User | None:
    if task.created_by:
        user = db.get(User, task.created_by)
        if user is not None:
            return user
    return db.query(User).order_by(User.id.asc()).first()
