from __future__ import annotations

import logging
import smtplib
import threading
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy.orm import Session

from ..core.config import settings
from ..db.session import SessionLocal
from ..models import SecurityEvent, SystemSetting, User
from .audit import append_audit_log
from .system_settings_registry import (
    EMAIL_LEVEL_ORDER,
    EMAIL_TEMPLATE_DEFINITIONS,
    default_system_settings,
    list_email_recipients,
)
from .time_utils import beijing_now, format_beijing, parse_utc_iso, to_beijing, utc_now

logger = logging.getLogger("app.email")

_worker_lock = threading.Lock()
_worker_stop_event = threading.Event()
_worker_thread: threading.Thread | None = None


@dataclass
class EmailNotificationConfig:
    enabled: bool
    recipients: list[str]
    template_key: str
    min_level: str
    digest_minutes: int
    subject_prefix: str
    sender: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_starttls: bool

    def missing_fields(self) -> list[str]:
        missing: list[str] = []
        if not self.recipients:
            missing.append("收件邮箱")
        if not self.sender:
            missing.append("发件邮箱")
        if not self.smtp_host:
            missing.append("SMTP 主机")
        if not self.smtp_port:
            missing.append("SMTP 端口")
        return missing


def start_email_digest_worker() -> None:
    global _worker_thread

    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return

        _worker_stop_event.clear()
        _worker_thread = threading.Thread(
            target=_email_digest_loop,
            name="email-digest-worker",
            daemon=True,
        )
        _worker_thread.start()
        logger.info(
            "email digest worker started | poll_interval=%.2fs",
            settings.email_digest_worker_poll_interval,
        )


def stop_email_digest_worker() -> None:
    global _worker_thread

    with _worker_lock:
        thread = _worker_thread
        if thread is None:
            return
        _worker_thread = None
        _worker_stop_event.set()

    thread.join(timeout=5)
    logger.info("email digest worker stopped")


def load_email_notification_config(db: Session) -> EmailNotificationConfig:
    setting_map = system_setting_map(db)
    return EmailNotificationConfig(
        enabled=setting_map.get("notify_email", "disabled") == "enabled",
        recipients=list_email_recipients(setting_map.get("notify_email_recipients", "")),
        template_key=setting_map.get("notify_email_template", "standard_digest"),
        min_level=setting_map.get("notify_email_min_level", "high"),
        digest_minutes=int(setting_map.get("notify_email_digest_minutes", "30") or "30"),
        subject_prefix=setting_map.get("notify_email_subject_prefix", "[蓝队防御]").strip() or "[蓝队防御]",
        sender=setting_map.get("notify_email_sender", "").strip(),
        smtp_host=setting_map.get("smtp_host", "").strip(),
        smtp_port=int(setting_map.get("smtp_port", "587") or "587"),
        smtp_username=setting_map.get("smtp_username", "").strip(),
        smtp_password=setting_map.get("smtp_password", ""),
        smtp_starttls=setting_map.get("smtp_starttls", "enabled") == "enabled",
    )


def send_test_email(db: Session) -> dict[str, str]:
    config = load_email_notification_config(db)
    _ensure_sendable(config, require_enabled=False)

    template = EMAIL_TEMPLATE_DEFINITIONS[config.template_key]
    sent_at = beijing_now()
    subject = f"{config.subject_prefix} {template['subject']}（测试）".strip()
    body = (
        f"{template['intro']}\n\n"
        f"这是一封测试邮件，用于验证平台邮件提醒链路。\n"
        f"时间：{sent_at.strftime('%Y-%m-%d %H:%M:%S')} 北京时间\n"
        f"收件人：{', '.join(config.recipients)}\n"
        f"发送阈值：{config.min_level}\n"
        f"汇总周期：{config.digest_minutes} 分钟\n"
    )
    _dispatch_email(config, subject, body)
    return {
        "subject": subject,
        "recipients": ", ".join(config.recipients),
        "sent_at": sent_at.strftime("%Y-%m-%d %H:%M:%S"),
    }


def system_setting_map(db: Session) -> dict[str, str]:
    values = {item["setting_key"]: item["setting_value"] for item in default_system_settings()}
    for item in db.query(SystemSetting).all():
        values[item.setting_key] = item.setting_value
    return values


def apply_email_digest_cycle() -> dict[str, str]:
    db = SessionLocal()
    try:
        config = load_email_notification_config(db)
        if not config.enabled:
            return {"status": "disabled", "detail": "邮件提醒未启用"}

        try:
            _ensure_sendable(config, require_enabled=True)
        except ValueError as exc:
            logger.debug("email digest skipped | reason=%s", exc)
            return {"status": "config_error", "detail": str(exc)}

        setting_map = system_setting_map(db)
        last_event_id = int(setting_map.get("notify_email_last_event_id", "0") or "0")
        new_events = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.id > last_event_id)
            .order_by(SecurityEvent.id.asc())
            .all()
        )
        if not new_events:
            return {"status": "idle", "detail": "没有新告警"}

        max_seen_event_id = new_events[-1].id
        qualifying_events = [item for item in new_events if _event_matches_level(item.event_level, config.min_level)]
        if not qualifying_events:
            _upsert_setting(db, "notify_email_last_event_id", str(max_seen_event_id), "邮件提醒内部游标")
            db.commit()
            return {"status": "skip", "detail": "新告警未达到发送阈值"}

        last_digest_at = parse_utc_iso(setting_map.get("notify_email_last_digest_at", ""))
        now_utc = utc_now().replace(microsecond=0)
        if last_digest_at is not None and now_utc < (last_digest_at + timedelta(minutes=config.digest_minutes)).replace(tzinfo=None):
            return {"status": "waiting", "detail": "尚未到达汇总发送周期"}

        subject, body = _build_digest_email(config, qualifying_events)
        _dispatch_email(config, subject, body)

        _upsert_setting(db, "notify_email_last_event_id", str(max_seen_event_id), "邮件提醒内部游标")
        _upsert_setting(db, "notify_email_last_digest_at", now_utc.isoformat(), "邮件提醒最近汇总时间")
        audit_user = _audit_user(db)
        if audit_user is not None:
            append_audit_log(
                db,
                audit_user,
                "system-settings",
                "email-digest",
                f"发送邮件汇总，共 {len(qualifying_events)} 条告警，收件人 {', '.join(config.recipients)}",
            )
        db.commit()
        logger.info(
            "email digest sent | events=%s recipients=%s",
            len(qualifying_events),
            ",".join(config.recipients),
        )
        return {"status": "sent", "detail": f"已发送 {len(qualifying_events)} 条告警"}
    except Exception:
        db.rollback()
        logger.exception("email digest failed")
        return {"status": "error", "detail": "邮件汇总发送失败"}
    finally:
        db.close()


def _email_digest_loop() -> None:
    while not _worker_stop_event.is_set():
        try:
            apply_email_digest_cycle()
        except Exception:
            logger.exception("email digest loop failed")
        _worker_stop_event.wait(settings.email_digest_worker_poll_interval)


def _event_matches_level(event_level: str, min_level: str) -> bool:
    current = EMAIL_LEVEL_ORDER.get(str(event_level or "").lower(), EMAIL_LEVEL_ORDER["medium"])
    required = EMAIL_LEVEL_ORDER.get(str(min_level or "").lower(), EMAIL_LEVEL_ORDER["high"])
    return current >= required


def _ensure_sendable(config: EmailNotificationConfig, *, require_enabled: bool) -> None:
    if require_enabled and not config.enabled:
        raise ValueError("邮件提醒未启用")
    missing = config.missing_fields()
    if missing:
        raise ValueError(f"邮件提醒配置不完整：{', '.join(missing)}")


def _dispatch_email(config: EmailNotificationConfig, subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.sender
    message["To"] = ", ".join(config.recipients)
    message.set_content(body)

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15) as client:
        client.ehlo()
        if config.smtp_starttls:
            client.starttls()
            client.ehlo()
        if config.smtp_username:
            client.login(config.smtp_username, config.smtp_password)
        client.send_message(message)


def _build_digest_email(config: EmailNotificationConfig, events: list[SecurityEvent]) -> tuple[str, str]:
    template = EMAIL_TEMPLATE_DEFINITIONS[config.template_key]
    subject = f"{config.subject_prefix} {template['subject']}".strip()
    lines = []
    for item in events:
        created_at = format_beijing(item.created_at) or "-"
        lines.append(
            f"- [{item.event_level.upper()}] {item.event_type} | {item.source} -> {item.target} | {created_at} | {item.detail}"
        )

    body = (
        f"{template['intro']}\n\n"
        f"生成时间：{beijing_now().strftime('%Y-%m-%d %H:%M:%S')} 北京时间\n"
        f"汇总条数：{len(events)}\n"
        f"发送阈值：{config.min_level}\n"
        f"汇总周期：{config.digest_minutes} 分钟\n\n"
        "告警明细：\n"
        f"{chr(10).join(lines)}\n"
    )
    return subject, body


def _upsert_setting(db: Session, key: str, value: str, description: str) -> None:
    item = db.query(SystemSetting).get(key)
    if item is None:
        item = SystemSetting(setting_key=key, setting_value=value, description=description)
        db.add(item)
        return
    item.setting_value = value
    item.description = description


def _audit_user(db: Session) -> User | None:
    admin_user = db.query(User).filter(User.roles_json.like("%admin%")).order_by(User.id.asc()).first()
    if admin_user is not None:
        return admin_user
    return db.query(User).order_by(User.id.asc()).first()
