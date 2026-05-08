from __future__ import annotations

import re
from typing import Any

EMAIL_LEVEL_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
}

EMAIL_TEMPLATE_DEFINITIONS: dict[str, dict[str, str]] = {
    "standard_digest": {
        "label": "标准汇总",
        "subject": "安全告警汇总",
        "intro": "以下为本周期内命中的安全告警汇总，请按优先级安排处置。",
    },
    "high_priority_digest": {
        "label": "高危简报",
        "subject": "高危告警简报",
        "intro": "以下为达到发送阈值的高优先级安全告警，请优先核查。",
    },
    "ops_shift_digest": {
        "label": "值班播报",
        "subject": "值班告警播报",
        "intro": "以下为新汇总的安全告警，请值班人员按流程跟进。",
    },
}

_VISIBLE_SETTING_DEFINITIONS: list[dict[str, Any]] = [
    {
        "setting_key": "log_level",
        "setting_value": "INFO",
        "description": "日志级别",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": "DEBUG", "value": "DEBUG"},
                {"label": "INFO", "value": "INFO"},
                {"label": "WARN", "value": "WARN"},
                {"label": "ERROR", "value": "ERROR"},
            ],
        },
    },
    {
        "setting_key": "notify_email",
        "setting_value": "disabled",
        "description": "邮件提醒",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": "启用", "value": "enabled"},
                {"label": "停用", "value": "disabled"},
            ],
        },
    },
    {
        "setting_key": "notify_email_recipients",
        "setting_value": "",
        "description": "收件邮箱",
        "field_meta": {
            "control": "token-input",
            "placeholder": "输入邮箱后按 Enter 添加",
            "helper_text": "",
            "options": [],
            "button_text": "添加邮箱",
            "empty_text": "当前未设置收件人",
        },
    },
    {
        "setting_key": "notify_email_template",
        "setting_value": "standard_digest",
        "description": "邮件模板",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": item["label"], "value": key}
                for key, item in EMAIL_TEMPLATE_DEFINITIONS.items()
            ],
        },
    },
    {
        "setting_key": "notify_email_min_level",
        "setting_value": "high",
        "description": "发送阈值",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": "低危及以上", "value": "low"},
                {"label": "中危及以上", "value": "medium"},
                {"label": "高危", "value": "high"},
            ],
        },
    },
    {
        "setting_key": "notify_email_digest_minutes",
        "setting_value": "30",
        "description": "汇总周期（分钟）",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 30",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "notify_email_subject_prefix",
        "setting_value": "[蓝队防御]",
        "description": "邮件标题前缀",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 [蓝队防御]",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "notify_email_sender",
        "setting_value": "",
        "description": "发件邮箱",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 alert@example.com",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "smtp_host",
        "setting_value": "",
        "description": "SMTP 主机",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 smtp.example.com",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "smtp_port",
        "setting_value": "587",
        "description": "SMTP 端口",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 587",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "smtp_username",
        "setting_value": "",
        "description": "SMTP 用户名",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 alert@example.com",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "smtp_password",
        "setting_value": "",
        "description": "SMTP 密码",
        "field_meta": {
            "control": "password",
            "placeholder": "输入 SMTP 密码",
            "helper_text": "",
            "options": [],
        },
    },
    {
        "setting_key": "smtp_starttls",
        "setting_value": "enabled",
        "description": "SMTP STARTTLS",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": "启用", "value": "enabled"},
                {"label": "停用", "value": "disabled"},
            ],
        },
    },
    {
        "setting_key": "display_timezone",
        "setting_value": "Asia/Shanghai",
        "description": "显示时区",
        "field_meta": {
            "control": "select",
            "placeholder": "",
            "helper_text": "",
            "options": [
                {"label": "北京时间（Asia/Shanghai）", "value": "Asia/Shanghai"},
            ],
        },
    },
]

_INTERNAL_SETTING_DEFAULTS: list[dict[str, str]] = [
    {
        "setting_key": "notify_email_last_event_id",
        "setting_value": "0",
        "description": "邮件提醒内部游标",
    },
    {
        "setting_key": "notify_email_last_digest_at",
        "setting_value": "",
        "description": "邮件提醒最近汇总时间",
    },
    {
        "setting_key": "permission_cache_refreshed_at",
        "setting_value": "",
        "description": "权限缓存刷新时间",
    },
]

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def default_system_settings() -> list[dict[str, str]]:
    items = [
        {
            "setting_key": item["setting_key"],
            "setting_value": item["setting_value"],
            "description": item["description"],
        }
        for item in _VISIBLE_SETTING_DEFINITIONS
    ]
    items.extend(_INTERNAL_SETTING_DEFAULTS)
    return items


def visible_setting_keys() -> list[str]:
    return [item["setting_key"] for item in _VISIBLE_SETTING_DEFINITIONS]


def visible_system_setting_definitions() -> list[dict[str, Any]]:
    return list(_VISIBLE_SETTING_DEFINITIONS)


def field_meta_for_setting(setting_key: str) -> dict[str, Any]:
    for item in _VISIBLE_SETTING_DEFINITIONS:
        if item["setting_key"] == setting_key:
            return dict(item["field_meta"])
    return {
        "control": "text",
        "placeholder": "输入设置值",
        "helper_text": "",
        "options": [],
    }


def is_internal_setting(setting_key: str) -> bool:
    return setting_key not in visible_setting_keys()


def sort_visible_settings(items: list[Any]) -> list[Any]:
    order_map = {key: index for index, key in enumerate(visible_setting_keys())}
    return sorted(items, key=lambda item: order_map.get(item.setting_key, len(order_map) + 1))


def list_email_recipients(value: str) -> list[str]:
    recipients: list[str] = []
    for raw_item in re.split(r"[,\n;]+", value or ""):
        normalized = raw_item.strip()
        if normalized and normalized not in recipients:
            recipients.append(normalized)
    return recipients


def normalize_setting_value(setting_key: str, setting_value: str) -> str:
    value = (setting_value or "").strip()

    if setting_key == "log_level":
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARN", "ERROR"}:
            raise ValueError("日志级别仅支持 DEBUG / INFO / WARN / ERROR")
        return normalized

    if setting_key in {"notify_email", "smtp_starttls"}:
        if value not in {"enabled", "disabled"}:
            raise ValueError("该设置仅支持 enabled / disabled")
        return value

    if setting_key == "notify_email_template":
        if value not in EMAIL_TEMPLATE_DEFINITIONS:
            raise ValueError("邮件模板不存在")
        return value

    if setting_key == "notify_email_min_level":
        if value not in EMAIL_LEVEL_ORDER:
            raise ValueError("发送阈值仅支持 low / medium / high")
        return value

    if setting_key == "notify_email_digest_minutes":
        try:
            minutes = int(value)
        except ValueError as exc:
            raise ValueError("汇总周期必须是数字") from exc
        if minutes < 1 or minutes > 1440:
            raise ValueError("汇总周期范围为 1 到 1440 分钟")
        return str(minutes)

    if setting_key == "smtp_port":
        try:
            port = int(value)
        except ValueError as exc:
            raise ValueError("SMTP 端口必须是数字") from exc
        if port < 1 or port > 65535:
            raise ValueError("SMTP 端口范围为 1 到 65535")
        return str(port)

    if setting_key in {"notify_email_sender", "smtp_username"}:
        if value and not _EMAIL_REGEX.match(value):
            raise ValueError("邮箱格式不正确")
        return value

    if setting_key == "notify_email_recipients":
        recipients = list_email_recipients(value)
        invalid = [item for item in recipients if not _EMAIL_REGEX.match(item)]
        if invalid:
            raise ValueError(f"收件邮箱格式不正确: {', '.join(invalid)}")
        return ",".join(recipients)

    if setting_key == "display_timezone":
        if value != "Asia/Shanghai":
            raise ValueError("当前仅支持 Asia/Shanghai")
        return value

    return value
