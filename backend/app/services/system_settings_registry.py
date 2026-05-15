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

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_QQ_MAILBOX_DOMAINS = ("qq.com", "vip.qq.com", "foxmail.com")
_QQ_EMAIL_HELPER = (
    "系统固定使用 QQ 邮箱 smtp.qq.com:465 发送。"
    "请在 QQ 邮箱 -> 设置 -> 账户 -> POP3/IMAP/SMTP 服务中开启 SMTP 并生成授权码。"
)
REVIEW_AI_API_URL_KEY = "review_ai_api_url"
REVIEW_AI_API_KEY_KEY = "review_ai_api_key"
REVIEW_AI_MODEL_KEY = "review_ai_model"
DEFAULT_REVIEW_AI_MODEL = "gpt-4.1-mini"

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
        "setting_key": REVIEW_AI_API_URL_KEY,
        "setting_value": "",
        "description": "辅助研判接口",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 https://api.example.com/v1",
            "helper_text": "填写独立研判服务的 OpenAI-compatible base URL 或 /chat/completions 完整地址。",
            "options": [],
        },
    },
    {
        "setting_key": REVIEW_AI_API_KEY_KEY,
        "setting_value": "",
        "description": "辅助研判 API Key",
        "field_meta": {
            "control": "password",
            "placeholder": "输入辅助研判服务的 API Key",
            "helper_text": "这里是独立研判服务的密钥，不会作为受保护目标的上游密钥使用。",
            "options": [],
        },
    },
    {
        "setting_key": REVIEW_AI_MODEL_KEY,
        "setting_value": DEFAULT_REVIEW_AI_MODEL,
        "description": "辅助研判模型",
        "field_meta": {
            "control": "text",
            "placeholder": DEFAULT_REVIEW_AI_MODEL,
            "helper_text": "通常保持默认即可；如果你的接口固定模型，也可以留空走默认值。",
            "options": [],
        },
    },
    {
        "setting_key": "notify_email_recipients",
        "setting_value": "",
        "description": "收件邮箱",
        "field_meta": {
            "control": "token-input",
            "placeholder": "输入邮箱后按 Enter 添加",
            "helper_text": "支持多个收件人，建议填写安全值班和负责人邮箱。",
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
            "helper_text": "仅当告警级别达到该阈值及以上时才进入邮件汇总。",
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
            "helper_text": "邮件按固定周期汇总发送，避免高频轰炸。",
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
            "helper_text": "会追加在测试邮件和告警汇总邮件主题前。",
            "options": [],
        },
    },
    {
        "setting_key": "qq_email_account",
        "setting_value": "",
        "description": "QQ 发件邮箱",
        "field_meta": {
            "control": "text",
            "placeholder": "例如 12345678@qq.com",
            "helper_text": _QQ_EMAIL_HELPER,
            "options": [],
        },
    },
    {
        "setting_key": "qq_email_auth_code",
        "setting_value": "",
        "description": "QQ 邮箱授权码",
        "field_meta": {
            "control": "password",
            "placeholder": "输入 QQ 邮箱 SMTP 授权码",
            "helper_text": "这里填写授权码，不是 QQ 登录密码。",
            "options": [],
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

    if setting_key == "notify_email":
        if value not in {"enabled", "disabled"}:
            raise ValueError("该设置仅支持 enabled / disabled")
        return value

    if setting_key == REVIEW_AI_API_URL_KEY:
        if not value:
            return ""
        if not re.match(r"^https?://", value, flags=re.IGNORECASE):
            raise ValueError("辅助研判接口必须以 http:// 或 https:// 开头")
        return value.rstrip("/")

    if setting_key == REVIEW_AI_API_KEY_KEY:
        return re.sub(r"\s+", "", value)

    if setting_key == REVIEW_AI_MODEL_KEY:
        return value or DEFAULT_REVIEW_AI_MODEL

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

    if setting_key == "qq_email_account":
        if value and not _EMAIL_REGEX.match(value):
            raise ValueError("QQ 发件邮箱格式不正确")
        if value and not _is_supported_qq_mailbox(value):
            raise ValueError("仅支持 QQ 邮箱或 Foxmail 邮箱作为发件账号")
        return value

    if setting_key == "qq_email_auth_code":
        return re.sub(r"\s+", "", value)

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


def _is_supported_qq_mailbox(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.endswith(f"@{domain}") for domain in _QQ_MAILBOX_DOMAINS)
