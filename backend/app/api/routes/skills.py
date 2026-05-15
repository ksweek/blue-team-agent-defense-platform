from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AiEndpoint, AttackTask, Skill, User
from ...schemas.skill import (
    SkillCreateRequest,
    SkillImportDirectoryRequest,
    SkillScanRequest,
    SkillSourcePathUpdate,
    TrustStatusUpdate,
)
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.endpoint_governance import assign_skills_to_endpoint, get_endpoint_skill_ids
from ...services.repository import contains_keyword, paginate
from ...services.skill_scan import describe_skill_source, serialize_skill_scan_source
from ...services.skill_registry import (
    create_or_update_skill,
    import_skills_from_directory,
    preview_skills_from_directory,
)
from ...services.time_utils import format_beijing, utc_now

router = APIRouter()


SOURCE_PATH_FIELD_META = {
    "control": "text",
    "placeholder": r"backend/data/demo_skills/filesystem-reader 或 /srv/skills/my-skill",
    "helper_text": "扫描路径按后端机器文件系统解析，支持绝对路径和相对项目根目录。",
    "button_text": "",
    "empty_text": "",
    "options": [],
}

SKILL_NAME_FIELD_META = {
    "control": "text",
    "placeholder": "技能名称",
    "helper_text": "",
    "button_text": "",
    "empty_text": "",
    "options": [],
}

SKILL_TYPE_FIELD_META = {
    "control": "select",
    "placeholder": "",
    "helper_text": "",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "本地", "value": "local", "tone": "info"},
        {"label": "插件", "value": "plugin", "tone": "warn"},
        {"label": "远程", "value": "remote", "tone": "info"},
        {"label": "MCP", "value": "mcp", "tone": "info"},
    ],
}

SKILL_PROVIDER_FIELD_META = {
    "control": "select",
    "placeholder": "",
    "helper_text": "",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "手动", "value": "manual", "tone": "info"},
        {"label": "导入", "value": "imported", "tone": "info"},
        {"label": "官方", "value": "official", "tone": "safe"},
        {"label": "第三方", "value": "third-party", "tone": "warn"},
    ],
}

TRUST_STATUS_FIELD_META = {
    "control": "segmented",
    "placeholder": "",
    "helper_text": "信任状态即时生效。",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "可信", "value": "trusted", "tone": "safe"},
        {"label": "待审核", "value": "pending", "tone": "warn"},
    ],
}

DIRECTORY_PATH_FIELD_META = {
    "control": "text",
    "placeholder": r"例如 /srv/skills 或 C:\agent\skills",
    "helper_text": "",
    "button_text": "",
    "empty_text": "",
    "options": [],
}

CREATE_SKILL_META = {
    "title": "新增 Skill",
    "helper_text": "直接纳管单个远程 skill 目录。",
    "submit_button_text": "新增",
    "field_meta": {
        "skill_name": SKILL_NAME_FIELD_META,
        "skill_type": SKILL_TYPE_FIELD_META,
        "provider": SKILL_PROVIDER_FIELD_META,
        "source_path": SOURCE_PATH_FIELD_META,
        "trust_status": TRUST_STATUS_FIELD_META,
    },
}

DIRECTORY_IMPORT_META = {
    "title": "导入 Skill 目录",
    "helper_text": "批量导入包含 SKILL.md 的目录，支持递归扫描。",
    "preview_button_text": "预览导入",
    "confirm_button_text": "确认入库",
    "recursive_enabled_text": "递归导入",
    "recursive_disabled_text": "当前仅一层",
    "recursive_default": True,
    "preview_title": "导入预览",
    "preview_empty_text": "当前目录未发现可导入的 skill。",
    "field_meta": {
        "directory_path": DIRECTORY_PATH_FIELD_META,
        "skill_type": SKILL_TYPE_FIELD_META,
        "provider": SKILL_PROVIDER_FIELD_META,
        "trust_status": TRUST_STATUS_FIELD_META,
    },
}

SCAN_SELECTION_META = {
    "toolbar_title": "扫描选择与即时审批",
    "selected_summary_template": "{count} 个已选",
    "selected_summary_active_tone": "info",
    "selected_summary_empty_tone": "safe",
    "pending_summary_template": "待审核 {count} 个",
    "select_pending_button_text": "选择待审核",
    "clear_selection_button_text": "清空选择",
    "scan_button_text": "扫描所选技能",
    "messages": {
        "select_pending_template": "已选中 {count} 个待审核技能。",
        "select_pending_empty_text": "当前没有待审核技能。",
        "clear_selection_text": "已清空选择",
        "missing_selection_text": "先选择需要联动扫描的技能。",
        "scan_creating_template": "正在为 {count} 个技能创建扫描任务...",
        "scan_completed_template": "已完成 {count} 个技能的联动扫描{event_suffix}{report_suffix}。",
        "scan_queued_template": "已创建 {count} 个后台任务，执行结果将自动回显。",
        "task_refresh_failed_text": "任务状态刷新失败",
        "task_finished_template": "任务 {task_name} 已完成，结果已自动回写。",
        "task_failed_template": "任务 {task_name} 执行失败",
        "scan_create_failed_text": "技能扫描任务创建失败",
        "event_suffix_template": "，事件 #{event_id}",
        "report_suffix_template": "，报告 #{report_id}",
    },
    "task_status_map": {
        "queued": {"label": "排队中", "tone": "info"},
        "running": {"label": "运行中", "tone": "warn"},
        "done": {"label": "已完成", "tone": "safe"},
        "failed": {"label": "执行失败", "tone": "danger"},
    },
}

SCAN_TASK_RESULT_META = {
    "key": "skill_scan_tasks",
    "title": "扫描任务",
    "empty_text": "当前还没有扫描或联动任务，选择技能后可直接创建。",
}


SCAN_TASK_SECTION_META = {
    "id": "scan-tasks",
    "eyebrow": "任务",
    "tone": "warn",
}


IMPORT_PREVIEW_SECTION_META = {
    "id": "import-preview",
    "eyebrow": "导入",
}


def _build_action_fields(field_meta: dict, keys: list[str]) -> list[dict]:
    return [{"key": key, "field_meta": field_meta[key]} for key in keys]


SKILL_ACTIONS = [
    {
        "key": "scan_selection",
        "action_type": "selection_toolbar",
        "title": SCAN_SELECTION_META["toolbar_title"],
        "summary_items": [
            {
                "key": "selected",
                "template": SCAN_SELECTION_META["selected_summary_template"],
                "source": "selected",
                "display": "pill",
                "tone": SCAN_SELECTION_META["selected_summary_active_tone"],
                "empty_tone": SCAN_SELECTION_META["selected_summary_empty_tone"],
            },
            {
                "key": "pending",
                "template": SCAN_SELECTION_META["pending_summary_template"],
                "source": "pending",
                "display": "text",
                "tone": "info",
            },
        ],
        "buttons": [
            {
                "action_key": "select_pending",
                "label": SCAN_SELECTION_META["select_pending_button_text"],
                "tone": "ghost",
            },
            {
                "action_key": "clear_selection",
                "label": SCAN_SELECTION_META["clear_selection_button_text"],
                "tone": "ghost",
                "requires_selection": True,
            },
            {
                "action_key": "scan_selected",
                "label": SCAN_SELECTION_META["scan_button_text"],
                "tone": "primary",
                "requires_selection": True,
            },
        ],
        "messages": SCAN_SELECTION_META["messages"],
        "task_status_map": SCAN_SELECTION_META["task_status_map"],
    },
    {
        "key": "create_skill",
        "action_type": "form",
        "model_key": "create_skill",
        "title": CREATE_SKILL_META["title"],
        "helper_text": CREATE_SKILL_META["helper_text"],
        "fields": _build_action_fields(
            CREATE_SKILL_META["field_meta"],
            ["skill_name", "skill_type", "provider", "source_path", "trust_status"],
        ),
        "submit_action": {
            "action_key": "create_skill",
            "label": CREATE_SKILL_META["submit_button_text"],
            "tone": "primary",
        },
    },
    {
        "key": "directory_import",
        "action_type": "form",
        "model_key": "directory_import",
        "title": DIRECTORY_IMPORT_META["title"],
        "helper_text": DIRECTORY_IMPORT_META["helper_text"],
        "fields": _build_action_fields(
            DIRECTORY_IMPORT_META["field_meta"],
            ["directory_path", "skill_type", "provider", "trust_status"],
        ),
        "secondary_actions": [
            {
                "action_key": "toggle_import_recursive",
                "label": DIRECTORY_IMPORT_META["recursive_enabled_text"],
                "alternate_label": DIRECTORY_IMPORT_META["recursive_disabled_text"],
                "tone": "ghost",
                "toggle_state_key": "recursive",
            }
        ],
        "submit_action": {
            "action_key": "preview_import_directory",
            "label": DIRECTORY_IMPORT_META["preview_button_text"],
            "tone": "primary",
        },
    },
]


def _build_import_preview_summary(result) -> dict:
    summary_items = [
        {
            "key": "detected",
            "text": f"检测 {result.detected}",
            "value": result.detected,
            "tone": "info",
        },
        {
            "key": "created",
            "text": f"新增 {result.created}",
            "value": result.created,
            "tone": "safe",
        },
        {
            "key": "updated",
            "text": f"更新 {result.updated}",
            "value": result.updated,
            "tone": "info",
        },
        {
            "key": "skipped",
            "text": f"跳过 {result.skipped}",
            "value": result.skipped,
            "tone": "warn",
        },
    ]
    summary_text = f"检测到 {result.detected} 个 skill，新增 {result.created}，更新 {result.updated}，跳过 {result.skipped}"
    return {
        "title": DIRECTORY_IMPORT_META["preview_title"],
        "confirm_button_text": DIRECTORY_IMPORT_META["confirm_button_text"],
        "empty_text": DIRECTORY_IMPORT_META["preview_empty_text"],
        "summary_text": summary_text,
        "summary_items": summary_items,
    }


def _build_import_preview_result_panel(result) -> dict:
    preview_summary = _build_import_preview_summary(result)
    return {
        "key": "directory_import_preview",
        "panel_type": "result_panel",
        "title": preview_summary["title"],
        "summary_text": preview_summary["summary_text"],
        "detail_text": result.base_directory,
        "empty_text": preview_summary["empty_text"],
        "summary_items": preview_summary["summary_items"],
        "actions": [
            {
                "action_key": "confirm_import_directory",
                "label": DIRECTORY_IMPORT_META["confirm_button_text"],
                "tone": "primary",
                "disabled": result.created + result.updated == 0,
            }
        ],
        "items": [
            {
                "key": f"{item.source_path}:{item.action}",
                "title": item.skill_name,
                "subtitle": item.source_path,
                "badges": [
                    {
                        "key": "reason",
                        "text": (
                            f"{item.reason_label} #{item.existing_skill_id}"
                            if item.existing_skill_id
                            else item.reason_label
                        ),
                        "tone": item.reason_tone,
                    },
                    {
                        "key": "action",
                        "text": item.action_label,
                        "tone": item.action_tone,
                    },
                ],
            }
            for item in result.items
        ],
    }


def _task_status_payload(status: str) -> dict:
    return SCAN_SELECTION_META["task_status_map"].get(
        status,
        {
            "label": status,
            "tone": "danger",
        },
    )


def _scan_task_summary(item: AttackTask) -> str:
    if item.result_summary:
        return item.result_summary
    if item.status == "queued":
        return "任务已创建，等待执行。"
    if item.status == "running":
        return "任务执行中，结果将自动回显。"
    if item.status == "done":
        return "任务已完成。"
    if item.status == "failed":
        return "任务执行失败。"
    return ""


def _build_scan_task_result_list(items: list[AttackTask], *, page: int, page_size: int) -> dict:
    paginated = paginate([{"task": item} for item in items], page=page, page_size=page_size)
    paginated_items = [entry["task"] for entry in paginated["items"]]
    return {
        "key": SCAN_TASK_RESULT_META["key"],
        "panel_type": "result_list",
        "title": SCAN_TASK_RESULT_META["title"],
        "empty_text": SCAN_TASK_RESULT_META["empty_text"],
        "total": paginated["total"],
        "page": paginated["page"],
        "page_size": paginated["page_size"],
        "items": [
            {
                "key": f"skill-scan-task-{item.id}",
                "task_id": item.id,
                "status": item.status,
                "title": item.task_name,
                "subtitle": f"{item.attack_type} / {item.target_agent}",
                "summary_text": _scan_task_summary(item),
                "meta_text": format_beijing(item.finished_at or item.updated_at or item.created_at) or "",
                "badges": [
                    {
                        "key": "status",
                        "text": _task_status_payload(item.status)["label"],
                        "tone": _task_status_payload(item.status)["tone"],
                    }
                ],
                "meta_badges": [
                    *(
                        [
                            {
                                "key": "event",
                                "text": f"事件 #{item.latest_event_id}",
                                "tone": "danger",
                            }
                        ]
                        if item.latest_event_id
                        else []
                    ),
                    *(
                        [
                            {
                                "key": "report",
                                "text": f"报告 #{item.latest_report_id}",
                                "tone": "info",
                            }
                        ]
                        if item.latest_report_id
                        else []
                    ),
                ],
            }
            for item in paginated_items
        ],
    }


def _build_result_block(
    *,
    key: str,
    block_type: str,
    eyebrow: str,
    title: str,
    tone: str,
    section_id: str = "",
    tag: str = "",
    result_panel: dict | None = None,
    result_list: dict | None = None,
) -> dict:
    return {
        "key": key,
        "block_type": block_type,
        "section": {
            "id": section_id,
            "eyebrow": eyebrow,
            "title": title,
            "tag": tag,
            "tone": tone,
        },
        "result_panel": result_panel,
        "result_list": result_list,
    }


def _build_import_preview_result_block(result) -> dict:
    preview_panel = _build_import_preview_result_panel(result)
    has_importable_items = result.created + result.updated > 0
    return _build_result_block(
        key=preview_panel["key"],
        block_type="result_panel",
        section_id=IMPORT_PREVIEW_SECTION_META["id"],
        eyebrow=IMPORT_PREVIEW_SECTION_META["eyebrow"],
        title=preview_panel["title"],
        tone="info" if has_importable_items else "safe",
        tag="\u5f85\u786e\u8ba4" if has_importable_items else "\u65e0\u53d8\u66f4",
        result_panel=preview_panel,
    )


def _serialize_skill(item: Skill) -> dict:
    source = describe_skill_source(item)
    return {
        "id": item.id,
        "skill_name": item.skill_name,
        "skill_type": item.skill_type,
        "provider": item.provider,
        "source_path": item.source_path,
        "source_path_state": source["state"],
        "resolved_source_path": source["resolved_path"],
        "trust_status": item.trust_status,
        "created_at": format_beijing(item.created_at, "%Y-%m-%d") or "",
        "field_meta": {
            "source_path": SOURCE_PATH_FIELD_META,
            "trust_status": TRUST_STATUS_FIELD_META,
        },
    }


def _serialize_task(item: AttackTask) -> dict:
    return {
        "id": item.id,
        "task_name": item.task_name,
        "attack_type": item.attack_type,
        "target_agent": item.target_agent,
        "status": item.status,
        "params_json": item.params,
        "raw_response": item.raw_response,
        "result_summary": item.result_summary,
        "latest_event_id": item.latest_event_id,
        "latest_report_id": item.latest_report_id,
        "created_at": format_beijing(item.created_at) or "",
    }


def _get_skill_or_404(db: Session, skill_id: int) -> Skill:
    item = db.get(Skill, skill_id)
    if item is None:
        raise HTTPException(status_code=404, detail="skill not found")
    return item


def _get_ai_endpoint_or_404(db: Session, ai_endpoint_id: int) -> AiEndpoint:
    item = db.get(AiEndpoint, ai_endpoint_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ai endpoint not found")
    return item


def _task_ai_endpoint_id(item: AttackTask) -> int | None:
    raw_value = item.params.get("ai_endpoint_id")
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str) and raw_value.strip().isdigit():
        return int(raw_value.strip())
    return None


def _normalize_trust_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in {"trusted", "pending"}:
        raise HTTPException(status_code=400, detail="invalid trust_status")
    return normalized


@router.get("")
def list_skills(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    scan_task_page: int = Query(1, ge=1),
    scan_task_page_size: int = Query(6, ge=1, le=50),
    trust_status: Optional[str] = None,
    provider: Optional[str] = None,
    keyword: Optional[str] = None,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id) if ai_endpoint_id is not None else None
    scoped_skill_ids = set(get_endpoint_skill_ids(endpoint)) if endpoint is not None else set()
    items = [
        _serialize_skill(item)
        for item in db.query(Skill).order_by(Skill.created_at.desc(), Skill.id.desc()).all()
        if endpoint is None or item.id in scoped_skill_ids
    ]
    scan_tasks = (
        db.query(AttackTask)
        .filter(AttackTask.attack_type == "skill_scan")
        .order_by(AttackTask.created_at.desc(), AttackTask.id.desc())
        .all()
    )
    if endpoint is not None:
        scan_tasks = [item for item in scan_tasks if _task_ai_endpoint_id(item) == endpoint.id]

    if trust_status:
        items = [item for item in items if item["trust_status"] == trust_status]
    if provider:
        items = [item for item in items if item["provider"] == provider]
    if keyword:
        items = [
            item
            for item in items
            if contains_keyword(item, keyword, ["skill_name", "skill_type", "provider", "source_path", "trust_status"])
        ]

    paginated_skills = paginate(items, page=page, page_size=page_size)
    scan_task_result_list = _build_scan_task_result_list(
        scan_tasks,
        page=scan_task_page,
        page_size=scan_task_page_size,
    )

    return success(
        {
            **paginated_skills,
            "intake_meta": {
                "create_skill": CREATE_SKILL_META,
                "directory_import": DIRECTORY_IMPORT_META,
            },
            "action_meta": {
                "actions": SKILL_ACTIONS,
            },
            "result_meta": {
                "panels": [],
                "lists": [scan_task_result_list],
                "blocks": [
                    _build_result_block(
                        key=SCAN_TASK_RESULT_META["key"],
                        block_type="result_list",
                        section_id=SCAN_TASK_SECTION_META["id"],
                        eyebrow=SCAN_TASK_SECTION_META["eyebrow"],
                        title=SCAN_TASK_RESULT_META["title"],
                        tone=SCAN_TASK_SECTION_META["tone"],
                        result_list=scan_task_result_list,
                    )
                ],
            },
        }
    )


@router.post("")
def create_skill(
    payload: SkillCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    endpoint = _get_ai_endpoint_or_404(db, payload.ai_endpoint_id) if payload.ai_endpoint_id is not None else None
    skill, created = create_or_update_skill(
        db,
        skill_name=payload.skill_name.strip(),
        skill_type=payload.skill_type.strip(),
        provider=payload.provider.strip(),
        source_path=payload.source_path.strip(),
        trust_status=_normalize_trust_status(payload.trust_status),
    )
    if endpoint is not None:
        assign_skills_to_endpoint(endpoint, [skill.id])
    append_audit_log(
        db,
        current_user,
        "skills",
        "create" if created else "update-from-create",
        f"{'created' if created else 'updated'} skill {skill.skill_name} scope={payload.ai_endpoint_id or 'global'}",
    )
    db.commit()
    db.refresh(skill)
    return success(_serialize_skill(skill), message="created" if created else "updated")


@router.post("/import-directory")
def import_skill_directory(
    payload: SkillImportDirectoryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    endpoint = _get_ai_endpoint_or_404(db, payload.ai_endpoint_id) if payload.ai_endpoint_id is not None else None
    try:
        result = import_skills_from_directory(
            db,
            directory_path=payload.directory_path,
            skill_type=payload.skill_type.strip(),
            provider=payload.provider.strip(),
            trust_status=_normalize_trust_status(payload.trust_status),
            recursive=payload.recursive,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    imported_items = [*result.created, *result.updated]
    if endpoint is not None and imported_items:
        assign_skills_to_endpoint(endpoint, [item.id for item in imported_items])
    append_audit_log(
        db,
        current_user,
        "skills",
        "import-directory",
        f"imported skill directory {payload.directory_path.strip()} created={len(result.created)} updated={len(result.updated)} skipped={len(result.skipped)} scope={payload.ai_endpoint_id or 'global'}",
    )
    db.commit()
    for item in imported_items:
        db.refresh(item)

    return success(
        {
            "created": len(result.created),
            "updated": len(result.updated),
            "skipped": len(result.skipped),
            "items": [_serialize_skill(item) for item in imported_items],
            "skipped_items": result.skipped,
        },
        message="imported",
    )


@router.post("/import-directory/preview")
def preview_import_skill_directory(
    payload: SkillImportDirectoryRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    if payload.ai_endpoint_id is not None:
        _get_ai_endpoint_or_404(db, payload.ai_endpoint_id)
    try:
        result = preview_skills_from_directory(
            db,
            directory_path=payload.directory_path,
            skill_type=payload.skill_type.strip(),
            provider=payload.provider.strip(),
            trust_status=_normalize_trust_status(payload.trust_status),
            recursive=payload.recursive,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return success(
        {
            "base_directory": result.base_directory,
            "detected": result.detected,
            "created": result.created,
            "updated": result.updated,
            "skipped": result.skipped,
            **_build_import_preview_summary(result),
            "result_panel": _build_import_preview_result_panel(result),
            "result_blocks": [_build_import_preview_result_block(result)],
            "items": [
                {
                    "skill_name": item.skill_name,
                    "source_path": item.source_path,
                    "action": item.action,
                    "action_label": item.action_label,
                    "action_tone": item.action_tone,
                    "reason": item.reason,
                    "reason_label": item.reason_label,
                    "reason_tone": item.reason_tone,
                    "existing_skill_id": item.existing_skill_id,
                }
                for item in result.items
            ],
        },
        message="previewed",
    )


@router.post("/scan")
def scan_skills(
    payload: SkillScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    endpoint = _get_ai_endpoint_or_404(db, payload.ai_endpoint_id) if payload.ai_endpoint_id is not None else None
    scoped_skill_ids = set(get_endpoint_skill_ids(endpoint)) if endpoint is not None else set()
    skill_names: list[str] = []
    skill_sources: list[dict[str, object]] = []
    for skill_id in payload.skill_ids:
        skill = _get_skill_or_404(db, skill_id)
        if endpoint is not None and skill.id not in scoped_skill_ids:
            raise HTTPException(status_code=400, detail=f"skill {skill.id} is not assigned to ai endpoint {endpoint.id}")
        skill_names.append(skill.skill_name)
        skill_sources.append(serialize_skill_scan_source(skill))

    task = AttackTask(
        task_name="skill-scan-task",
        attack_type="skill_scan",
        target_agent=f"skills:{','.join(map(str, payload.skill_ids))}",
        status="queued",
        created_by=current_user.id,
    )
    task.set_params(
        {
            "skill_ids": payload.skill_ids,
            "skill_names": skill_names,
            "skill_sources": skill_sources,
            "requested_at": format_beijing(utc_now()) or "",
            "scan_execution_mode": "prefer_remote_runtime" if endpoint is not None else "local_worker",
            **({"ai_endpoint_id": endpoint.id} if endpoint is not None else {}),
        }
    )
    db.add(task)
    append_audit_log(
        db,
        current_user,
        "skills",
        "scan",
        f"queued skill scan for {len(payload.skill_ids)} skill(s) scope={payload.ai_endpoint_id or 'global'}",
    )
    db.commit()
    db.refresh(task)
    return success(_serialize_task(task), message="scan queued")


@router.get("/{skill_id}")
def get_skill(
    skill_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_skill_or_404(db, skill_id)
    return success(_serialize_skill(item))


@router.put("/{skill_id}/trust-status")
def update_skill_trust_status(
    skill_id: int,
    payload: TrustStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_skill_or_404(db, skill_id)
    item.trust_status = payload.trust_status
    append_audit_log(db, current_user, "skills", "update-trust", f"updated skill {item.skill_name}")
    db.commit()
    db.refresh(item)
    return success(_serialize_skill(item), message="updated")


@router.put("/{skill_id}/source-path")
def update_skill_source_path(
    skill_id: int,
    payload: SkillSourcePathUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_skill_or_404(db, skill_id)
    item.source_path = payload.source_path.strip()
    append_audit_log(db, current_user, "skills", "update-source-path", f"updated source path for {item.skill_name}")
    db.commit()
    db.refresh(item)
    return success(_serialize_skill(item), message="updated")
