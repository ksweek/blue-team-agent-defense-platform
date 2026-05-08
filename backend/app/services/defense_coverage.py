from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .sample_catalog import focused_pack_index, query_samples, section_index

DEFENSE_COVERAGE_HINTS: dict[str, dict[str, Any]] = {
    "prompt_injection_firewall": {
        "section_files": [
            "01_direct_prompt_injection.jsonl",
            "08_approval_bypass_social_engineering.jsonl",
            "09_combined_attack_chain.jsonl",
        ],
        "pack_files": [],
        "attack_stages": ["input", "authorization", "chain"],
        "attack_surfaces": ["直接 Prompt Injection", "Jailbreak 变体", "角色混淆与社会工程"],
        "attack_families": [
            "prompt-injection",
            "jailbreak_prompt",
            "suffix_attack",
            "role-confusion",
            "harmful_goal",
            "persuasion_social_engineering",
        ],
    },
    "indirect_content_isolation": {
        "section_files": [
            "05_indirect_prompt_injection.jsonl",
            "07_output_leakage_and_redaction.jsonl",
        ],
        "pack_files": [],
        "attack_stages": ["external_content", "tool_result", "output"],
        "attack_surfaces": ["RAG 文档投毒", "网页与邮件注入", "工具回传污染"],
        "attack_families": [
            "indirect-injection",
            "rendered_script_injection",
            "markdown_javascript_injection",
            "invisible_unicode_tag_injection",
            "markdown_uri_data_exfiltration",
            "playground_markdown_exfiltration",
            "renderer_image_exfiltration",
        ],
    },
    "tool_permission_broker": {
        "section_files": [
            "03_unauthorized_tool_calls.jsonl",
            "04_protected_paths_skills_plugins.jsonl",
            "07_output_leakage_and_redaction.jsonl",
        ],
        "pack_files": [],
        "attack_stages": ["tool_use", "authorization", "output"],
        "attack_surfaces": ["未授权工具调用", "敏感路径读取", "函数调用滥用"],
        "attack_families": [
            "tool-abuse",
            "tool-poisoning",
            "rbac_access_bypass",
            "function-calling",
            "function-calling_alias-bypass",
            "function-calling_schema-smuggling",
            "coding_agent_secret-env-read",
            "coding_agent_secret-file-read",
            "coding_agent_sandbox-read-escape",
            "coding_agent_sandbox-write-escape",
            "data-exfiltration",
        ],
    },
    "mcp_capability_binding": {
        "section_files": ["04_protected_paths_skills_plugins.jsonl"],
        "pack_files": [
            "04_mcp_plugin_chain_cross_plugin.jsonl",
            "04_mcp_plugin_chain_cross_plugin_single_turn.jsonl",
            "04_mcp_plugin_chain_cross_plugin_multi_turn.jsonl",
        ],
        "attack_stages": ["authorization"],
        "attack_surfaces": ["MCP 协议欺骗", "Capability spoof", "Session rebind"],
        "attack_families": [
            "mcp-injection",
            "mcp-injection_authority-smuggling",
            "mcp-injection_server-message-smuggling",
            "mcp-protocol",
            "mcp-protocol_capability-spoof",
            "mcp-protocol_session-rebind",
            "mcp-tool-chain",
            "mcp-tool-chain_cross-server-hop",
            "mcp-tool-chain_secret-staging",
            "mcp-tool-chain_shadow-approval",
        ],
    },
    "cross_plugin_handoff_guard": {
        "section_files": ["04_protected_paths_skills_plugins.jsonl"],
        "pack_files": [
            "04_mcp_plugin_chain_cross_plugin.jsonl",
            "04_mcp_plugin_chain_cross_plugin_single_turn.jsonl",
            "04_mcp_plugin_chain_cross_plugin_multi_turn.jsonl",
        ],
        "attack_stages": ["authorization", "tool_use"],
        "attack_surfaces": ["跨插件授权跳转", "Role borrowing", "Summary laundering"],
        "attack_families": [
            "cross-plugin",
            "cross-plugin_auth-hop",
            "cross-plugin_data-staging",
            "cross-plugin_role-borrowing",
            "cross-plugin_summary-laundering",
            "plugin-abuse",
            "plugin-abuse_disabled-plugin-bypass",
            "plugin-abuse_skill-proxy",
            "function-calling",
            "function-calling_alias-bypass",
            "function-calling_schema-smuggling",
        ],
    },
    "memory_taint_guard": {
        "section_files": [
            "06_multi_turn_context_pollution.jsonl",
            "09_combined_attack_chain.jsonl",
        ],
        "pack_files": [],
        "attack_stages": ["multi_turn", "chain"],
        "attack_surfaces": ["多轮上下文污染", "记忆注入", "延迟触发链路"],
        "attack_families": [
            "memory-injection",
            "chain-poisoning",
            "workflow-hijacking",
            "multi-stage",
            "process-hijacking",
            "system-compromise",
        ],
    },
    "output_redaction_gate": {
        "section_files": ["07_output_leakage_and_redaction.jsonl"],
        "pack_files": [],
        "attack_stages": ["output"],
        "attack_surfaces": ["Secrets 泄露", "训练数据回放", "路径与凭据暴露"],
        "attack_families": [
            "data-exfiltration",
            "model-extraction",
            "model-inversion",
            "training_data_replay_cloze",
            "training_data_replay_completion",
            "string_assembly_exfiltration",
            "membership-inference",
            "renderer_image_exfiltration",
            "markdown_uri_data_exfiltration",
            "playground_markdown_exfiltration",
        ],
    },
    "approval_integrity_gate": {
        "section_files": [
            "08_approval_bypass_social_engineering.jsonl",
            "09_combined_attack_chain.jsonl",
            "04_protected_paths_skills_plugins.jsonl",
        ],
        "pack_files": [],
        "attack_stages": ["authorization", "chain"],
        "attack_surfaces": ["审批绕过", "社会工程诱导", "高风险动作确认"],
        "attack_families": [
            "persuasion_social_engineering",
            "harmful_goal",
            "workflow-hijacking",
            "plugin-abuse_disabled-plugin-bypass",
            "mcp-tool-chain_shadow-approval",
            "cross-plugin_auth-hop",
            "rbac_access_bypass",
        ],
    },
}


def build_defense_coverage_map(defense_type: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    hint = DEFENSE_COVERAGE_HINTS.get(defense_type, {})
    config = config or {}

    section_files = _normalize_name_list(hint.get("section_files") or [])
    pack_files = _normalize_name_list(hint.get("pack_files") or [])
    attack_stages = _normalize_name_list([*(hint.get("attack_stages") or []), *(config.get("stages") or [])])
    attack_families = _normalize_name_list([*(hint.get("attack_families") or []), *(config.get("families") or [])])
    attack_surfaces = _normalize_display_list(hint.get("attack_surfaces") or [])

    matched_sections = _resolve_section_targets(section_files)
    matched_packs = _resolve_pack_targets(pack_files)
    matched_ids = _matched_sample_ids(
        matched_sections=matched_sections,
        matched_packs=matched_packs,
        attack_families=attack_families,
        attack_stages=attack_stages,
    )

    summary_parts = []
    if matched_sections:
        summary_parts.append(f"{len(matched_sections)} 个章节")
    if matched_packs:
        summary_parts.append(f"{len(matched_packs)} 个专项包")
    summary_parts.append(f"{len(matched_ids)} 条样本")

    return {
        "summary_text": f"主要覆盖 {' / '.join(summary_parts)}",
        "sample_count": len(matched_ids),
        "section_count": len(matched_sections),
        "pack_count": len(matched_packs),
        "matched_sections": matched_sections,
        "matched_packs": matched_packs,
        "attack_surfaces": attack_surfaces,
        "attack_families": attack_families,
        "attack_stages": attack_stages,
    }


@lru_cache
def _section_lookup() -> dict[str, dict[str, Any]]:
    return {Path(str(item.get("catalog_file") or "")).name.lower(): dict(item) for item in section_index()}


@lru_cache
def _pack_lookup() -> dict[str, dict[str, Any]]:
    return {Path(str(item.get("pack_file") or "")).name.lower(): dict(item) for item in focused_pack_index()}


@lru_cache
def _all_samples() -> tuple[dict[str, Any], ...]:
    return tuple(query_samples())


@lru_cache
def _pack_sample_ids(pack_file_name: str) -> tuple[str, ...]:
    pack_meta = _pack_lookup().get(pack_file_name.lower())
    if not pack_meta:
        return tuple()
    items = query_samples(pack=str(pack_meta.get("pack_name") or pack_file_name))
    return tuple(str(item.get("id")) for item in items if item.get("id"))


def _resolve_section_targets(section_files: list[str]) -> list[dict[str, Any]]:
    lookup = _section_lookup()
    targets: list[dict[str, Any]] = []
    for file_name in section_files:
        item = lookup.get(file_name.lower())
        if item is None:
            continue
        targets.append(
            {
                "label": str(item.get("section_name") or file_name),
                "value": file_name,
                "entry_count": int(item.get("entry_count") or 0),
                "risk_level": str(item.get("risk_level") or ""),
                "attack_stage": str(item.get("attack_stage") or ""),
            }
        )
    return targets


def _resolve_pack_targets(pack_files: list[str]) -> list[dict[str, Any]]:
    lookup = _pack_lookup()
    targets: list[dict[str, Any]] = []
    for file_name in pack_files:
        item = lookup.get(file_name.lower())
        if item is None:
            continue
        targets.append(
            {
                "label": str(item.get("pack_name") or file_name),
                "value": file_name,
                "entry_count": int(item.get("entry_count") or 0),
                "test_mode": str(item.get("test_mode") or ""),
            }
        )
    return targets


def _matched_sample_ids(
    *,
    matched_sections: list[dict[str, Any]],
    matched_packs: list[dict[str, Any]],
    attack_families: list[str],
    attack_stages: list[str],
) -> set[str]:
    section_names = {str(item["label"]) for item in matched_sections}
    pack_ids = {
        sample_id
        for item in matched_packs
        for sample_id in _pack_sample_ids(str(item["value"]))
    }
    family_set = {item.lower() for item in attack_families}
    stage_set = {item.lower() for item in attack_stages}

    matched_ids: set[str] = set(pack_ids)
    for item in _all_samples():
        sample_id = str(item.get("id") or "").strip()
        if not sample_id:
            continue

        if str(item.get("mapped_section") or "") in section_names:
            matched_ids.add(sample_id)
            continue

        if str(item.get("attack_family") or "").lower() in family_set:
            matched_ids.add(sample_id)
            continue

        if str(item.get("attack_stage") or "").lower() in stage_set:
            matched_ids.add(sample_id)

    return matched_ids


def _normalize_name_list(values: list[Any]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = Path(str(value or "")).name.strip().lower()
        if item and item not in normalized:
            normalized.append(item)
    return normalized


def _normalize_display_list(values: list[Any]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in normalized:
            normalized.append(item)
    return normalized
