from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import configure_test_environment


def _force_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


CASE_DESCRIPTION_OVERRIDES = {
    "test_admin_login_and_me": "验证管理员登录后可以读取当前用户信息、角色和页面权限。",
    "test_qq_email_alert_configuration_and_test_send": "验证 QQ 邮件告警配置可以保存，并且测试邮件会按配置发出。",
    "test_runtime_callbacks_require_platform_login": "验证运行时任务回调接口必须携带平台登录凭据。",
    "test_runtime_activation_exchange_does_not_require_platform_login": "验证运行时激活码交换接口无需平台登录即可完成激活。",
    "test_openclaw_target_creation_uses_runtime_profile": "验证创建 OpenClaw 目标时会使用运行时桥接配置档案。",
    "test_openclaw_target_test_uses_online_runtime_bridge": "验证 OpenClaw 目标连通性测试会识别在线运行时桥接。",
    "test_mcp_runtime_authorize_issues_ticket_and_complete_consumes_it": "验证 MCP 运行时授权会签发执行票据，并在完成回调时消费票据。",
    "test_mcp_runtime_authorize_denies_unregistered_capability_and_scope_escalation": "验证 MCP 运行时授权会拒绝未注册能力和越权 scope。",
    "test_openclaw_default_mcp_policy_is_strict_and_hardened": "验证 OpenClaw 默认 MCP 策略保持严格和加固状态。",
    "test_mcp_tool_result_without_ticket_is_denied": "验证没有 MCP 票据的工具结果会被拒绝。",
    "test_ai_endpoint_mcp_policy_management_roundtrip_and_template_apply": "验证 AI 端点 MCP 策略管理支持保存、读取和应用模板。",
    "test_task_execution_and_report_export": "验证任务执行完成后可以生成并导出安全报告。",
    "test_worker_falls_back_to_rules_when_ai_review_provider_fails": "验证 AI 复核 Provider 失败时 Worker 会回退到规则引擎结果。",
    "test_attack_lab_executes_against_selected_ai_endpoint": "验证攻击实验室会调用用户选定的 AI 端点执行测试。",
    "test_attack_lab_uses_openclaw_runtime_executor_when_runtime_is_bound": "验证绑定 OpenClaw 运行时时攻击实验室会使用运行时执行器。",
    "test_skill_scan_uses_remote_runtime_executor_when_openclaw_runtime_is_bound": "验证绑定 OpenClaw 运行时时技能扫描会使用远程运行时执行器。",
    "test_ai_review_uses_system_configured_reviewer_endpoint": "验证 AI 复核使用系统配置的独立复核端点。",
    "test_ai_review_cannot_downgrade_intercepted_rule_result": "验证 AI 复核不能把已拦截的规则结果降级为放行。",
    "test_skill_import_preview_import_and_scan": "验证技能目录预览、导入和扫描流程可以完整跑通。",
    "test_system_actions_produce_artifact_paths": "验证系统操作会生成可访问的导出或备份文件路径。",
    "test_request_activation_clears_platform_password_and_syncs_ai_binding": "验证请求运行时激活后会清理平台密码并同步 AI 绑定信息。",
    "test_reset_runtime_for_reactivation_clears_credentials_but_keeps_binding": "验证重新激活运行时时会清理凭据但保留 AI 绑定。",
    "test_issue_activation_code_updates_runtime_state": "验证签发激活码后运行时状态和绑定信息会更新。",
    "test_security_headers_are_applied": "验证健康检查响应包含预期的安全响应头。",
    "test_trusted_host_middleware_blocks_untrusted_host": "验证可信 Host 中间件会阻止未信任 Host。",
    "test_sensitive_query_values_are_redacted": "验证 URL 查询参数中的敏感值会被脱敏。",
    "test_validation_errors_redact_sensitive_inputs": "验证请求校验错误不会泄露敏感输入内容。",
    "test_production_config_rejects_wildcards_and_debug_details": "验证生产配置会拒绝通配 Host 和调试错误详情。",
    "test_login_rate_limit_blocks_repeated_attempts": "验证登录接口会限制连续失败尝试。",
    "test_public_runtime_register_rate_limit_blocks_repeated_attempts": "验证公开运行时注册接口会限制重复失败请求。",
    "test_http_request_body_limit_rejects_oversized_payload": "验证超大请求体会被 HTTP 请求体限制拒绝。",
    "test_internal_errors_are_redacted_in_client_response": "验证内部异常响应不会把敏感错误细节返回给客户端。",
    "test_report_download_recovers_from_invalid_stored_path": "验证报告下载遇到非法存储路径时会修复并恢复。",
    "test_openclaw_chat_is_not_classified_as_prompt_injection_by_default": "验证普通 OpenClaw 聊天默认不会被误判为提示词注入。",
    "test_broad_security_terms_do_not_trigger_rule_hits_by_themselves": "验证宽泛安全术语本身不会触发规则命中。",
    "test_quoted_attack_examples_in_security_docs_do_not_trigger_hits": "验证安全文档中引用的攻击示例不会误触发命中。",
    "test_mcp_discussion_text_does_not_trigger_workspace_scan_by_keyword_alone": "验证仅讨论 MCP 关键词不会触发工作区扫描。",
    "test_benign_approval_flow_discussion_does_not_trigger_token_reuse_hits": "验证正常审批流程讨论不会误触发令牌复用规则。",
    "test_low_signal_roleplay_term_without_attack_context_does_not_trigger_hits": "验证没有攻击上下文的低信号角色扮演术语不会触发命中。",
    "test_benign_multi_turn_context_does_not_trigger_memory_guard": "验证正常多轮上下文不会触发记忆防护规则。",
    "test_openclaw_prompt_injection_still_hits_rules": "验证 OpenClaw 提示词注入样本仍会命中防护规则。",
    "test_chinese_prompt_injection_phrase_hits_rules": "验证中文提示词注入短语会命中对应规则。",
    "test_explicit_mcp_override_language_still_hits_rules": "验证显式 MCP 覆盖语言仍会命中规则。",
    "test_approval_bypass_and_ticket_reuse_language_hits_rules": "验证审批绕过和票据复用话术会命中规则。",
    "test_multi_turn_context_persistence_attack_hits_memory_guards": "验证多轮上下文持久化攻击会命中记忆防护规则。",
    "test_secret_egress_phrase_hits_output_and_exfiltration_guards": "验证密钥外传话术会命中输出和外传防护规则。",
    "test_tool_description_payload_is_scanned_from_request_excerpt": "验证工具描述中的恶意载荷会从请求摘要中被扫描出来。",
    "test_output_replay_family_hits_output_guards": "验证输出重放攻击家族会命中输出防护规则。",
    "test_authorization_family_hits_approval_guard_without_literal_phrase": "验证授权阶段攻击即使没有字面绕过短语也会命中审批防护。",
    "test_function_calling_family_hits_tool_permission_guards": "验证 Function Calling 攻击家族会命中工具权限防护。",
    "test_security_event_report_view_renders_pattern_location_label": "验证安全事件报告视图会渲染规则命中位置标签。",
    "test_build_task_guard_trace_exposes_ai_review_fields": "验证任务防护链路会展示 AI 复核字段。",
    "test_build_task_guard_trace_keeps_ai_review_fallback_without_authorization": "验证没有授权信息时防护链路仍保留 AI 复核回退状态。",
    "test_concurrent_email_registration_flows": "验证多个邮件注册流程并发执行时验证码隔离、注册和登录都成功。",
    "test_concurrent_all_feature_flows": "验证认证、用户、AI目标、防御配置、MCP、网关、Runtime、任务、事件、报告、Skill、资产和系统设置等主要功能链路可以并发执行。",
    "test_email_register_and_reset_password_flow": "验证邮件验证码注册和邮件验证码重置密码完整流程。",
    "test_auth_verification_email_does_not_require_digest_recipients": "验证认证验证码邮件不依赖告警摘要收件人配置。",
}


class ChineseTablePytestPlugin:
    def __init__(self) -> None:
        self.started_at = time.perf_counter()
        self.collected: dict[str, int] = defaultdict(int)
        self.items: dict[str, dict[str, Any]] = {}
        self.collection_errors: list[dict[str, str]] = []
        self.warnings: list[str] = []

    def pytest_collection_finish(self, session) -> None:
        for item in session.items:
            path = _display_path(Path(str(item.path)))
            self.collected[path] += 1
            self.items.setdefault(
                item.nodeid,
                {
                    "script": path,
                    "case": item.nodeid.split("::", 1)[-1],
                    "description": _case_description(item),
                    "status": "未运行",
                    "duration": 0.0,
                    "detail": "",
                },
            )

    def pytest_collectreport(self, report) -> None:
        if report.failed:
            nodeid = str(report.nodeid)
            detail = _short_detail(str(report.longrepr))
            self.collection_errors.append(
                {
                    "脚本": _display_path(Path(nodeid.split("::", 1)[0])),
                    "阶段": "收集",
                    "详情": detail,
                }
            )

    def pytest_runtest_logreport(self, report) -> None:
        item = self.items.setdefault(
            report.nodeid,
            {
                "script": _display_path(Path(str(report.location[0]))),
                "case": report.nodeid.split("::", 1)[-1],
                "description": _describe_case_name(report.nodeid.split("::", 1)[-1]),
                "status": "未运行",
                "duration": 0.0,
                "detail": "",
            },
        )
        item["duration"] += float(getattr(report, "duration", 0.0) or 0.0)

        if report.failed:
            item["status"] = "失败"
            item["detail"] = _short_detail(getattr(report, "longreprtext", str(report.longrepr)))
            return

        if report.skipped and item["status"] != "失败":
            item["status"] = "跳过"
            item["detail"] = _short_detail(str(report.longrepr))
            return

        if report.when == "call" and report.passed and item["status"] not in {"失败", "跳过"}:
            item["status"] = "通过"

    def pytest_warning_recorded(self, warning_message, when, nodeid, location) -> None:
        self.warnings.append(str(warning_message.message))

    def summary_rows(self) -> list[dict[str, str]]:
        grouped: dict[str, dict[str, Any]] = {}
        for script, count in self.collected.items():
            grouped[script] = {
                "脚本": script,
                "收集": count,
                "通过": 0,
                "失败": 0,
                "跳过": 0,
                "耗时(秒)": 0.0,
                "结果": "通过",
            }

        for item in self.items.values():
            script = str(item["script"])
            row = grouped.setdefault(
                script,
                {
                    "脚本": script,
                    "收集": 0,
                    "通过": 0,
                    "失败": 0,
                    "跳过": 0,
                    "耗时(秒)": 0.0,
                    "结果": "通过",
                },
            )
            status = str(item["status"])
            if status == "通过":
                row["通过"] += 1
            elif status == "跳过":
                row["跳过"] += 1
            elif status == "失败":
                row["失败"] += 1
            row["耗时(秒)"] += float(item["duration"])

        for error in self.collection_errors:
            script = error["脚本"]
            row = grouped.setdefault(
                script,
                {
                    "脚本": script,
                    "收集": 0,
                    "通过": 0,
                    "失败": 0,
                    "跳过": 0,
                    "耗时(秒)": 0.0,
                    "结果": "失败",
                },
            )
            row["失败"] += 1

        rows = []
        for row in grouped.values():
            result = "通过" if int(row["失败"]) == 0 else "失败"
            rows.append(
                {
                    "脚本": str(row["脚本"]),
                    "收集": str(row["收集"]),
                    "通过": str(row["通过"]),
                    "失败": str(row["失败"]),
                    "跳过": str(row["跳过"]),
                    "耗时(秒)": f"{float(row['耗时(秒)']):.2f}",
                    "结果": result,
                }
            )
        return sorted(rows, key=lambda row: row["脚本"])

    def case_rows(self) -> list[dict[str, str]]:
        rows = []
        for nodeid, item in self.items.items():
            status = str(item["status"])
            detail = str(item["detail"] or "")
            if not detail:
                if status == "通过":
                    detail = "实际结果符合预期"
                elif status == "跳过":
                    detail = "该用例被跳过"
                else:
                    detail = "-"
            rows.append(
                {
                    "脚本": str(item["script"]),
                    "用例": str(item.get("case") or nodeid.split("::", 1)[-1]),
                    "做了什么测试": str(item.get("description") or _describe_case_name(nodeid)),
                    "结果": status,
                    "耗时(秒)": f"{float(item['duration']):.2f}",
                    "详情": detail,
                }
            )
        return sorted(rows, key=lambda row: (row["脚本"], row["用例"]))

    def failure_rows(self) -> list[dict[str, str]]:
        rows = [
            {
                "脚本": error["脚本"],
                "用例": "-",
                "阶段": error["阶段"],
                "详情": error["详情"],
            }
            for error in self.collection_errors
        ]
        for nodeid, item in self.items.items():
            if item["status"] == "失败":
                rows.append(
                    {
                        "脚本": str(item["script"]),
                        "用例": nodeid.split("::", 1)[-1],
                        "阶段": "执行",
                        "详情": str(item["detail"]),
                    }
                )
        return rows

    def total_row(self, exit_code: int) -> dict[str, str]:
        rows = self.summary_rows()
        collected = sum(int(row["收集"]) for row in rows)
        passed = sum(int(row["通过"]) for row in rows)
        failed = sum(int(row["失败"]) for row in rows)
        skipped = sum(int(row["跳过"]) for row in rows)
        elapsed = time.perf_counter() - self.started_at
        return {
            "脚本数": str(len(rows)),
            "收集": str(collected),
            "通过": str(passed),
            "失败": str(failed),
            "跳过": str(skipped),
            "警告": str(len(self.warnings)),
            "总耗时(秒)": f"{elapsed:.2f}",
            "退出码": str(exit_code),
            "结果": "通过" if exit_code == 0 and failed == 0 else "失败",
        }


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    configure_test_environment()
    parser = argparse.ArgumentParser(description="以中文表格形式运行后端测试。")
    parser.add_argument("paths", nargs="*", help="测试文件或目录，默认运行 backend/tests")
    parser.add_argument("--keyword", "-k", default="", help="pytest -k 表达式")
    parser.add_argument("--maxfail", type=int, default=0, help="失败到指定数量后停止，0 表示不限制")
    args = parser.parse_args(argv)

    paths = args.paths or [str(Path(__file__).resolve().parent)]
    pytest_args = [str(Path(path)) for path in paths]
    pytest_args.extend(["-q", "--disable-warnings", "--tb=short", "--no-header", "--no-summary"])
    if args.keyword:
        pytest_args.extend(["-k", args.keyword])
    if args.maxfail > 0:
        pytest_args.append(f"--maxfail={args.maxfail}")

    try:
        import pytest
    except ImportError:
        print_table(
            "测试汇总",
            [
                {
                    "脚本数": "0",
                    "收集": "0",
                    "通过": "0",
                    "失败": "1",
                    "跳过": "0",
                    "警告": "0",
                    "总耗时(秒)": "0.00",
                    "退出码": "1",
                    "结果": "失败：未安装 pytest",
                }
            ],
        )
        return 1

    test_scripts = _resolve_test_scripts(args.paths)
    if not test_scripts:
        print_table(
            "测试汇总",
            [
                {
                    "脚本数": "0",
                    "收集": "0",
                    "通过": "0",
                    "失败": "1",
                    "跳过": "0",
                    "警告": "0",
                    "总耗时(秒)": "0.00",
                    "退出码": "1",
                    "结果": "失败：未找到测试脚本",
                }
            ],
        )
        return 1

    if len(test_scripts) == 1 and _all_inputs_are_files(args.paths):
        plugin = ChineseTablePytestPlugin()
        exit_code = _run_pytest_once(pytest, pytest_args, plugin)
        _emit_pytest_tables(exit_code, plugin)
        return exit_code

    return _run_test_scripts_isolated(test_scripts, args)


def _run_pytest_once(pytest_module, pytest_args: list[str], plugin: ChineseTablePytestPlugin) -> int:
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        return int(pytest_module.main(pytest_args, plugins=[plugin]))


def _emit_pytest_tables(exit_code: int, plugin: ChineseTablePytestPlugin) -> None:
    print_table("测试汇总", [plugin.total_row(exit_code)])
    print_table("脚本结果", plugin.summary_rows())
    print_table("用例明细", plugin.case_rows())

    failures = plugin.failure_rows()
    if failures:
        print_table("失败详情", failures)


def _run_test_scripts_isolated(test_scripts: list[Path], args: argparse.Namespace) -> int:
    results: list[dict[str, str]] = []
    exit_code = 0
    for script in test_scripts:
        started_at = time.perf_counter()
        print_table(
            "脚本开始",
            [
                {
                    "脚本": _display_path(script),
                    "运行方式": "单独进程",
                }
            ],
        )
        sys.stdout.flush()
        child_args = [str(Path(__file__).resolve()), str(script)]
        if args.keyword:
            child_args.extend(["--keyword", args.keyword])
        if args.maxfail > 0:
            child_args.extend(["--maxfail", str(args.maxfail)])

        completed = subprocess.run(
            [sys.executable, *child_args],
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.stdout:
            print(completed.stdout, end="")
        child_exit = int(completed.returncode)
        elapsed = time.perf_counter() - started_at
        if child_exit != 0:
            exit_code = child_exit
        results.append(
            {
                "脚本": _display_path(script),
                "状态": "通过" if child_exit == 0 else "失败",
                "退出码": str(child_exit),
                "耗时(秒)": f"{elapsed:.2f}",
            }
        )

    print_table("目录汇总", results)
    return exit_code


def _resolve_test_scripts(paths: list[str]) -> list[Path]:
    if not paths:
        return _discover_test_scripts([Path(__file__).resolve().parent])

    resolved_paths = [Path(path).resolve() for path in paths]
    if any(path.is_dir() for path in resolved_paths):
        return _discover_test_scripts(resolved_paths)
    return [path for path in resolved_paths if path.name.startswith("test_") and path.suffix == ".py"]


def _discover_test_scripts(paths: list[Path]) -> list[Path]:
    scripts: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path.is_file() and path.name.startswith("test_") and path.suffix == ".py":
            if path not in seen:
                scripts.append(path)
                seen.add(path)
            continue
        if not path.is_dir():
            continue
        for script in sorted(path.rglob("test_*.py")):
            if script in seen:
                continue
            scripts.append(script)
            seen.add(script)
    return sorted(scripts)


def _all_inputs_are_files(paths: list[str]) -> bool:
    if not paths:
        return False
    return all(Path(path).resolve().is_file() for path in paths)


def print_table(title: str, rows: list[dict[str, str]]) -> None:
    print(f"\n### {title}")
    if not rows:
        print("| 结果 |")
        print("|---|")
        print("| 无 |")
        return

    headers = list(rows[0].keys())
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(_cell(row.get(header, "")) for header in headers) + " |")


def _cell(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = text.replace("|", "\\|")
    return text[:240] + ("..." if len(text) > 240 else "")


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except Exception:
        return path.as_posix()


def _short_detail(detail: str) -> str:
    lines = [line.strip() for line in detail.splitlines() if line.strip()]
    if not lines:
        return "-"
    return " / ".join(lines[-3:])


def _case_description(item: Any) -> str:
    function = getattr(item, "function", None)
    doc = getattr(function, "__doc__", None)
    if doc:
        first_line = str(doc).strip().splitlines()[0].strip()
        if first_line:
            return first_line
    return _describe_case_name(str(getattr(item, "name", "") or item.nodeid))


def _describe_case_name(raw_name: str) -> str:
    name = raw_name.split("::")[-1]
    if "[" in name:
        name = name.split("[", 1)[0]
    if name in CASE_DESCRIPTION_OVERRIDES:
        return CASE_DESCRIPTION_OVERRIDES[name]
    if name.startswith("test_"):
        name = name[5:]

    phrase_map = {
        "activation": "激活",
        "admin": "管理员",
        "ai": "AI",
        "alert": "告警",
        "alone": "单独触发",
        "approval": "审批",
        "applied": "已生效",
        "apply": "应用",
        "asset": "资产",
        "attack": "攻击",
        "auth": "认证",
        "authorization": "授权",
        "authorize": "授权",
        "benign": "正常请求",
        "binding": "绑定",
        "body": "请求体",
        "bridge": "桥接",
        "broad": "宽泛",
        "bypass": "绕过",
        "callback": "回调",
        "callbacks": "回调",
        "cannot": "不能",
        "capability": "能力",
        "chat": "聊天",
        "chinese": "中文",
        "classified": "分类",
        "clears": "清理",
        "complete": "完成",
        "consumes": "消费",
        "context": "上下文",
        "concurrent": "并发",
        "config": "配置",
        "configuration": "配置",
        "configured": "已配置",
        "creation": "创建",
        "credentials": "凭据",
        "default": "默认",
        "denied": "拒绝",
        "denies": "拒绝",
        "digest": "摘要",
        "discussion": "讨论",
        "downgrade": "降级",
        "download": "下载",
        "egress": "外传",
        "email": "邮件",
        "endpoint": "端点",
        "entry": "入口",
        "errors": "错误",
        "escalation": "越权",
        "execution": "执行",
        "executor": "执行器",
        "examples": "示例",
        "exchange": "交换",
        "export": "导出",
        "exposes": "暴露",
        "explicit": "显式",
        "fallback": "回退",
        "falls": "回退",
        "family": "家族",
        "fields": "字段",
        "flow": "流程",
        "flows": "流程",
        "function": "函数",
        "guards": "防护规则",
        "gateway": "网关",
        "guard": "防护",
        "hardening": "加固",
        "headers": "响应头",
        "helper": "辅助函数",
        "helpers": "辅助函数",
        "import": "导入",
        "injection": "注入",
        "internal": "内部",
        "invalid": "无效",
        "issue": "签发",
        "issues": "签发",
        "keeps": "保留",
        "keyword": "关键词",
        "lab": "实验室",
        "language": "语言",
        "literal": "字面短语",
        "location": "位置",
        "login": "登录",
        "mcp": "MCP",
        "me": "当前用户",
        "memory": "记忆",
        "middleware": "中间件",
        "multi": "多轮",
        "online": "在线",
        "openclaw": "OpenClaw",
        "output": "输出",
        "override": "覆盖",
        "password": "密码",
        "payload": "载荷",
        "persistence": "持久化",
        "platform": "平台",
        "policy": "策略",
        "preview": "预览",
        "profile": "配置档案",
        "provider": "Provider",
        "public": "公开接口",
        "prompt": "提示词",
        "production": "生产环境",
        "qq": "QQ",
        "quality": "质量",
        "quoted": "引用",
        "rate": "频率",
        "reactivation": "重新激活",
        "recipients": "收件人",
        "recovers": "恢复",
        "redacted": "脱敏",
        "rejects": "拒绝",
        "register": "注册",
        "registration": "注册",
        "report": "报告",
        "require": "要求",
        "requires": "要求",
        "request": "请求",
        "reset": "重置",
        "result": "结果",
        "reuse": "复用",
        "review": "复核",
        "roleplay": "角色扮演",
        "roundtrip": "往返读写",
        "rule": "规则",
        "rules": "规则",
        "runtime": "运行时",
        "scan": "扫描",
        "scanned": "被扫描",
        "script": "脚本",
        "security": "安全",
        "selected": "选定",
        "sensitive": "敏感",
        "send": "发送",
        "signal": "低信号",
        "skill": "技能",
        "strict": "严格",
        "syncs": "同步",
        "system": "系统",
        "target": "目标",
        "task": "任务",
        "template": "模板",
        "terms": "术语",
        "test": "测试",
        "text": "文本",
        "ticket": "票据",
        "tool": "工具",
        "token": "令牌",
        "trace": "链路",
        "trusted": "可信",
        "unregistered": "未注册",
        "updates": "更新",
        "uses": "使用",
        "values": "值",
        "validation": "校验",
        "when": "当",
        "wildcards": "通配符",
        "without": "无",
        "workspace": "工作区",
        "worker": "Worker",
    }
    stop_words = {"and", "as", "by", "does", "for", "from", "in", "is", "not", "of", "the", "to", "with"}
    words = [word for word in name.split("_") if word and word not in stop_words]
    translated = [phrase_map.get(word, word) for word in words]
    if not translated:
        return raw_name
    return "验证" + " / ".join(translated)


if __name__ == "__main__":
    raise SystemExit(main())
