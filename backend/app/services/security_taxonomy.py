from __future__ import annotations

from typing import Any

Tone = str


RISK_LEVEL_META: dict[str, dict[str, str]] = {
    "critical": {"label": "严重", "tone": "danger"},
    "high": {"label": "高危", "tone": "danger"},
    "medium": {"label": "中危", "tone": "warn"},
    "low": {"label": "低危", "tone": "info"},
}

ATTACK_STAGE_META: dict[str, dict[str, str]] = {
    "input": {"label": "输入阶段", "tone": "danger"},
    "external_content": {"label": "外部内容阶段", "tone": "warn"},
    "tool_use": {"label": "工具调用阶段", "tone": "danger"},
    "authorization": {"label": "授权审批阶段", "tone": "warn"},
    "multi_turn": {"label": "多轮上下文阶段", "tone": "warn"},
    "output": {"label": "输出阶段", "tone": "safe"},
    "chain": {"label": "组合攻击链阶段", "tone": "danger"},
}

TEST_MODE_META: dict[str, dict[str, str]] = {
    "single_turn": {"label": "单轮测试", "tone": "info"},
    "multi_turn": {"label": "多轮测试", "tone": "warn"},
}

SOURCE_REPO_LABELS: dict[str, str] = {
    "cyberark/FuzzyAI": "CyberArk FuzzyAI 攻击集",
    "JailbreakBench/jailbreakbench": "JailbreakBench 基准集",
    "NVIDIA/garak": "NVIDIA garak 攻击集",
    "preambleai/prompt-injector": "Preamble Prompt Injector",
    "promptfoo/promptfoo": "Promptfoo 攻击集",
    "verazuo/jailbreak_llms": "Jailbreak LLMs 样本集",
}

ATTACK_SECTION_META: dict[str, dict[str, Any]] = {
    "直接 Prompt Injection": {
        "primary_key": "input_injection",
        "primary_label": "输入与越狱攻击",
        "surface_key": "prompt_input",
        "surface_label": "提示输入面",
        "section_key": "direct_prompt_injection",
    },
    "审批绕过与社会工程测试": {
        "primary_key": "approval_bypass",
        "primary_label": "审批与社会工程攻击",
        "surface_key": "approval_chain",
        "surface_label": "审批链路面",
        "section_key": "approval_social_engineering",
    },
    "组合攻击链": {
        "primary_key": "attack_chain",
        "primary_label": "组合攻击链",
        "surface_key": "multi_stage_chain",
        "surface_label": "组合链路面",
        "section_key": "composite_attack_chain",
    },
    "未授权工具调用": {
        "primary_key": "tool_abuse",
        "primary_label": "工具与执行面攻击",
        "surface_key": "tool_execution",
        "surface_label": "工具执行面",
        "section_key": "unauthorized_tool_calls",
    },
    "受保护路径、技能、插件测试": {
        "primary_key": "protected_resource_abuse",
        "primary_label": "受保护资源攻击",
        "surface_key": "asset_skill_plugin",
        "surface_label": "路径 / Skill / 插件面",
        "section_key": "protected_paths_skills_plugins",
    },
    "间接 Prompt Injection": {
        "primary_key": "indirect_injection",
        "primary_label": "间接内容注入",
        "surface_key": "external_content",
        "surface_label": "检索与外部内容面",
        "section_key": "indirect_prompt_injection",
    },
    "多轮上下文污染": {
        "primary_key": "multi_turn_pollution",
        "primary_label": "多轮上下文污染",
        "surface_key": "memory_context",
        "surface_label": "记忆与上下文面",
        "section_key": "multi_turn_context_pollution",
    },
    "输出泄露与脱敏测试": {
        "primary_key": "output_exfiltration",
        "primary_label": "输出泄露与外传",
        "surface_key": "output_channel",
        "surface_label": "输出回显面",
        "section_key": "output_leakage_redaction",
    },
}

ATTACK_FAMILY_LABELS: dict[str, str] = {
    "adversarial-example": "对抗样本攻击",
    "chain-poisoning": "链路投毒",
    "code-injection": "代码注入",
    "coding_agent_automation-poisoning": "编码代理自动化投毒",
    "coding_agent_delayed-ci-exfil": "编码代理延迟 CI 外传",
    "coding_agent_network-egress-bypass": "编码代理网络出站绕过",
    "coding_agent_procfs-credential-read": "编码代理 Procfs 凭据读取",
    "coding_agent_repo-prompt-injection": "编码代理仓库提示注入",
    "coding_agent_sandbox-read-escape": "编码代理沙箱读逃逸",
    "coding_agent_sandbox-write-escape": "编码代理沙箱写逃逸",
    "coding_agent_secret-env-read": "编码代理环境密钥读取",
    "coding_agent_secret-file-read": "编码代理敏感文件读取",
    "coding_agent_steganographic-exfil": "编码代理隐写外传",
    "coding_agent_terminal-output-injection": "编码代理终端输出注入",
    "content-violation": "内容违规诱导",
    "cross-plugin": "跨插件攻击",
    "cross-plugin_auth-hop": "跨插件授权跳转",
    "cross-plugin_data-staging": "跨插件数据暂存",
    "cross-plugin_role-borrowing": "跨插件角色借用",
    "cross-plugin_summary-laundering": "跨插件摘要洗白",
    "data-exfiltration": "数据外传",
    "data-manipulation": "数据篡改",
    "data-poisoning": "数据投毒",
    "defense-bypass": "防护绕过",
    "direct-injection": "直接注入",
    "financial-fraud": "金融欺诈诱导",
    "formal-attack": "正式化攻击",
    "function-calling": "函数调用攻击",
    "function-calling_alias-bypass": "函数别名绕过",
    "function-calling_schema-smuggling": "函数 Schema 夹带",
    "gradient-attack": "梯度攻击",
    "harmful_goal": "有害目标诱导",
    "indirect-injection": "间接注入",
    "invisible_unicode_tag_injection": "隐形 Unicode 标签注入",
    "jailbreak_prompt": "越狱提示词",
    "legal-violation": "法律违规诱导",
    "markdown_javascript_injection": "Markdown JavaScript 注入",
    "markdown_uri_data_exfiltration": "Markdown URI 数据外传",
    "mcp-injection": "MCP 注入",
    "mcp-injection_authority-smuggling": "MCP 权限夹带",
    "mcp-injection_server-message-smuggling": "MCP 服务端消息夹带",
    "mcp-protocol": "MCP 协议攻击",
    "mcp-protocol_capability-spoof": "MCP 能力伪造",
    "mcp-protocol_session-rebind": "MCP 会话重绑",
    "mcp-tool-chain": "MCP 工具链攻击",
    "mcp-tool-chain_cross-server-hop": "MCP 跨服务链路跳转",
    "mcp-tool-chain_secret-staging": "MCP 密钥暂存",
    "mcp-tool-chain_shadow-approval": "MCP 影子审批",
    "membership-inference": "成员推断",
    "memory-injection": "记忆注入",
    "model-extraction": "模型抽取",
    "model-inversion": "模型反演",
    "model_specific_obfuscated_variant": "模型定向混淆变体",
    "multi-stage": "多阶段攻击",
    "output_format_coercion": "输出格式胁迫",
    "persuasion_social_engineering": "说服型社会工程",
    "playground_markdown_exfiltration": "Playground Markdown 外传",
    "plugin-abuse": "插件滥用",
    "plugin-abuse_disabled-plugin-bypass": "禁用插件绕过",
    "plugin-abuse_skill-proxy": "技能代理绕过",
    "process-hijacking": "流程劫持",
    "prompt-injection": "提示词注入",
    "rbac_access_bypass": "RBAC 权限绕过",
    "rendered_script_injection": "渲染脚本注入",
    "renderer_image_exfiltration": "渲染器图像外传",
    "role-confusion": "角色混淆",
    "string_assembly_exfiltration": "字符串拼接外传",
    "suffix_attack": "后缀越狱攻击",
    "system-compromise": "系统接管诱导",
    "tool-abuse": "工具滥用",
    "tool-poisoning": "工具投毒",
    "training_data_replay_cloze": "训练数据回放填空",
    "training_data_replay_completion": "训练数据回放补全",
    "transfer-attack": "迁移攻击",
    "universal-attack": "通用攻击",
    "vulnerability-introduction": "漏洞引入诱导",
    "workflow-hijacking": "工作流劫持",
    "zero-day": "零日诱导",
}

RULE_CATEGORY_META: dict[str, dict[str, Any]] = {
    "input_intent": {"label": "输入与意图防护", "order": 10, "tone": "danger"},
    "indirect_content": {"label": "间接内容与检索边界", "order": 20, "tone": "warn"},
    "tool_plugin_mcp": {"label": "工具 / Skill / MCP 治理", "order": 30, "tone": "danger"},
    "memory_context": {"label": "多轮上下文与记忆污染", "order": 40, "tone": "warn"},
    "output_exfiltration": {"label": "输出脱敏与外传防护", "order": 50, "tone": "safe"},
    "approval_integrity": {"label": "审批与授权完整性", "order": 60, "tone": "warn"},
    "runtime_audit": {"label": "运行时联动与审计", "order": 70, "tone": "info"},
    "ai_review": {"label": "AI 复核与二次研判", "order": 80, "tone": "info"},
}

CONTROL_META: dict[str, dict[str, Any]] = {
    "prompt_injection_firewall": {
        "label": "提示注入防火墙",
        "description": "识别直接 Prompt Injection、越狱、角色混淆和高风险输入指令。",
        "category_key": "input_intent",
        "surface_keys": ["prompt_input"],
        "stage_keys": ["input"],
    },
    "indirect_content_isolation": {
        "label": "间接内容隔离",
        "description": "隔离检索结果、网页片段、RAG 文档和工具回传中的不可信上下文。",
        "category_key": "indirect_content",
        "surface_keys": ["external_content", "tool_execution"],
        "stage_keys": ["external_content", "tool_use"],
    },
    "tool_permission_broker": {
        "label": "工具权限代理",
        "description": "限制文件系统、网络、命令执行和写入型工具的调用权限与范围。",
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["tool_execution", "asset_skill_plugin"],
        "stage_keys": ["tool_use", "authorization"],
    },
    "mcp_capability_binding": {
        "label": "MCP 能力绑定",
        "description": "校验 MCP server、capability、session 与 approval 的绑定关系。",
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["authorization", "tool_use"],
    },
    "cross_plugin_handoff_guard": {
        "label": "跨插件交接防护",
        "description": "约束跨插件 token 传递、角色借用和链路移交中的风险行为。",
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["authorization", "chain"],
    },
    "memory_taint_guard": {
        "label": "上下文污染防护",
        "description": "识别多轮记忆污染、延迟触发链路和长期上下文植入。",
        "category_key": "memory_context",
        "surface_keys": ["memory_context"],
        "stage_keys": ["multi_turn"],
    },
    "output_redaction_gate": {
        "label": "输出脱敏闸门",
        "description": "在输出前识别并脱敏 secrets、路径、PII 与敏感回放片段。",
        "category_key": "output_exfiltration",
        "surface_keys": ["output_channel"],
        "stage_keys": ["output"],
    },
    "approval_integrity_gate": {
        "label": "审批完整性校验",
        "description": "对审批绕过、社会工程诱导和高风险动作执行做二次确认。",
        "category_key": "approval_integrity",
        "surface_keys": ["approval_chain"],
        "stage_keys": ["authorization"],
    },
}

RULE_META: dict[str, dict[str, Any]] = {
    "source-trace": {
        "category_key": "runtime_audit",
        "surface_keys": ["prompt_input", "external_content", "tool_execution"],
        "stage_keys": ["input", "external_content", "tool_use"],
    },
    "memory-write-guard": {
        "category_key": "memory_context",
        "surface_keys": ["memory_context"],
        "stage_keys": ["multi_turn"],
    },
    "loop-guard": {
        "category_key": "runtime_audit",
        "surface_keys": ["tool_execution"],
        "stage_keys": ["tool_use", "chain"],
    },
    "tool-approval-gate": {
        "category_key": "approval_integrity",
        "surface_keys": ["tool_execution", "approval_chain"],
        "stage_keys": ["tool_use", "authorization"],
    },
    "mcp-session-bind": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["authorization", "tool_use"],
    },
    "cross-plugin-proof": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["authorization", "chain"],
    },
    "intent-scan": {
        "category_key": "input_intent",
        "surface_keys": ["prompt_input"],
        "stage_keys": ["input"],
    },
    "workspace-scan": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["tool_use", "authorization"],
    },
    "tool-result-scan": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["tool_execution"],
        "stage_keys": ["tool_use"],
    },
    "external-content-scan": {
        "category_key": "indirect_content",
        "surface_keys": ["external_content"],
        "stage_keys": ["external_content"],
    },
    "secret-pattern-scan": {
        "category_key": "output_exfiltration",
        "surface_keys": ["output_channel"],
        "stage_keys": ["output"],
    },
    "output-sanitize": {
        "category_key": "output_exfiltration",
        "surface_keys": ["output_channel"],
        "stage_keys": ["output"],
    },
    "approval-persuasion-scan": {
        "category_key": "approval_integrity",
        "surface_keys": ["approval_chain"],
        "stage_keys": ["authorization"],
    },
    "approval-social-engineering-scan": {
        "category_key": "approval_integrity",
        "surface_keys": ["approval_chain"],
        "stage_keys": ["authorization"],
    },
    "indirect-instruction-quarantine": {
        "category_key": "indirect_content",
        "surface_keys": ["external_content"],
        "stage_keys": ["external_content"],
    },
    "retrieval-boundary-scan": {
        "category_key": "indirect_content",
        "surface_keys": ["external_content"],
        "stage_keys": ["external_content"],
    },
    "tool-poisoning-scan": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["tool_execution", "asset_skill_plugin"],
        "stage_keys": ["tool_use", "authorization"],
    },
    "mcp-tool-poisoning-scan": {
        "category_key": "tool_plugin_mcp",
        "surface_keys": ["asset_skill_plugin"],
        "stage_keys": ["tool_use", "authorization"],
    },
    "prompt-leakage-scan": {
        "category_key": "output_exfiltration",
        "surface_keys": ["prompt_input", "output_channel"],
        "stage_keys": ["input", "output"],
    },
    "pii-exfiltration-scan": {
        "category_key": "output_exfiltration",
        "surface_keys": ["output_channel"],
        "stage_keys": ["output"],
    },
    "canary-leak-scan": {
        "category_key": "output_exfiltration",
        "surface_keys": ["output_channel"],
        "stage_keys": ["output"],
    },
    "memory-escalation-scan": {
        "category_key": "memory_context",
        "surface_keys": ["memory_context"],
        "stage_keys": ["multi_turn"],
    },
    "encoding-evasion-scan": {
        "category_key": "input_intent",
        "surface_keys": ["prompt_input", "external_content"],
        "stage_keys": ["input", "external_content"],
    },
    "ansi-control-scan": {
        "category_key": "input_intent",
        "surface_keys": ["prompt_input", "external_content"],
        "stage_keys": ["input", "external_content"],
    },
    "tool-call-audit": {
        "category_key": "runtime_audit",
        "surface_keys": ["tool_execution", "asset_skill_plugin", "approval_chain"],
        "stage_keys": ["tool_use", "authorization", "chain"],
    },
    "protected-agent-ai-review": {
        "category_key": "ai_review",
        "surface_keys": ["prompt_input", "external_content", "memory_context", "output_channel"],
        "stage_keys": ["input", "external_content", "multi_turn", "output"],
    },
}

SIGNAL_META: dict[str, dict[str, str]] = {
    "known_attack_family": {
        "label": "已知攻击家族",
        "detail": "样本或输入命中了平台已知攻击家族标签。",
        "tone": "danger",
    },
    "blocked_profile": {
        "label": "阻断型攻击画像",
        "detail": "命中了可直接拦截的高置信攻击画像。",
        "tone": "danger",
    },
    "critical_risk": {
        "label": "严重风险",
        "detail": "规则引擎综合判定为严重风险。",
        "tone": "danger",
    },
    "high_risk": {
        "label": "高风险",
        "detail": "规则引擎综合判定为高风险。",
        "tone": "danger",
    },
    "medium_risk": {
        "label": "中风险",
        "detail": "规则引擎综合判定为中风险。",
        "tone": "warn",
    },
    "prompt_injection_surface": {
        "label": "提示注入面",
        "detail": "输入内容呈现明显提示注入或越权诱导特征。",
        "tone": "danger",
    },
    "output_leak_surface": {
        "label": "输出泄露面",
        "detail": "响应或上下文存在敏感输出、提示词泄露或数据外传风险。",
        "tone": "warn",
    },
    "multi_turn_context": {
        "label": "多轮上下文面",
        "detail": "上下文呈现跨轮污染、延迟触发或长期记忆植入特征。",
        "tone": "warn",
    },
    "plugin_or_mcp_surface": {
        "label": "插件 / MCP 攻击面",
        "detail": "攻击链路涉及插件、Skill、MCP 或工具调用侧风险。",
        "tone": "danger",
    },
    "context_persistence_or_trigger_setup": {
        "label": "上下文持久化植入",
        "detail": "检测到试图把隐藏规则、审批继承或延迟触发条件写入后续轮次上下文。",
        "tone": "warn",
    },
    "context_attack_chain_detected": {
        "label": "多轮触发链路",
        "detail": "检测到上下文植入、延迟触发、跨轮激活或记忆污染组成的攻击链。",
        "tone": "danger",
    },
    "cross_turn_instruction_override": {
        "label": "跨轮指令覆盖",
        "detail": "检测到后续轮次利用前文埋点去覆盖既有规则或系统策略。",
        "tone": "danger",
    },
    "memory_persistence_setup": {
        "label": "记忆植入准备",
        "detail": "当前轮次包含要求长期记忆、隐藏规则或持久化执行条件的文本。",
        "tone": "warn",
    },
    "delayed_trigger_setup": {
        "label": "延迟触发准备",
        "detail": "当前轮次试图设置后续触发词、代码词或激活条件。",
        "tone": "warn",
    },
    "delayed_trigger_activation": {
        "label": "延迟触发激活",
        "detail": "后续轮次出现激活存量规则或执行隐藏动作的触发文本。",
        "tone": "danger",
    },
    "delayed_trigger_codeword_match": {
        "label": "触发词命中",
        "detail": "后续轮次出现与前文代码词或触发词匹配的上下文内容。",
        "tone": "danger",
    },
    "delayed_trigger_execution": {
        "label": "跨轮执行接续",
        "detail": "后续轮次在前文植入条件后继续请求执行越权或覆盖型动作。",
        "tone": "danger",
    },
    "cross_turn_override": {
        "label": "多轮覆盖语义",
        "detail": "多轮上下文中出现利用前文状态覆盖当前规则的攻击语义。",
        "tone": "warn",
    },
    "output_channel_attack_surface": {
        "label": "输出通道攻击面",
        "detail": "请求或样本已落在输出回显、泄露或编码外传阶段，需要对响应进行脱敏和外传审查。",
        "tone": "warn",
    },
    "sensitive_output_review": {
        "label": "敏感输出复核",
        "detail": "当前链路需要额外检查是否存在 secrets、PII、训练数据回放或绕过滤器的输出片段。",
        "tone": "warn",
    },
    "authorization_stage_attack_surface": {
        "label": "审批链路攻击面",
        "detail": "请求已进入审批、授权或人工确认边界，需要校验是否存在社工、伪授权或越权执行诱导。",
        "tone": "warn",
    },
    "tool_use_attack_surface": {
        "label": "工具调用攻击面",
        "detail": "请求已进入工具执行阶段，需要校验工具范围、参数权限和是否触发额外审批。",
        "tone": "danger",
    },
    "output_exfiltration_family": {
        "label": "输出外传家族",
        "detail": "样本家族表现为结果拼接、图像/URI 外传、密文编码外传或其它输出通道泄露路径。",
        "tone": "danger",
    },
    "output_coercion_family": {
        "label": "输出胁迫家族",
        "detail": "样本家族试图通过格式约束、逐字复述或输出控制来绕过防护并取回敏感内容。",
        "tone": "danger",
    },
    "training_or_model_replay_surface": {
        "label": "训练数据 / 模型回放面",
        "detail": "样本家族涉及训练数据复现、模型抽取、模型反演或成员推断等高风险输出请求。",
        "tone": "danger",
    },
    "tool_execution_family": {
        "label": "工具执行家族",
        "detail": "样本家族直接针对函数调用、工具执行、工作区写入或权限绕过链路。",
        "tone": "danger",
    },
    "tool_execution_workspace_surface": {
        "label": "工作区 / 能力面",
        "detail": "攻击链已落在 Skill、插件、MCP 或工作区能力边界，需要额外校验执行上下文。",
        "tone": "warn",
    },
    "approval_or_goal_escalation_surface": {
        "label": "目标升级 / 审批诱导面",
        "detail": "样本家族试图把危险目标、越权动作或组合攻击伪装成应被批准的正常请求。",
        "tone": "danger",
    },
}


def display_risk_label(value: str | None) -> str:
    key = str(value or "").strip().lower()
    return RISK_LEVEL_META.get(key, {}).get("label", value or "-")


def display_attack_stage_label(value: str | None) -> str:
    key = str(value or "").strip().lower()
    return ATTACK_STAGE_META.get(key, {}).get("label", value or "-")


def display_test_mode_label(value: str | None) -> str:
    key = str(value or "").strip().lower()
    return TEST_MODE_META.get(key, {}).get("label", value or "-")


def display_source_repo_label(value: str | None) -> str:
    key = str(value or "").strip()
    return SOURCE_REPO_LABELS.get(key, key or "-")


def display_attack_family_label(value: str | None) -> str:
    key = str(value or "").strip()
    if not key:
        return "-"
    if key in ATTACK_FAMILY_LABELS:
        return ATTACK_FAMILY_LABELS[key]
    return _humanize_code(key)


def display_policy_label(value: str | None) -> str:
    key = str(value or "").strip()
    if not key:
        return "未命名项"
    if key in CONTROL_META:
        return str(CONTROL_META[key]["label"])
    return RULE_META_LABEL_FALLBACKS.get(key, _humanize_code(key))


def display_policy_description(value: str | None) -> str:
    key = str(value or "").strip()
    if not key:
        return ""
    if key in CONTROL_META:
        return str(CONTROL_META[key]["description"])
    return RULE_DESCRIPTION_FALLBACKS.get(key, "")


RULE_META_LABEL_FALLBACKS: dict[str, str] = {
    "source-trace": "风险来源追踪",
    "memory-write-guard": "记忆写入守卫",
    "loop-guard": "循环调用限幅",
    "tool-approval-gate": "敏感工具审批门",
    "mcp-session-bind": "MCP 会话绑定",
    "cross-plugin-proof": "跨插件移交校验",
    "intent-scan": "输入意图扫描",
    "workspace-scan": "技能与插件扫描",
    "tool-result-scan": "工具结果扫描",
    "external-content-scan": "外部内容隔离扫描",
    "secret-pattern-scan": "敏感信息模式扫描",
    "output-sanitize": "输出脱敏",
    "approval-persuasion-scan": "审批诱导扫描",
    "approval-social-engineering-scan": "审批社工扫描",
    "indirect-instruction-quarantine": "间接指令隔离扫描",
    "retrieval-boundary-scan": "检索边界扫描",
    "tool-poisoning-scan": "工具投毒扫描",
    "mcp-tool-poisoning-scan": "MCP 能力投毒扫描",
    "prompt-leakage-scan": "提示词泄露扫描",
    "pii-exfiltration-scan": "PII 与密钥外传扫描",
    "canary-leak-scan": "蜜标泄露扫描",
    "memory-escalation-scan": "多轮污染扫描",
    "encoding-evasion-scan": "编码绕过扫描",
    "ansi-control-scan": "控制字符扫描",
    "tool-call-audit": "运行时联动审计",
    "protected-agent-ai-review": "AI 复核策略",
}

RULE_DESCRIPTION_FALLBACKS: dict[str, str] = {
    "source-trace": "记录高风险提示、工具结果和外部文档的上游来源，便于审计回放与归因。",
    "memory-write-guard": "拦截长期记忆和持久化存储中的高风险写入，防止污染带入后续轮次。",
    "loop-guard": "限制异常自循环工具调用和无收益重试，避免单次任务放大成持续风险。",
    "tool-approval-gate": "对写文件、发网络请求、执行命令和写数据库等动作要求显式审批或允许清单。",
    "mcp-session-bind": "校验 MCP server、capability、session 与审批票据是否一致，防止 capability spoof 和 session rebind。",
    "cross-plugin-proof": "要求跨插件跳转时携带可信来源证明，阻断 auth hop、role borrowing 和 summary laundering。",
    "intent-scan": "在输入阶段预检明显的 Prompt Injection、Jailbreak 和越权语义。",
    "workspace-scan": "扫描 workspace 中新增的技能、插件和 MCP capability，并纳入审核队列。",
    "tool-result-scan": "拦截工具输出中的提示注入、密钥痕迹、隐藏指令与额外上下文污染。",
    "external-content-scan": "对网页片段、RAG 文档、邮件和远程知识块打标签并执行二次风险扫描。",
    "secret-pattern-scan": "检测 API Key、令牌、凭据、内网路径和训练数据回放片段。",
    "output-sanitize": "在输出前处理文件位置、API 密钥片段、敏感路径和结构化泄露字段。",
    "approval-persuasion-scan": "识别社会工程、紧急借口和伪造授权措辞，阻断绕过审批链路的诱导文本。",
    "approval-social-engineering-scan": "识别利用紧急话术、伪造授权、角色混淆和人为施压绕过审批链的文本。",
    "indirect-instruction-quarantine": "识别来自网页、邮件、文档、附件和检索片段中的隐式指令，并将其标记为不可信上下文。",
    "retrieval-boundary-scan": "针对 RAG、搜索结果、知识库和外部内容建立边界，防止外部文本覆盖系统策略。",
    "tool-poisoning-scan": "识别工具输出、插件结果和工作区内容中的提示词注入、结果投毒和指令覆盖片段。",
    "mcp-tool-poisoning-scan": "识别 MCP capability 返回、会话重绑、伪造审批和跨插件调用中的高风险指令。",
    "prompt-leakage-scan": "识别系统提示词、开发者消息、隐藏指令和内部策略泄露请求。",
    "pii-exfiltration-scan": "识别 API Key、令牌、凭据、邮箱和敏感身份数据的导出、回显与拼接泄露。",
    "canary-leak-scan": "识别 canary token、诱饵凭据和测试密钥的外传信号。",
    "memory-escalation-scan": "识别跨轮记忆污染、延迟执行、长期上下文植入和未来轮次触发攻击。",
    "encoding-evasion-scan": "识别 base64、URL 编码、Unicode 转义、Hex 转义和混淆字符承载的攻击指令。",
    "ansi-control-scan": "识别零宽字符、ANSI 转义和不可见控制字符构造的隐藏指令或显示层绕过。",
    "tool-call-audit": "对关键 tool call、跨插件跳转、审批决策和高风险输出做留痕、回放与事后核查。",
    "protected-agent-ai-review": "对受保护 AI/Agent 在规则判定后执行二次 AI 风险复核。",
}


def build_sample_classification(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    turns = item.get("turns")
    if not isinstance(turns, list):
        turns = []

    section_label = str(item.get("mapped_section") or "").strip()
    section_meta = ATTACK_SECTION_META.get(section_label, {})
    family_key = str(item.get("attack_family") or "").strip()
    risk_key = str(item.get("risk_level") or "").strip().lower()
    stage_key = str(item.get("attack_stage") or "").strip().lower()
    mode_key = str(
        item.get("test_mode") or metadata.get("test_mode") or ("multi_turn" if turns else "single_turn")
    ).strip().lower()

    return {
        "primary_key": str(section_meta.get("primary_key") or "uncategorized"),
        "primary_label": str(section_meta.get("primary_label") or "未分类攻击面"),
        "section_key": str(section_meta.get("section_key") or _slugify_label(section_label or "section")),
        "section_label": section_label or "未分类章节",
        "family_key": family_key,
        "family_label": display_attack_family_label(family_key),
        "surface_key": str(section_meta.get("surface_key") or "unknown_surface"),
        "surface_label": str(section_meta.get("surface_label") or "未分类攻击面"),
        "risk_key": risk_key,
        "risk_label": display_risk_label(risk_key),
        "stage_key": stage_key,
        "stage_label": display_attack_stage_label(stage_key),
        "test_mode_key": mode_key,
        "test_mode_label": display_test_mode_label(mode_key),
        "source_label": display_source_repo_label(item.get("source_repo")),
    }


def build_section_classification(section_name: str, *, risk_level: str | None = None, attack_stage: str | None = None) -> dict[str, Any]:
    meta = ATTACK_SECTION_META.get(section_name, {})
    risk_key = str(risk_level or "").strip().lower()
    stage_key = str(attack_stage or "").strip().lower()
    return {
        "primary_key": str(meta.get("primary_key") or "uncategorized"),
        "primary_label": str(meta.get("primary_label") or "未分类攻击面"),
        "section_key": str(meta.get("section_key") or _slugify_label(section_name or "section")),
        "section_label": section_name or "未分类章节",
        "surface_key": str(meta.get("surface_key") or "unknown_surface"),
        "surface_label": str(meta.get("surface_label") or "未分类攻击面"),
        "risk_key": risk_key,
        "risk_label": display_risk_label(risk_key),
        "stage_key": stage_key,
        "stage_label": display_attack_stage_label(stage_key),
    }


def build_pack_classification(pack: dict[str, Any]) -> dict[str, Any]:
    section_name = str(pack.get("mapped_section") or "").strip()
    classification = build_section_classification(section_name)
    mode_key = str(pack.get("test_mode") or "").strip().lower()
    classification["test_mode_key"] = mode_key
    classification["test_mode_label"] = display_test_mode_label(mode_key)
    return classification


def build_catalog_group_summary(section_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for item in section_items:
        classification = build_section_classification(
            str(item.get("section_name") or ""),
            risk_level=str(item.get("risk_level") or ""),
            attack_stage=str(item.get("attack_stage") or ""),
        )
        group = summary.setdefault(
            classification["primary_key"],
            {
                "key": classification["primary_key"],
                "label": classification["primary_label"],
                "entry_count": 0,
                "section_count": 0,
                "sections": [],
            },
        )
        group["entry_count"] += int(item.get("entry_count") or 0)
        group["section_count"] += 1
        group["sections"].append(classification["section_label"])

    return sorted(summary.values(), key=lambda item: (-int(item["entry_count"]), str(item["label"])))


def enrich_defense_config(item: dict[str, Any]) -> dict[str, Any]:
    key = str(item.get("defense_type") or "").strip()
    meta = CONTROL_META.get(key, {})
    category = RULE_CATEGORY_META.get(str(meta.get("category_key") or ""), {})
    return {
        **item,
        "category_key": str(meta.get("category_key") or "runtime_audit"),
        "category_label": str(category.get("label") or "未分类规则"),
        "category_order": int(category.get("order") or 999),
        "tone": str(category.get("tone") or "info"),
        "surface_keys": list(meta.get("surface_keys") or []),
        "surface_labels": [display_surface_label(value) for value in list(meta.get("surface_keys") or [])],
        "stage_keys": list(meta.get("stage_keys") or []),
        "stage_labels": [display_attack_stage_label(value) for value in list(meta.get("stage_keys") or [])],
        "display_label": str(meta.get("label") or item.get("defense_name") or key or "未命名规则"),
    }


def enrich_policy_rule(item: dict[str, Any]) -> dict[str, Any]:
    key = str(item.get("key") or "").strip()
    meta = RULE_META.get(key, {})
    category = RULE_CATEGORY_META.get(str(meta.get("category_key") or ""), {})
    return {
        **item,
        "display_label": display_policy_label(key),
        "display_description": display_policy_description(key) or str(item.get("description") or ""),
        "category_key": str(meta.get("category_key") or "runtime_audit"),
        "category_label": str(category.get("label") or "未分类规则"),
        "category_order": int(category.get("order") or 999),
        "tone": str(category.get("tone") or "info"),
        "surface_keys": list(meta.get("surface_keys") or []),
        "surface_labels": [display_surface_label(value) for value in list(meta.get("surface_keys") or [])],
        "stage_keys": list(meta.get("stage_keys") or []),
        "stage_labels": [display_attack_stage_label(value) for value in list(meta.get("stage_keys") or [])],
    }


def build_policy_reference(key: str, *, kind: str = "rule") -> dict[str, Any]:
    normalized = str(key or "").strip()
    if not normalized:
        return {
            "key": "",
            "label": "未命名项",
            "detail": "",
            "category_key": "runtime_audit",
            "category_label": "未分类规则",
            "tone": "info",
            "kind": kind,
            "surface_labels": [],
            "stage_labels": [],
        }

    source_meta = CONTROL_META.get(normalized) if kind == "control" else RULE_META.get(normalized)
    category = RULE_CATEGORY_META.get(str((source_meta or {}).get("category_key") or ""), {})
    return {
        "key": normalized,
        "label": display_policy_label(normalized),
        "detail": display_policy_description(normalized),
        "category_key": str((source_meta or {}).get("category_key") or "runtime_audit"),
        "category_label": str(category.get("label") or "未分类规则"),
        "tone": str(category.get("tone") or "info"),
        "kind": kind,
        "surface_labels": [display_surface_label(value) for value in list((source_meta or {}).get("surface_keys") or [])],
        "stage_labels": [display_attack_stage_label(value) for value in list((source_meta or {}).get("stage_keys") or [])],
    }


def build_policy_reference_auto(key: str) -> dict[str, Any]:
    normalized = str(key or "").strip()
    kind = "control" if normalized in CONTROL_META else "rule"
    return build_policy_reference(normalized, kind=kind)


def display_surface_label(value: str | None) -> str:
    mapping = {
        "prompt_input": "提示输入面",
        "external_content": "检索与外部内容面",
        "tool_execution": "工具执行面",
        "approval_chain": "审批链路面",
        "asset_skill_plugin": "路径 / Skill / 插件面",
        "memory_context": "记忆与上下文面",
        "output_channel": "输出回显面",
        "multi_stage_chain": "组合链路面",
    }
    key = str(value or "").strip()
    return mapping.get(key, key or "-")


def display_signal_label(value: str | None) -> str:
    signal = str(value or "").strip()
    if not signal:
        return "未记录"
    if signal.startswith("strong:"):
        return f"强攻击信号 / {signal[len('strong:') :]}"
    if signal.startswith("suspicious:"):
        return f"可疑信号 / {signal[len('suspicious:') :]}"
    if signal in SIGNAL_META:
        return str(SIGNAL_META[signal]["label"])
    return _humanize_code(signal)


def display_signal_detail(value: str | None) -> str:
    signal = str(value or "").strip()
    if not signal:
        return ""
    if signal.startswith("strong:"):
        return "规则引擎将该信号判定为强攻击特征。"
    if signal.startswith("suspicious:"):
        return "规则引擎将该信号判定为可疑攻击特征。"
    if signal in SIGNAL_META:
        return str(SIGNAL_META[signal]["detail"])
    return ""


def build_signal_reference(value: str) -> dict[str, Any]:
    normalized = str(value or "").strip()
    tone = "info"
    if normalized.startswith("strong:"):
        tone = "danger"
    elif normalized.startswith("suspicious:"):
        tone = "warn"
    elif normalized in SIGNAL_META:
        tone = str(SIGNAL_META[normalized]["tone"])
    return {
        "key": normalized,
        "label": display_signal_label(normalized),
        "detail": display_signal_detail(normalized),
        "tone": tone,
        "kind": "signal",
    }


def build_trigger_sections(*, hit_rules: list[str] | None, guard_trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    trace = guard_trace if isinstance(guard_trace, dict) else {}
    hit_rule_controls, hit_rule_rules = partition_policy_keys(_normalize_string_list(hit_rules))
    matched_rule_controls, matched_rule_rules = partition_policy_keys(_normalize_string_list(trace.get("matched_rules")))
    assessed_controls, assessed_rules = partition_policy_keys(
        _normalize_string_list((trace.get("rule_assessment") or {}).get("hit_rules"))
    )
    control_keys = _unique_strings(
        _normalize_string_list(trace.get("matched_controls")) + hit_rule_controls + matched_rule_controls + assessed_controls
    )
    rule_keys = _unique_strings(hit_rule_rules + matched_rule_rules + assessed_rules)
    signal_keys = _unique_strings(_normalize_string_list((trace.get("rule_assessment") or {}).get("matched_signals")))

    sections: list[dict[str, Any]] = []
    if control_keys:
        items = [build_policy_reference(value, kind="control") for value in control_keys]
        sections.append(
            {
                "key": "control",
                "label": "控制面",
                "tone": "safe",
                "summary": _build_trigger_section_summary("control", items),
                "items": items,
            }
        )
    if rule_keys:
        items = [build_policy_reference_auto(value) for value in rule_keys]
        sections.append(
            {
                "key": "rule",
                "label": "规则",
                "tone": "warn",
                "summary": _build_trigger_section_summary("rule", items),
                "items": items,
            }
        )
    if signal_keys:
        items = [build_signal_reference(value) for value in signal_keys]
        sections.append(
            {
                "key": "signal",
                "label": "信号",
                "tone": "danger",
                "summary": _build_trigger_section_summary("signal", items),
                "items": items,
            }
        )
    return sections


def build_event_trigger_summary(*, hit_rules: list[str] | None, guard_trace: dict[str, Any] | None) -> str:
    trace = guard_trace if isinstance(guard_trace, dict) else {}
    hit_rule_controls, hit_rule_rules = partition_policy_keys(_normalize_string_list(hit_rules))
    matched_rule_controls, matched_rule_rules = partition_policy_keys(_normalize_string_list(trace.get("matched_rules")))
    assessed_controls, assessed_rules = partition_policy_keys(
        _normalize_string_list((trace.get("rule_assessment") or {}).get("hit_rules"))
    )
    matched_rules = _unique_strings(hit_rule_rules + matched_rule_rules + assessed_rules)
    matched_controls = _unique_strings(
        _normalize_string_list(trace.get("matched_controls")) + hit_rule_controls + matched_rule_controls + assessed_controls
    )
    decision = str(trace.get("decision") or "").strip().lower()
    rule_verdict = str(trace.get("rule_verdict") or "").strip().lower()

    if not trace:
        return f"规则命中 {len(matched_rules)} 条" if matched_rules else "未记录具体触发链路"

    if decision == "deny":
        if bool(trace.get("reused")):
            return "复用预检结果后直接拦截"
        if rule_verdict == "blocked" or matched_rules:
            return "规则已触发拦截"
        if matched_controls:
            return "控制面已触发拦截"
        return "授权链路已触发拦截"

    if decision == "review":
        return "规则命中后进入 AI 复核" if bool(trace.get("ai_review_invoked")) else "规则命中，当前等待复核"

    if bool(trace.get("ai_review_invoked")):
        return "AI 复核后继续执行"
    if rule_verdict == "clean":
        return "未命中明确攻击规则"
    if matched_rules or matched_controls:
        return "已命中防护项"
    return "未记录具体触发链路"


def build_event_trigger_support_text(*, hit_rules: list[str] | None, guard_trace: dict[str, Any] | None) -> str:
    trace = guard_trace if isinstance(guard_trace, dict) else {}
    hit_rule_controls, hit_rule_rules = partition_policy_keys(_normalize_string_list(hit_rules))
    matched_rule_controls, matched_rule_rules = partition_policy_keys(_normalize_string_list(trace.get("matched_rules")))
    assessed_controls, assessed_rules = partition_policy_keys(
        _normalize_string_list((trace.get("rule_assessment") or {}).get("hit_rules"))
    )
    matched_rules = _unique_strings(hit_rule_rules + matched_rule_rules + assessed_rules)
    matched_controls = _unique_strings(
        _normalize_string_list(trace.get("matched_controls")) + hit_rule_controls + matched_rule_controls + assessed_controls
    )
    matched_signals = _unique_strings(_normalize_string_list((trace.get("rule_assessment") or {}).get("matched_signals")))
    fragments: list[str] = []

    if not trace:
        if matched_rules:
            fragments.append(f"规则 {len(matched_rules)} 条")
        return " / ".join(fragments) or "没有控制面或 AI 复核记录"

    review_decision = str(trace.get("review_decision") or "").strip().lower()
    review_mode = str(trace.get("ai_review_mode") or "").strip().lower()
    if bool(trace.get("ai_review_invoked")):
        fragments.append("AI 复核已触发")
    elif review_decision == "target_protection_disabled":
        fragments.append("AI 复核未开启")
    elif review_decision == "rules_only_mode" or review_mode == "rules_only":
        fragments.append("当前仅按规则判定")
    elif review_decision == "confirmed_by_policy":
        fragments.append("已由规则直接定性")
    elif review_decision == "review_suspicious_only":
        fragments.append("当前仅复核可疑流量")
    elif review_decision == "review_all_remaining":
        fragments.append("当前其余流量进入 AI 复核")
    else:
        fragments.append("未触发 AI 复核")

    if matched_controls:
        fragments.append(f"控制面 {len(matched_controls)} 项")
    if matched_rules:
        fragments.append(f"规则 {len(matched_rules)} 条")
    if matched_signals:
        fragments.append(f"信号 {len(matched_signals)} 项")
    return " / ".join(fragments)


def _build_trigger_section_summary(section_key: str, items: list[dict[str, Any]]) -> str:
    if not items:
        if section_key == "control":
            return "当前没有控制面命中。"
        if section_key == "rule":
            return "当前没有规则命中。"
        return "当前没有攻击信号。"

    preview = "、".join(str(item.get("label") or "") for item in items[:2])
    suffix = f"（{preview}{' 等' if len(items) > 2 else ''}）" if preview else ""
    if section_key == "control":
        return f"命中 {len(items)} 个控制面{suffix}"
    if section_key == "rule":
        return f"命中 {len(items)} 条规则{suffix}"
    return f"识别 {len(items)} 个攻击信号{suffix}"


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def partition_policy_keys(values: list[str]) -> tuple[list[str], list[str]]:
    controls: list[str] = []
    rules: list[str] = []
    for item in values:
        normalized = str(item).strip()
        if not normalized:
            continue
        if normalized in CONTROL_META:
            if normalized not in controls:
                controls.append(normalized)
            continue
        if normalized not in rules:
            rules.append(normalized)
    return controls, rules


def _unique_strings(items: list[str]) -> list[str]:
    unique: list[str] = []
    for item in items:
        normalized = str(item).strip()
        if normalized and normalized not in unique:
            unique.append(normalized)
    return unique


def _slugify_label(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_").replace("/", "_")
    return normalized or "unknown"


def _humanize_code(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.replace("_", " ").replace("-", " ")
