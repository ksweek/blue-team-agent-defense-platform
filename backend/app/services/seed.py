users = [
    {
        "id": 1,
        "username": "admin",
        "real_name": "系统管理员",
        "email": "admin@example.com",
        "status": "active",
        "roles": ["admin"],
    },
    {
        "id": 2,
        "username": "analyst",
        "real_name": "安全分析师",
        "email": "analyst@example.com",
        "status": "active",
        "roles": ["analyst"],
    },
]

dashboard_overview = {
    "attack_count": 128,
    "blocked_count": 97,
    "enabled_defense_count": 8,
    "high_risk_event_count": 6,
    "active_task_count": 3,
}

dashboard_trends = [
    {"day": "Mon", "attack": 16, "block": 12, "false_positive": 1},
    {"day": "Tue", "attack": 20, "block": 15, "false_positive": 2},
    {"day": "Wed", "attack": 18, "block": 14, "false_positive": 1},
    {"day": "Thu", "attack": 26, "block": 19, "false_positive": 2},
    {"day": "Fri", "attack": 21, "block": 17, "false_positive": 1},
]

dashboard_sessions = [
    {"session_id": "sess-001", "session_name": "越权测试任务", "status": "running", "risk_level": "high"},
    {"session_id": "sess-002", "session_name": "提示注入测试", "status": "queued", "risk_level": "medium"},
]

defense_configs = [
    {
        "id": 1,
        "defense_name": "提示注入拦截",
        "defense_type": "prompt_injection_firewall",
        "threat_level": "critical",
        "mode": "enforce",
        "enabled": True,
        "description": "在输入侧识别直接 Prompt Injection、越权指令、角色混淆和高风险 Jailbreak 语义。",
        "config_json": {
            "threshold": 0.82,
            "stages": ["input"],
            "families": ["prompt-injection", "jailbreak_prompt", "suffix_attack", "role-confusion"],
        },
    },
    {
        "id": 2,
        "defense_name": "间接内容隔离",
        "defense_type": "indirect_content_isolation",
        "threat_level": "high",
        "mode": "observe",
        "enabled": True,
        "description": "对检索内容、网页片段、RAG 文档和工具回传文本打上不可信标签并触发二次扫描。",
        "config_json": {
            "scan_external_content": True,
            "quarantine_untrusted_context": True,
            "stages": ["external_content", "tool_result"],
            "families": ["indirect-injection", "rendered_script_injection", "markdown_javascript_injection"],
        },
    },
    {
        "id": 3,
        "defense_name": "敏感工具最小授权",
        "defense_type": "tool_permission_broker",
        "threat_level": "critical",
        "mode": "enforce",
        "enabled": True,
        "description": "限制文件系统、网络、命令执行和写入型工具的调用范围，默认拒绝越权动作。",
        "config_json": {
            "role_required": True,
            "require_allowlist": True,
            "restricted_tools": ["filesystem", "shell", "network", "database_write"],
        },
    },
    {
        "id": 4,
        "defense_name": "MCP 会话与能力绑定",
        "defense_type": "mcp_capability_binding",
        "threat_level": "critical",
        "mode": "enforce",
        "enabled": True,
        "description": "绑定 MCP server、capability、session 和 approval 上下文，阻断协议欺骗与会话串改。",
        "config_json": {
            "bind_server_identity": True,
            "bind_capability_set": True,
            "bind_session_approval": True,
        },
    },
    {
        "id": 5,
        "defense_name": "跨插件链路约束",
        "defense_type": "cross_plugin_handoff_guard",
        "threat_level": "critical",
        "mode": "enforce",
        "enabled": True,
        "description": "限制跨插件 token 传递、角色借用、summary laundering 和跨链路数据暂存。",
        "config_json": {
            "require_handoff_policy": True,
            "deny_role_borrowing": True,
            "deny_summary_laundering": True,
        },
    },
    {
        "id": 6,
        "defense_name": "长上下文污染防护",
        "defense_type": "memory_taint_guard",
        "threat_level": "high",
        "mode": "observe",
        "enabled": True,
        "description": "识别多轮上下文中的污染片段、诱导记忆写入和延迟触发链路，并在高风险时中断继续执行。",
        "config_json": {
            "track_memory_taint": True,
            "suspicious_turn_window": 6,
            "break_on_taint_escalation": True,
        },
    },
    {
        "id": 7,
        "defense_name": "输出泄露脱敏",
        "defense_type": "output_redaction_gate",
        "threat_level": "critical",
        "mode": "enforce",
        "enabled": True,
        "description": "在响应输出前做 secrets、路径、训练数据回放和敏感片段脱敏与截断。",
        "config_json": {
            "redact_secrets": True,
            "redact_sensitive_paths": True,
            "block_training_replay": True,
        },
    },
    {
        "id": 8,
        "defense_name": "高风险动作审批校验",
        "defense_type": "approval_integrity_gate",
        "threat_level": "high",
        "mode": "enforce",
        "enabled": True,
        "description": "对审批绕过、社会工程诱导和高风险动作执行做二次确认，确保授权链路完整。",
        "config_json": {
            "require_two_step_confirmation": True,
            "enforce_human_approval": True,
            "families": ["persuasion_social_engineering", "harmful_goal", "workflow-hijacking"],
        },
    },
]

security_events = [
    {
        "id": 1,
        "event_type": "prompt_injection",
        "event_level": "high",
        "source": "攻击模拟器",
        "target": "filesystem-reader",
        "status": "intercepted",
        "created_at": "2026-04-16 10:18:07",
        "detail": "检测到高风险提示注入样本。",
        "hit_rules": ["prompt_injection_firewall", "intent-scan"],
        "raw_input": "Ignore previous instructions...",
        "result": "已拦截",
        "operation_logs": [{"operator": "system", "action": "intercepted", "time": "2026-04-16 10:18:08"}],
    },
    {
        "id": 2,
        "event_type": "asset_access",
        "event_level": "medium",
        "source": "资产保护模块",
        "target": "/srv/secrets",
        "status": "suspicious",
        "created_at": "2026-04-16 10:11:34",
        "detail": "访问请求指向敏感目录。",
        "hit_rules": ["tool_permission_broker"],
        "raw_input": "read /srv/secrets",
        "result": "可疑待复核",
        "operation_logs": [],
    },
]

assets = [
    {"id": 1, "asset_name": "配置目录", "asset_type": "path", "asset_path": "/etc/app/config", "risk_level": "high", "status": "protected"},
    {"id": 2, "asset_name": "机密文件目录", "asset_type": "path", "asset_path": "/srv/secrets", "risk_level": "high", "status": "protected"},
]

asset_whitelists = [
    {"id": 1, "asset_id": 1, "whitelist_type": "path", "rule_value": "/workspace/**", "description": "项目工作目录"},
    {"id": 2, "asset_id": 1, "whitelist_type": "skill", "rule_value": "trusted-*", "description": "可信技能"},
    {"id": 3, "asset_id": 2, "whitelist_type": "path", "rule_value": "/srv/secrets/read-only", "description": "只读受控目录"},
]

skills = [
    {
        "id": 1,
        "skill_name": "filesystem-reader",
        "skill_type": "local",
        "provider": "official",
        "source_path": "backend/data/demo_skills/filesystem-reader",
        "trust_status": "trusted",
        "created_at": "2026-04-15",
    },
    {
        "id": 2,
        "skill_name": "plugin-risk-audit",
        "skill_type": "plugin",
        "provider": "third-party",
        "source_path": "backend/data/demo_skills/plugin-risk-audit",
        "trust_status": "pending",
        "created_at": "2026-04-14",
    },
]

tasks = [
    {"id": 1, "task_name": "越权攻击测试", "attack_type": "jailbreak", "target_agent": "agent-A", "status": "running", "params_json": {"rounds": 5}},
    {"id": 2, "task_name": "提示注入测试", "attack_type": "prompt_injection", "target_agent": "agent-B", "status": "queued", "params_json": {"rounds": 3}},
]

reports = [
    {"id": 1, "report_name": "安全评估报告-001", "report_type": "security_evaluation", "task_id": 1, "file_path": "/reports/report-001.pdf", "created_by": 1, "created_at": "2026-04-16 11:00:00"}
]

system_settings = [
    {"setting_key": "log_level", "setting_value": "INFO", "description": "系统日志级别"},
    {"setting_key": "notify_email", "setting_value": "enabled", "description": "是否开启邮件通知"},
]

audit_logs = [
    {"id": 1, "user_id": 1, "module": "defense-config", "action": "update", "detail": "更新提示注入拦截模式", "created_at": "2026-04-16 10:30:00"},
    {"id": 2, "user_id": 2, "module": "security-events", "action": "export", "detail": "导出安全事件列表", "created_at": "2026-04-16 11:00:00"},
]

default_guard_rules = [
    {
        "key": "source-trace",
        "title": "风险来源追踪",
        "description": "记录高风险提示、工具结果和外部文档的上游来源，便于审计回放与归因。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "memory-write-guard",
        "title": "记忆写入守卫",
        "description": "拦截长期记忆和持久化存储中的高风险写入，防止污染被带入后续轮次。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "loop-guard",
        "title": "循环调用限幅",
        "description": "限制异常自循环工具调用和无收益重试，避免单次任务放大成持续风险。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "tool-approval-gate",
        "title": "敏感工具审批门",
        "description": "对写文件、发网络请求、执行命令和写数据库等动作要求显式审批或允许清单。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "mcp-session-bind",
        "title": "MCP 会话绑定",
        "description": "校验 MCP server、capability、session 与审批票据是否一致，防止 capability spoof 和 session rebind。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "cross-plugin-proof",
        "title": "跨插件移交校验",
        "description": "要求跨插件跳转时携带可信来源证明，阻断 auth hop、role borrowing 和 summary laundering。",
        "enabled": True,
        "mode": "observe",
    },
]

default_scan_rules = [
    {
        "key": "intent-scan",
        "title": "输入意图扫描",
        "description": "在 message_received 阶段预检明显的 Prompt Injection、Jailbreak 和越权语义。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "workspace-scan",
        "title": "技能与插件扫描",
        "description": "扫描 workspace 中新增的技能、插件和 MCP capability，并纳入审核队列。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "tool-result-scan",
        "title": "工具结果扫描",
        "description": "拦截工具输出中的提示注入、密钥痕迹、隐藏指令与额外上下文污染。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "external-content-scan",
        "title": "外部内容隔离扫描",
        "description": "对网页片段、RAG 文档、邮件和远程知识块打标签并执行二次风险扫描。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "secret-pattern-scan",
        "title": "敏感信息模式扫描",
        "description": "检测 API Key、令牌、凭据、内网路径和训练数据回放片段。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "output-sanitize",
        "title": "输出脱敏",
        "description": "在输出前处理文件位置、API 密钥片段、敏感路径和结构化泄露字段。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "approval-persuasion-scan",
        "title": "审批诱导扫描",
        "description": "识别社会工程、紧急借口和伪造授权措辞，阻断绕过审批链路的诱导文本。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "indirect-instruction-quarantine",
        "title": "间接指令隔离扫描",
        "description": "识别来自网页、邮件、文档、附件和检索片段中的隐式指令，并将其标记为不可信上下文。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "retrieval-boundary-scan",
        "title": "检索边界扫描",
        "description": "针对 RAG、搜索结果、知识库和外部内容建立边界，防止外部文本覆盖系统策略。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "tool-poisoning-scan",
        "title": "工具投毒扫描",
        "description": "识别工具输出、插件结果和工作区内容中的提示词注入、结果投毒和指令覆盖片段。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "mcp-tool-poisoning-scan",
        "title": "MCP 能力投毒扫描",
        "description": "识别 MCP capability 返回、会话重绑、伪造审批和跨插件调用中的高风险指令。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "prompt-leakage-scan",
        "title": "提示词泄露扫描",
        "description": "识别系统提示词、开发者消息、隐藏指令和内部策略泄露请求。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "pii-exfiltration-scan",
        "title": "PII 与密钥外传扫描",
        "description": "识别 API Key、令牌、凭据、邮箱和敏感身份数据的导出、回显与拼接泄露。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "canary-leak-scan",
        "title": "蜜标泄露扫描",
        "description": "识别 canary token、诱饵凭据和测试密钥的外传信号，用于发现隐藏泄露路径。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "approval-social-engineering-scan",
        "title": "审批社工扫描",
        "description": "识别利用紧急话术、伪造授权、角色混淆和人为施压绕过审批链的文本。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "memory-escalation-scan",
        "title": "多轮污染扫描",
        "description": "识别跨轮记忆污染、延迟执行、长期上下文植入和未来轮次触发攻击。",
        "enabled": True,
        "mode": "observe",
    },
    {
        "key": "encoding-evasion-scan",
        "title": "编码绕过扫描",
        "description": "识别 base64、URL 编码、Unicode 转义、Hex 转义和混淆字符承载的攻击指令。",
        "enabled": True,
        "mode": "enforce",
    },
    {
        "key": "ansi-control-scan",
        "title": "控制字符扫描",
        "description": "识别零宽字符、ANSI 转义和不可见控制字符构造的隐藏指令或显示层绕过。",
        "enabled": True,
        "mode": "observe",
    },
]

default_advanced_rule = {
    "key": "tool-call-audit",
    "title": "运行时联动审计",
    "description": "对关键 tool call、跨插件跳转、审批决策和高风险输出做留痕、回放与事后核查。",
    "enabled": True,
    "mode": "observe",
}

default_ai_review_policy = {
    "key": "protected-agent-ai-review",
    "title": "AI 复核策略",
    "description": "对受保护 AI/Agent 在规则判定后执行二次 AI 风险复核，重点覆盖间接注入、编码绕过、工具投毒、多轮污染和泄露外传场景。",
    "mode": "suspicious_review",
}

default_protected_paths = [item["asset_path"] for item in assets]
default_protected_skills = [item["skill_name"] for item in skills]
default_protected_plugins = [item["skill_name"] for item in skills if item["skill_type"] == "plugin"]
