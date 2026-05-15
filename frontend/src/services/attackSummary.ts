import type { GuardTrace } from './api'

export type AttackSummaryInput = {
  eventType?: string | null
  hitRules?: Array<string | null | undefined> | null
  guardTrace?: GuardTrace | null
}

export type AttackSummary = {
  label: string
  brief: string
  supportText: string
  counts: {
    controls: number
    rules: number
    signals: number
  }
}

type AttackFamily = {
  label: string
  supportText: string
  eventTypes: string[]
  rules: string[]
  controls: string[]
  signals: string[]
  priority: number
}

type AttackFallback = {
  label: string
  supportText: string
}

const ATTACK_FAMILIES: AttackFamily[] = [
  {
    label: 'MCP 投毒攻击',
    supportText: 'MCP 会话、能力绑定或跨能力链路出现了异常迹象。',
    eventTypes: ['runtime_execution'],
    rules: ['mcp-tool-poisoning-scan', 'mcp-session-bind', 'cross-plugin-proof'],
    controls: ['mcp_capability_binding', 'cross_plugin_handoff_guard'],
    signals: ['plugin_or_mcp_surface'],
    priority: 100
  },
  {
    label: '工具投毒攻击',
    supportText: '工具结果、工作区或插件链路中出现了可疑载荷。',
    eventTypes: ['runtime_execution'],
    rules: ['tool-poisoning-scan', 'tool-result-scan', 'workspace-scan'],
    controls: ['tool_permission_broker'],
    signals: ['plugin_or_mcp_surface'],
    priority: 90
  },
  {
    label: '提示注入攻击',
    supportText: '检测到越狱、覆盖指令或间接注入的迹象。',
    eventTypes: ['prompt_injection'],
    rules: ['intent-scan', 'external-content-scan', 'indirect-instruction-quarantine', 'retrieval-boundary-scan', 'prompt-leakage-scan'],
    controls: ['prompt_injection_firewall', 'indirect_content_isolation'],
    signals: ['prompt_injection_surface'],
    priority: 80
  },
  {
    label: '敏感信息泄露',
    supportText: '命中了密钥、PII、蜜标或提示词外泄的风险特征。',
    eventTypes: ['prompt_injection', 'runtime_execution'],
    rules: ['secret-pattern-scan', 'pii-exfiltration-scan', 'canary-leak-scan', 'output-sanitize'],
    controls: ['output_redaction_gate'],
    signals: ['output_leak_surface'],
    priority: 70
  },
  {
    label: '审批绕过攻击',
    supportText: '请求试图绕过审批或诱导放行高风险动作。',
    eventTypes: ['runtime_execution'],
    rules: ['approval-persuasion-scan', 'approval-social-engineering-scan', 'tool-approval-gate', 'approval-integrity-gate'],
    controls: ['approval_integrity_gate'],
    signals: [],
    priority: 60
  },
  {
    label: '多轮污染攻击',
    supportText: '上下文或记忆写入出现了污染痕迹。',
    eventTypes: ['prompt_injection', 'runtime_execution'],
    rules: ['memory-escalation-scan', 'memory-write-guard'],
    controls: ['memory_taint_guard'],
    signals: ['multi_turn_context'],
    priority: 50
  },
  {
    label: '编码绕过攻击',
    supportText: '载荷使用了编码、转义或不可见字符混淆。',
    eventTypes: ['prompt_injection', 'runtime_execution'],
    rules: ['encoding-evasion-scan', 'ansi-control-scan'],
    controls: [],
    signals: [],
    priority: 45
  },
  {
    label: '跨插件交接攻击',
    supportText: '跨插件或跨能力交接链路未形成完整证明。',
    eventTypes: ['runtime_execution'],
    rules: ['cross-plugin-proof'],
    controls: ['cross_plugin_handoff_guard'],
    signals: [],
    priority: 40
  },
  {
    label: '输出泄露风险',
    supportText: '模型输出中出现了不应暴露的敏感内容。',
    eventTypes: ['runtime_execution', 'prompt_injection'],
    rules: ['output-sanitize'],
    controls: ['output_redaction_gate'],
    signals: ['output_leak_surface'],
    priority: 35
  }
]

const EVENT_TYPE_FALLBACKS: Record<string, AttackFallback> = {
  prompt_injection: {
    label: '提示注入攻击',
    supportText: '事件更接近提示注入、越狱或覆盖指令尝试。'
  },
  asset_access: {
    label: '越权访问风险',
    supportText: '事件更接近越权访问或资源探测。'
  },
  skill_scan: {
    label: '技能扫描风险',
    supportText: '事件来自技能或能力扫描流程。'
  },
  runtime_execution: {
    label: '运行时执行风险',
    supportText: '事件发生在运行时执行链路中。'
  },
  preflight_block: {
    label: '预检阻断事件',
    supportText: '请求在预检阶段被拦截。'
  }
}

export function buildAttackSummary(input: AttackSummaryInput): AttackSummary {
  const eventType = normalizeToken(input.eventType)
  const hitRules = uniqueStrings([
    ...(input.hitRules ?? []),
    ...(input.guardTrace?.matched_rules ?? []),
    ...(input.guardTrace?.rule_assessment?.hit_rules ?? [])
  ])
  const matchedControls = uniqueStrings(input.guardTrace?.matched_controls ?? [])
  const matchedSignals = uniqueStrings(input.guardTrace?.rule_assessment?.matched_signals ?? [])
  const matchedFamilies = ATTACK_FAMILIES
    .map((family) => ({
      ...family,
      score: scoreAttackFamily(family, eventType, hitRules, matchedControls, matchedSignals)
    }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || right.priority - left.priority)

  const primaryFamily = matchedFamilies[0] ?? null
  const fallback = eventType ? EVENT_TYPE_FALLBACKS[eventType] : null
  const counts = {
    controls: matchedControls.length,
    rules: hitRules.length,
    signals: matchedSignals.length
  }

  return {
    label: primaryFamily?.label || fallback?.label || (hasAnyHits(counts) ? '异常攻击行为' : '未识别事件'),
    brief: buildAttackBrief(counts),
    supportText:
      primaryFamily?.supportText ||
      fallback?.supportText ||
      (hasAnyHits(counts) ? '当前命中项不足以归入更细的攻击族群。' : '当前没有提取到足够明确的攻击特征。'),
    counts
  }
}

function scoreAttackFamily(
  family: AttackFamily,
  eventType: string,
  hitRules: string[],
  matchedControls: string[],
  matchedSignals: string[]
) {
  let score =
    countMatches(hitRules, family.rules) * 3 +
    countMatches(matchedControls, family.controls) * 2 +
    countMatches(matchedSignals, family.signals) * 4

  if (score > 0 && family.eventTypes.includes(eventType)) {
    score += 1
  }

  return score
}

function countMatches(values: string[], tokens: string[]) {
  if (!values.length || !tokens.length) {
    return 0
  }

  let total = 0
  for (const value of values) {
    if (tokens.some((token) => token === value || value.includes(token) || token.includes(value))) {
      total += 1
    }
  }
  return total
}

function buildAttackBrief(counts: AttackSummary['counts']) {
  const parts: string[] = []
  if (counts.controls) {
    parts.push(`${counts.controls} 个控制面`)
  }
  if (counts.rules) {
    parts.push(`${counts.rules} 条规则`)
  }
  if (counts.signals) {
    parts.push(`${counts.signals} 个信号`)
  }

  return parts.length ? `命中 ${parts.join('，')}` : '未提取到足够明确的攻击特征'
}

function hasAnyHits(counts: AttackSummary['counts']) {
  return counts.controls > 0 || counts.rules > 0 || counts.signals > 0
}

function uniqueStrings(values: Array<string | null | undefined>) {
  const seen = new Set<string>()
  const items: string[] = []

  for (const value of values) {
    const normalized = normalizeToken(value)
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    items.push(normalized)
  }

  return items
}

function normalizeToken(value?: string | null) {
  return (value || '').trim().toLowerCase()
}
