<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import PageSection from '../components/PageSection.vue'
import RawSectionHighlighter from '../components/RawSectionHighlighter.vue'
import StatusPill from '../components/StatusPill.vue'
import {
  api,
  type DownloadedFile,
  type GuardTrace,
  type SecurityEventReportView,
  type SecurityReportPayloadItem,
  type SensitiveFindingItem
} from '../services/api'
import { eventStatusLabel, eventStatusTone } from '../services/eventStatus'
import { buildRawHighlightSectionViews, buildRawLocationKey } from '../services/rawHighlight'
import { redactSensitiveText } from '../services/redaction'

type Tone = 'safe' | 'warn' | 'danger' | 'info'
type RawFilterMode = 'hits' | 'all'
type PayloadSectionKey = SecurityReportPayloadItem['kind']
type ReportSummaryEntry = {
  id: string
  label: string
  value: string
}
type PayloadSection = {
  key: PayloadSectionKey
  label: string
  tone: Tone
  items: SecurityReportPayloadItem[]
  summary: string
}

const CONTROL_LABELS: Record<string, string> = {
  prompt_injection_firewall: '提示注入防火墙',
  indirect_content_isolation: '外部内容隔离',
  tool_permission_broker: '工具权限代理',
  mcp_capability_binding: 'MCP 能力绑定',
  cross_plugin_handoff_guard: '跨插件交接防护',
  memory_taint_guard: '上下文污染防护',
  output_redaction_gate: '输出脱敏闸门',
  approval_integrity_gate: '审批完整性校验'
}

const CONTROL_DESCRIPTIONS: Record<string, string> = {
  prompt_injection_firewall: '用于拦截提示注入、越狱和角色混淆类高风险输入。',
  indirect_content_isolation: '用于隔离外部内容、工具结果和间接注入来源。',
  tool_permission_broker: '用于限制高风险工具、路径和技能调用权限。',
  mcp_capability_binding: '用于校验 MCP 会话、能力和审批绑定关系。',
  cross_plugin_handoff_guard: '用于约束跨插件交接链路和证明凭据。',
  memory_taint_guard: '用于识别多轮上下文污染和记忆写入风险。',
  output_redaction_gate: '用于识别并脱敏输出中的敏感信息。',
  approval_integrity_gate: '用于校验高风险动作是否具备有效审批。'
}

const RULE_LABELS: Record<string, string> = {
  'intent-scan': '意图扫描',
  'secret-pattern-scan': '敏感信息模式扫描',
  'approval-persuasion-scan': '审批绕过说服扫描',
  'approval-social-engineering-scan': '审批社工扫描',
  'external-content-scan': '外部内容扫描',
  'indirect-instruction-quarantine': '间接指令隔离扫描',
  'retrieval-boundary-scan': '检索边界扫描',
  'tool-result-scan': '工具结果扫描',
  'tool-poisoning-scan': '工具投毒扫描',
  'tool-approval-gate': '工具审批闸门',
  'workspace-scan': '工作区与插件扫描',
  'mcp-tool-poisoning-scan': 'MCP 能力投毒扫描',
  'mcp-session-bind': 'MCP 会话绑定校验',
  'cross-plugin-proof': '跨插件交接校验',
  'memory-write-guard': '记忆写入防护',
  'memory-escalation-scan': '多轮污染扫描',
  'output-sanitize': '输出脱敏',
  'prompt-leakage-scan': '提示词泄露扫描',
  'pii-exfiltration-scan': 'PII 与密钥外传扫描',
  'canary-leak-scan': '蜜标泄露扫描',
  'encoding-evasion-scan': '编码绕过扫描',
  'ansi-control-scan': '控制字符扫描'
}

const RULE_DESCRIPTIONS: Record<string, string> = {
  'intent-scan': '识别忽略规则、覆盖指令、越狱和角色混淆类攻击意图。',
  'secret-pattern-scan': '识别密钥、令牌、系统提示词等敏感信息泄露风险。',
  'approval-persuasion-scan': '识别通过社会工程或说服方式绕过审批的意图。',
  'approval-social-engineering-scan': '识别通过紧急话术、角色伪装和伪造授权绕过审批链的行为。',
  'external-content-scan': '识别来自外部页面、文件和上下文的间接注入风险。',
  'indirect-instruction-quarantine': '识别网页、附件、邮件和文档中的隐式指令并隔离不可信上下文。',
  'retrieval-boundary-scan': '识别 RAG、搜索结果和知识库片段对系统提示词的覆盖风险。',
  'tool-result-scan': '识别工具返回结果中夹带的攻击片段。',
  'tool-poisoning-scan': '识别工具、插件和工作区结果中的投毒或指令覆盖片段。',
  'tool-approval-gate': '识别高风险工具调用是否缺少授权或审批。',
  'workspace-scan': '识别插件、技能、工作区和路径层面的越权风险。',
  'mcp-tool-poisoning-scan': '识别 MCP capability 返回、会话重绑和伪造审批中的投毒风险。',
  'mcp-session-bind': '识别 MCP 会话、能力调用和审批信息是否一致。',
  'cross-plugin-proof': '识别跨插件交接时是否缺少交接凭据。',
  'memory-write-guard': '识别多轮上下文污染和恶意记忆写入。',
  'memory-escalation-scan': '识别延迟触发、未来轮次执行和长期上下文污染风险。',
  'output-sanitize': '识别输出中的敏感内容并要求脱敏。',
  'prompt-leakage-scan': '识别系统提示词、开发者消息和隐藏指令泄露请求。',
  'pii-exfiltration-scan': '识别 PII、密钥、令牌和凭据的导出或回显请求。',
  'canary-leak-scan': '识别蜜标、诱饵令牌和测试密钥的泄露信号。',
  'encoding-evasion-scan': '识别 base64、URL 编码、Unicode/Hex 转义等编码绕过载荷。',
  'ansi-control-scan': '识别零宽字符、ANSI 转义和其他不可见控制字符绕过。'
}

const REPORT_SUMMARY_LABELS: Record<string, string> = {
  task: '任务名称',
  attack_type: '攻击类型',
  target_agent: '目标对象',
  status: '任务状态',
  source_type: '任务来源',
  source_ref: '来源引用',
  execution_mode: '执行方式',
  result: '执行结论',
  ai_endpoint: 'AI 目标',
  ai_endpoint_provider: '目标提供方',
  ai_endpoint_model: '目标模型',
  ai_endpoint_protection: '保护模式',
  ai_review_mode: 'AI 复核模式',
  ai_review_invoked: '是否触发 AI 复核',
  review_decision: '复核结论',
  rule_verdict: '规则判定',
  authorization_decision: '授权决策',
  authorization_controls: '命中控制面',
  provider: '上游提供方',
  model: '上游模型',
  runtime_name: '运行时名称',
  runtime_task_ref: '运行时任务号',
  event_type: '事件类型',
  event_level: '事件等级',
  event_status: '事件状态'
}

const SOURCE_TYPE_LABELS: Record<string, string> = {
  manual: '手动创建',
  sample: '攻击样本',
  catalog: '样本目录',
  batch: '批量任务'
}

const EXECUTION_MODE_LABELS: Record<string, string> = {
  worker: '平台 Worker',
  runtime_callback: '运行时回传',
  scheduled: '定时调度'
}

const PROTECTION_MODE_LABELS: Record<string, string> = {
  enforce: '强制拦截',
  observe: '观察模式',
  off: '关闭保护'
}

const AI_REVIEW_MODE_LABELS: Record<string, string> = {
  rules_only: '仅规则直断',
  suspicious_review: '疑似再复核',
  review_all_remaining: '剩余全复核'
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  task_execution: '任务执行报告',
  runtime_execution: '运行时执行报告',
  preflight_block: '预检阻断报告',
  security_evaluation: '安全评估报告'
}

const OPERATION_ACTION_LABELS: Record<string, string> = {
  task_started: '任务启动',
  rule_engine_assessed: '规则引擎评估',
  policy_enforcer_assessed: '策略授权评估',
  ai_review_started: 'AI 复核启动',
  provider_completed: '模型调用完成',
  runtime_complete: '运行时结果回传',
  blocked: '已拦截',
  pending: '可疑',
  closed: '已放行',
  intercepted: '已拦截',
  suspicious: '可疑',
  allowed: '已放行',
  done: '已完成',
  failed: '执行失败'
}

const OPERATOR_LABELS: Record<string, string> = {
  worker: '平台 Worker',
  system: '系统',
  'external-runtime': '外部运行时'
}

const route = useRoute()
const loading = ref(false)
const error = ref<string | null>(null)
const downloadError = ref<string | null>(null)
const data = ref<SecurityEventReportView | null>(null)
const rawFilterMode = ref<RawFilterMode>('hits')
const activeRawLocationKey = ref<string | null>(null)
const payloadSectionExpanded = ref<Record<PayloadSectionKey, boolean>>(createCollapsedPayloadSectionState())

const eventId = computed(() => {
  const raw = Array.isArray(route.params.eventId) ? route.params.eventId[0] : route.params.eventId
  const parsed = Number(raw)
  return Number.isFinite(parsed) ? parsed : 0
})

const guardTrace = computed<GuardTrace | null>(() => data.value?.event.guard_trace ?? data.value?.task?.guard_trace ?? null)
const reportSummaryEntries = computed<ReportSummaryEntry[]>(() =>
  (data.value?.report?.summary_text.split('\n').filter(Boolean) ?? [])
    .map((line, index) => buildReportSummaryEntry(line, index))
    .filter((item): item is ReportSummaryEntry => Boolean(item))
)
const payloadItems = computed(() => data.value?.payload_detection.items ?? [])
const payloadSections = computed<PayloadSection[]>(() =>
  ([
    {
      key: 'control',
      label: '控制面',
      tone: 'safe',
      items: payloadItems.value.filter((item) => item.kind === 'control')
    },
    {
      key: 'rule',
      label: '规则',
      tone: 'warn',
      items: payloadItems.value.filter((item) => item.kind === 'rule')
    },
    {
      key: 'signal',
      label: '信号',
      tone: 'danger',
      items: payloadItems.value.filter((item) => item.kind === 'signal')
    },
    {
      key: 'pattern',
      label: '内容特征',
      tone: 'info',
      items: payloadItems.value.filter((item) => item.kind === 'pattern')
    }
  ] satisfies Array<Omit<PayloadSection, 'summary'>>)
    .filter((section) => section.items.length)
    .map((section) => ({
      ...section,
      summary: buildPayloadSectionSummary(section.key, section.items)
    }))
)
const sensitiveCategories = computed(() => data.value?.sensitive_findings.categories ?? [])
const sensitiveItems = computed(() => data.value?.sensitive_findings.items ?? [])
const rawSections = computed(() => data.value?.raw_sections ?? [])
const operationLogs = computed(() => data.value?.event.operation_logs ?? [])
const reportTriggerSummary = computed(() => data.value?.event.trigger_summary || buildReportTriggerSummary(guardTrace.value))
const reportTriggerSupportText = computed(() => data.value?.event.trigger_support_text || buildReportTriggerSupportText(guardTrace.value))
const reportHeaderRouteText = computed(() => {
  if (!data.value) {
    return ''
  }
  return `来源：${eventSourceLabel(data.value.event.source)}  目标：${displayText(data.value.event.target)}`
})
const reportDisplayName = computed(() => {
  if (!data.value?.report) {
    return ''
  }
  return reportTypeLabel(data.value.report.report_type)
})
const rawSectionViews = computed(() =>
  buildRawHighlightSectionViews(rawSections.value, payloadItems.value, sensitiveItems.value)
)
const visibleRawSectionViews = computed(() =>
  rawSectionViews.value.filter((item) => rawFilterMode.value === 'all' || item.rows.some((row) => row.hasHits))
)
const totalRawRows = computed(() =>
  rawSectionViews.value.reduce((total, item) => total + item.rows.length, 0)
)
const hitRawRows = computed(() =>
  rawSectionViews.value.reduce((total, item) => total + item.rows.filter((row) => row.hasHits).length, 0)
)

watch(
  eventId,
  (id) => {
    if (!id) {
      error.value = '事件编号无效'
      data.value = null
      return
    }
    void loadReportView(id)
  },
  { immediate: true }
)

function displayText(value?: string | null) {
  return redactSensitiveText(value)
}

function humanizeTechnicalValue(value?: string | null) {
  return (value || '').replace(/_/g, ' ').trim()
}

function policyKeyLabel(value?: string | null) {
  const key = (value || '').trim()
  return CONTROL_LABELS[key] || RULE_LABELS[key] || key || '未命名项'
}

function policyKeyDescription(value?: string | null) {
  const key = (value || '').trim()
  return CONTROL_DESCRIPTIONS[key] || RULE_DESCRIPTIONS[key] || ''
}

function sourceTypeLabel(value?: string | null) {
  const key = (value || '').trim().toLowerCase()
  return SOURCE_TYPE_LABELS[key] || value || '未记录'
}

function executionModeLabel(value?: string | null) {
  const key = (value || '').trim().toLowerCase()
  return EXECUTION_MODE_LABELS[key] || value || '未记录'
}

function protectionModeLabel(value?: string | null) {
  const key = (value || '').trim().toLowerCase()
  return PROTECTION_MODE_LABELS[key] || value || '未记录'
}

function aiReviewModeLabel(value?: string | null) {
  const key = (value || '').trim().toLowerCase() as keyof typeof AI_REVIEW_MODE_LABELS
  return AI_REVIEW_MODE_LABELS[key] || value || '未记录'
}

function aiReviewDecisionLabel(value?: string | null) {
  const key = (value || '').trim().toLowerCase()
  if (key === 'review_suspicious_only') return '仅复核可疑请求'
  if (key === 'review_all_remaining') return '对剩余请求执行复核'
  if (key === 'rules_only_mode') return '仅规则判定，不触发 AI 复核'
  if (key === 'confirmed_by_policy') return '已被策略确认，无需再次复核'
  if (key === 'target_protection_disabled') return '目标未开启 AI 防护'
  return value || '未记录'
}

function reportTypeLabel(value?: string | null) {
  const key = (value || '').trim()
  return REPORT_TYPE_LABELS[key] || value || '未记录'
}

function boolDisplayLabel(value?: string | null) {
  const lowered = (value || '').trim().toLowerCase()
  if (lowered === 'true') return '是'
  if (lowered === 'false') return '否'
  return value || '未记录'
}

function ruleVerdictLabel(value?: string | null) {
  const lowered = (value || '').trim().toLowerCase()
  if (lowered === 'blocked') return '命中拦截'
  if (lowered === 'suspicious') return '疑似攻击'
  if (lowered === 'clean') return '未发现明显风险'
  return value || '未判定'
}

function taskStatusLabel(value?: string | null) {
  const lowered = (value || '').trim().toLowerCase()
  if (lowered === 'queued') return '排队中'
  if (lowered === 'scheduled') return '已调度'
  if (lowered === 'running') return '执行中'
  if (lowered === 'done') return '已完成'
  if (lowered === 'failed') return '执行失败'
  if (lowered === 'ready') return '待执行'
  return value || '未记录'
}

function providerLabel(value?: string | null) {
  const lowered = (value || '').trim().toLowerCase()
  if (lowered === 'openai_compatible') return 'OpenAI 兼容接口'
  if (lowered === 'anthropic') return 'Anthropic 兼容接口'
  if (lowered === 'openai') return 'OpenAI'
  return value || '未记录'
}

function eventSourceLabel(value?: string | null) {
  const source = (value || '').trim()
  if (!source) {
    return '未记录'
  }
  if (source === 'task-runner/prompt-injection') return '任务执行器 / 提示注入检测'
  if (source === 'task-runner/jailbreak') return '任务执行器 / 越狱检测'
  if (source === 'skill-management/scan') return '技能管理 / 联动扫描'
  if (source === 'task-runner/default') return '任务执行器 / 默认评估'
  if (source.startsWith('runtime/')) {
    return `运行时回传 / ${source.slice('runtime/'.length)}`
  }
  return source
}

function sourceLabel(value?: string | null) {
  const source = (value || '').trim()
  if (!source) {
    return '未记录'
  }
  if (source === 'Payload 识别') return '攻击载荷识别'
  if (source === '规则命中') return '规则命中'
  if (source === '授权链路') return '授权链路'
  return source
}

function locationLabel(value?: string | null) {
  const location = (value || '').trim()
  if (!location || location === 'content') {
    return '正文'
  }

  return location
    .replace(/^params\b/, '任务参数')
    .replace(/^runtime\b/, '运行时')
    .replace(/^provider\b/, '模型返回')
    .replace(/^metadata\b/, '元数据')
    .replace(/^result\b/, '处理结果')
    .replace(/^raw_response\b/, '原始响应')
    .replace(/\.(?![^\[]*\])/g, ' / ')
}

function payloadDisplayLabel(item: SecurityReportPayloadItem) {
  if (item.display_label) {
    return displayText(item.display_label)
  }
  if (item.kind === 'signal') {
    return signalLabel(item.label)
  }
  if (item.kind === 'pattern') {
    return displayText(item.label)
  }
  return policyKeyLabel(item.label)
}

function payloadDisplayDetail(item: SecurityReportPayloadItem) {
  if (item.detail_label) {
    return displayText(item.detail_label)
  }
  if (item.kind === 'control' || item.kind === 'rule') {
    return displayText(policyKeyDescription(item.label) || item.detail)
  }
  if (item.kind === 'signal') {
    return `规则引擎识别到可疑攻击信号：${signalLabel(item.label)}`
  }
  if (item.kind === 'pattern') {
    return `在${sourceLabel(item.source)}中匹配到可疑片段。`
  }
  return displayText(item.detail)
}

function payloadSourceLabel(item: SecurityReportPayloadItem) {
  return item.source_label || sourceLabel(item.source)
}

function payloadLocationLabel(item: SecurityReportPayloadItem) {
  return item.location_label || locationLabel(item.location)
}

function signalLabel(value?: string | null) {
  const signal = (value || '').trim()
  if (!signal) {
    return '未记录'
  }
  if (signal.startsWith('strong:')) {
    return `强攻击信号 / ${signal.slice('strong:'.length)}`
  }
  if (signal.startsWith('suspicious:')) {
    return `可疑信号 / ${signal.slice('suspicious:'.length)}`
  }
  if (signal === 'known_attack_family') return '已知攻击家族'
  if (signal === 'blocked_profile') return '阻断型攻击画像'
  if (signal === 'critical_risk') return '高危风险'
  if (signal === 'high_risk') return '高风险'
  if (signal === 'medium_risk') return '中风险'
  if (signal === 'prompt_injection_surface') return '提示注入面'
  if (signal === 'output_leak_surface') return '输出泄露面'
  if (signal === 'multi_turn_context') return '多轮上下文污染'
  if (signal === 'plugin_or_mcp_surface') return '插件或 MCP 攻击面'
  return signal
}

function buildReportSummaryEntry(line: string, index: number): ReportSummaryEntry | null {
  const separatorIndex = line.indexOf('=')
  if (separatorIndex < 0) {
    const value = displayText(line).trim()
    return value
      ? {
          id: `summary-text-${index}`,
          label: '附加说明',
          value
        }
      : null
  }

  const key = line.slice(0, separatorIndex).trim()
  const rawValue = line.slice(separatorIndex + 1).trim()
  if (!rawValue) {
    return null
  }

  return {
    id: `${key}-${index}`,
    label: REPORT_SUMMARY_LABELS[key] || humanizeTechnicalValue(key),
    value: formatReportSummaryValue(key, rawValue)
  }
}

function formatReportSummaryValue(key: string, value: string) {
  if (key === 'attack_type' || key === 'event_type') return eventTypeLabel(value)
  if (key === 'status') return taskStatusLabel(value)
  if (key === 'event_status') return eventLabel(value)
  if (key === 'event_level') return levelLabel(value)
  if (key === 'source_type') return sourceTypeLabel(value)
  if (key === 'execution_mode') return executionModeLabel(value)
  if (key === 'ai_endpoint_provider' || key === 'provider') return providerLabel(value)
  if (key === 'ai_endpoint_protection') return protectionModeLabel(value)
  if (key === 'ai_review_mode') return aiReviewModeLabel(value)
  if (key === 'ai_review_invoked') return boolDisplayLabel(value)
  if (key === 'review_decision') return aiReviewDecisionLabel(value)
  if (key === 'authorization_decision') return guardDecisionLabel(value)
  if (key === 'rule_verdict') return ruleVerdictLabel(value)
  if (key === 'authorization_controls') {
    return value
      .split(',')
      .map((item) => policyKeyLabel(item.trim()))
      .filter(Boolean)
      .join('、')
  }
  if (key === 'report_type') return reportTypeLabel(value)
  if (key === 'source_ref' || key === 'runtime_task_ref') return displayText(value)
  return displayText(value)
}

function normalizeEventLevel(level: string) {
  const lowered = level.toLowerCase()
  if (lowered === 'high') return 'high'
  if (lowered === 'low') return 'low'
  return 'medium'
}

function levelTone(level: string): Tone {
  if (normalizeEventLevel(level) === 'high') return 'danger'
  if (normalizeEventLevel(level) === 'medium') return 'warn'
  return 'info'
}

function levelLabel(level: string) {
  if (normalizeEventLevel(level) === 'high') return '高危'
  if (normalizeEventLevel(level) === 'medium') return '中危'
  return '低危'
}

function eventTone(status: string): Tone {
  return eventStatusTone(status)
}

function eventLabel(status: string) {
  return eventStatusLabel(status)
}

function eventTypeLabel(type: string) {
  if (type === 'prompt_injection') return '提示注入'
  if (type === 'asset_access') return '资产访问'
  if (type === 'skill_scan') return '技能扫描'
  if (type === 'runtime_execution') return '运行时执行'
  if (type === 'preflight_block') return '预检阻断'
  return type.replace(/_/g, ' ')
}

function payloadTone(kind: SecurityReportPayloadItem['kind']): Tone {
  if (kind === 'control') return 'safe'
  if (kind === 'rule') return 'warn'
  if (kind === 'signal') return 'danger'
  return 'info'
}

function payloadKindLabel(kind: SecurityReportPayloadItem['kind']) {
  if (kind === 'control') return '控制面'
  if (kind === 'rule') return '规则'
  if (kind === 'signal') return '信号'
  return '内容特征'
}

function createCollapsedPayloadSectionState(): Record<PayloadSectionKey, boolean> {
  return {
    control: false,
    rule: false,
    signal: false,
    pattern: false
  }
}

function guardDecisionTone(decision?: string | null): Tone {
  if (decision === 'deny') return 'danger'
  if (decision === 'review') return 'warn'
  if (decision === 'allow') return 'safe'
  return 'info'
}

function guardDecisionLabel(decision?: string | null) {
  if (decision === 'deny') return '拦截'
  if (decision === 'review') return '复核'
  if (decision === 'allow') return '放行'
  return '未判定'
}

function guardSourceLabel(source?: string | null) {
  if (source === 'worker_preflight_reused') return '复用预检结果'
  if (source === 'worker_preflight_blocked') return '预检阻断'
  if (source === 'runtime_authorization_snapshot') return '运行时快照'
  if (source === 'task_runner_evaluated') return '执行阶段评估'
  if (source === 'raw_response_embedded') return '响应内嵌结果'
  return '未记录'
}

function isAiReviewDisabled(trace?: GuardTrace | null) {
  const reviewDecision = (trace?.review_decision || '').trim().toLowerCase()
  const reviewMode = (trace?.ai_review_mode || '').trim().toLowerCase()
  return reviewDecision === 'target_protection_disabled' || reviewDecision === 'rules_only_mode' || reviewMode === 'rules_only'
}

function buildReportTriggerSummary(trace?: GuardTrace | null) {
  const matchedControlCount = payloadSections.value.find((item) => item.key === 'control')?.items.length ?? 0
  const matchedRuleCount = payloadSections.value.find((item) => item.key === 'rule')?.items.length ?? 0
  const matchedSignalCount = payloadSections.value.find((item) => item.key === 'signal')?.items.length ?? 0
  const matchedPatternCount = payloadSections.value.find((item) => item.key === 'pattern')?.items.length ?? 0
  const counts: string[] = []
  const segments: string[] = []

  if (matchedControlCount) counts.push(`控制面 ${matchedControlCount} 项`)
  if (matchedRuleCount) counts.push(`规则 ${matchedRuleCount} 条`)
  if (matchedSignalCount) counts.push(`信号 ${matchedSignalCount} 个`)
  if (matchedPatternCount) counts.push(`内容特征 ${matchedPatternCount} 处`)

  if (!trace) {
    return counts.length ? `已记录 ${counts.join('，')}。` : '当前没有记录到控制面、规则或信号命中。'
  }

  if (trace.decision === 'deny') {
    if (trace.reused) {
      segments.push('复用预检结果后直接拦截。')
    } else if (trace.rule_verdict === 'blocked' || matchedRuleCount) {
      segments.push('规则已直接拦截本次请求。')
    } else {
      segments.push('控制面已直接拦截本次请求。')
    }
  } else if (trace.decision === 'review') {
    segments.push(trace.ai_review_invoked ? '命中可疑项后已进入 AI 复核。' : '命中可疑项，当前等待复核。')
  } else if (trace.ai_review_invoked) {
    segments.push('请求经过 AI 复核后继续执行。')
  } else if (trace.rule_verdict === 'clean') {
    segments.push('规则未判定为明确攻击。')
  } else {
    segments.push('已记录到防护链路命中。')
  }

  if (counts.length) {
    segments.push(`本次共涉及 ${counts.join('，')}。`)
  }

  return segments.join('')
}

function buildReportTriggerSupportText(trace?: GuardTrace | null) {
  if (!trace) {
    return '展开下方分组可查看控制面、规则和信号明细。'
  }

  if (trace.ai_review_invoked) {
    return 'AI 复核已触发，明细默认折叠，按需展开查看。'
  }
  if (trace.review_decision?.trim().toLowerCase() === 'target_protection_disabled') {
    return '该目标未开启 AI 复核，本次仅按现有规则和控制面判定。'
  }
  if (isAiReviewDisabled(trace)) {
    return '当前策略未启用 AI 复核，本次仅按规则直接判定。'
  }
  if (trace.review_decision?.trim().toLowerCase() === 'confirmed_by_policy') {
    return '规则已完成定性，因此没有再次触发 AI 复核。'
  }
  return '本页默认只展示摘要，详细命中项请展开下方分组。'
}

function buildPayloadSectionSummary(key: PayloadSectionKey, items: SecurityReportPayloadItem[]) {
  if (!items.length) {
    return `当前没有 ${payloadKindLabel(key)} 命中。`
  }

  const preview = items
    .slice(0, 2)
    .map((item) => payloadDisplayLabel(item))
    .join('、')
  const suffix = preview ? `：${preview}${items.length > 2 ? ' 等' : ''}` : ''

  if (key === 'control') return `命中 ${items.length} 个控制面${suffix}`
  if (key === 'rule') return `命中 ${items.length} 条规则${suffix}`
  if (key === 'signal') return `识别 ${items.length} 个攻击信号${suffix}`
  return `匹配 ${items.length} 处内容特征${suffix}`
}

function isPayloadSectionExpanded(key: PayloadSectionKey) {
  return payloadSectionExpanded.value[key]
}

function togglePayloadSection(key: PayloadSectionKey) {
  payloadSectionExpanded.value = {
    ...payloadSectionExpanded.value,
    [key]: !payloadSectionExpanded.value[key]
  }
}

function operationActionLabel(item: { action?: string; operator?: string }) {
  const action = (item.action || item.operator || '').trim()
  if (!action) {
    return '未记录动作'
  }
  if (action.startsWith('ai_review_skipped:')) {
    return `AI 复核跳过 / ${aiReviewDecisionLabel(action.slice('ai_review_skipped:'.length))}`
  }
  return OPERATION_ACTION_LABELS[action] || humanizeTechnicalValue(action)
}

function operationOperatorLabel(item: { action?: string; operator?: string }) {
  const operator = (item.action ? item.operator || '' : '').trim()
  if (!operator) {
    return '系统'
  }
  return OPERATOR_LABELS[operator] || operator
}

function resolveRawLocationKey(source?: string | null, location?: string | null) {
  const matchedSection = rawSections.value.find((item) => item.title === (source || ''))
  if (!matchedSection) {
    return null
  }
  return buildRawLocationKey(matchedSection.key, location || 'content')
}

function canLocatePayloadItem(item: SecurityReportPayloadItem) {
  return Boolean(resolveRawLocationKey(item.source, item.location))
}

function canLocateSensitiveItem(item: SensitiveFindingItem) {
  return Boolean(resolveRawLocationKey(item.source, item.location))
}

function focusPayloadItem(item: SecurityReportPayloadItem) {
  const locationKey = resolveRawLocationKey(item.source, item.location)
  if (!locationKey) {
    return
  }
  void scrollToRawLocation(locationKey)
}

function focusSensitiveItem(item: SensitiveFindingItem) {
  const locationKey = resolveRawLocationKey(item.source, item.location)
  if (!locationKey) {
    return
  }
  void scrollToRawLocation(locationKey)
}

async function scrollToRawLocation(locationKey: string) {
  activeRawLocationKey.value = locationKey
  await nextTick()
  const target = document.querySelector<HTMLElement>(`[data-raw-location-key="${locationKey}"]`)
  if (!target) {
    return
  }
  target.scrollIntoView({
    behavior: 'smooth',
    block: 'center'
  })
}

async function loadReportView(id: number) {
  loading.value = true
  error.value = null
  activeRawLocationKey.value = null
  payloadSectionExpanded.value = createCollapsedPayloadSectionState()

  try {
    data.value = await api.securityEventReportView(id)
  } catch (err) {
    data.value = null
    error.value = err instanceof Error ? err.message : '安全报告加载失败'
  } finally {
    loading.value = false
  }
}

async function downloadReport() {
  if (!data.value?.report) {
    return
  }

  downloadError.value = null
  try {
    const file = await api.downloadReport(data.value.report.id, 'docx')
    triggerFileDownload(file)
  } catch (err) {
    downloadError.value = err instanceof Error ? err.message : '报告下载失败'
  }
}

function triggerFileDownload(file: DownloadedFile) {
  const url = URL.createObjectURL(file.blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = file.filename
  anchor.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <section class="page-grid security-report-page">
    <header class="security-report-header">
      <div class="security-report-header-copy">
        <p class="attack-testing-kicker">安全报告</p>
        <h1 v-if="data">事件 #{{ data.event.id }} / {{ eventTypeLabel(data.event.event_type) }}</h1>
        <h1 v-else>安全报告</h1>
        <p v-if="data">{{ reportHeaderRouteText }}</p>
      </div>
      <div class="security-report-header-actions">
        <RouterLink class="ghost-button" to="/security-events">返回事件页</RouterLink>
        <button
          v-if="data?.report"
          class="primary-button"
          type="button"
          @click="downloadReport"
        >
          下载报告
        </button>
      </div>
    </header>

    <div v-if="downloadError" class="empty-state">{{ downloadError }}</div>
    <div v-if="loading" class="empty-state">正在加载安全报告...</div>
    <div v-else-if="error" class="empty-state">
      <p>加载失败：{{ error }}</p>
      <button class="ghost-button" type="button" @click="eventId && loadReportView(eventId)">重试</button>
    </div>
    <template v-else-if="data">
      <div class="security-report-summary-strip">
        <article class="security-report-summary-item">
          <span>事件状态</span>
          <div class="security-report-summary-meta">
            <StatusPill :label="eventLabel(data.event.status)" :tone="eventTone(data.event.status)" />
            <StatusPill :label="levelLabel(data.event.event_level)" :tone="levelTone(data.event.event_level)" />
          </div>
        </article>
        <article class="security-report-summary-item">
          <span>攻击载荷命中</span>
          <strong>{{ data.payload_detection.total }} 项</strong>
        </article>
        <article class="security-report-summary-item">
          <span>敏感数据</span>
          <strong>{{ data.sensitive_findings.total }} 处</strong>
        </article>
        <article class="security-report-summary-item">
          <span>关联任务</span>
          <strong>{{ data.task ? `#${data.task.id}` : '无' }}</strong>
        </article>
      </div>

      <section class="content-grid two-column security-report-grid">
        <div class="security-report-main">
          <PageSection eyebrow="报告" title="安全报告概览" tag="明细" tone="warn">
            <div class="security-report-card-list">
              <article class="info-card">
                <div class="card-head">
                  <div>
                    <h4>{{ eventTypeLabel(data.event.event_type) }}</h4>
                  </div>
                  <StatusPill :label="eventLabel(data.event.status)" :tone="eventTone(data.event.status)" />
                </div>
                <p class="code-inline">{{ eventSourceLabel(data.event.source) }} -> {{ displayText(data.event.target) }}</p>
                <p>{{ displayText(data.event.detail) }}</p>
              </article>

              <article v-if="data.report" class="field-card field-card-compact">
                <div class="field-head">
                  <div>
                    <h4>报告摘要</h4>
                  </div>
                  <small class="field-count">{{ reportDisplayName }}</small>
                </div>
                <div class="security-report-line-list">
                  <div
                    v-for="item in reportSummaryEntries"
                    :key="item.id"
                    class="security-report-line security-report-line-fact"
                  >
                    <span class="security-report-line-label">{{ item.label }}</span>
                    <strong class="security-report-line-value">{{ item.value }}</strong>
                  </div>
                </div>
              </article>

              <article class="field-card field-card-compact">
                <div class="field-head">
                  <div>
                    <h4>攻击载荷命中</h4>
                  </div>
                  <small class="field-count">{{ payloadSections.length ? `${payloadSections.length} 组` : '无命中' }}</small>
                </div>
                <div class="detail-block">
                  <p class="security-summary-note">{{ reportTriggerSummary }}</p>
                  <p class="security-summary-subnote">{{ reportTriggerSupportText }}</p>
                </div>
                <div v-if="payloadSections.length" class="security-disclosure-list">
                  <article
                    v-for="section in payloadSections"
                    :key="section.key"
                    class="security-disclosure-card"
                  >
                    <button class="security-disclosure-toggle" type="button" @click="togglePayloadSection(section.key)">
                      <div class="security-disclosure-copy">
                        <strong>{{ section.label }}</strong>
                        <p>{{ section.summary }}</p>
                      </div>
                      <div class="security-disclosure-meta">
                        <StatusPill :label="`${section.items.length} 项`" :tone="section.tone" />
                        <span class="security-disclosure-action">{{ isPayloadSectionExpanded(section.key) ? '收起' : '展开' }}</span>
                      </div>
                    </button>
                    <div v-if="isPayloadSectionExpanded(section.key)" class="security-disclosure-body">
                      <div class="security-report-list">
                        <button
                          v-for="(item, index) in section.items"
                          :key="`${item.kind}-${item.label}-${item.location}-${index}`"
                          :class="['security-report-list-row', 'security-report-list-button', { interactive: canLocatePayloadItem(item) }]"
                          :disabled="!canLocatePayloadItem(item)"
                          type="button"
                          @click="focusPayloadItem(item)"
                        >
                          <div class="security-report-list-main">
                            <div class="security-report-list-head">
                              <strong>{{ payloadDisplayLabel(item) }}</strong>
                              <StatusPill :label="payloadKindLabel(item.kind)" :tone="payloadTone(item.kind)" />
                            </div>
                            <p>{{ payloadDisplayDetail(item) }}</p>
                            <div class="security-report-list-meta">
                              <span>{{ payloadSourceLabel(item) }}</span>
                              <span v-if="item.category_label">{{ item.category_label }}</span>
                              <span v-if="item.location">{{ payloadLocationLabel(item) }}</span>
                              <span v-if="canLocatePayloadItem(item)">点击定位</span>
                            </div>
                            <p v-if="item.evidence" class="code-inline security-report-evidence">{{ displayText(item.evidence) }}</p>
                          </div>
                        </button>
                      </div>
                    </div>
                  </article>
                </div>
                <div v-else class="token-empty">未发现额外的 payload 命中明细。</div>
              </article>

              <article class="field-card field-card-compact">
                <div class="field-head">
                  <div>
                    <h4>敏感数据识别</h4>
                  </div>
                  <small class="field-count">{{ displayText(data.sensitive_findings.summary_text) }}</small>
                </div>
                <div v-if="sensitiveCategories.length" class="token-list">
                  <span
                    v-for="item in sensitiveCategories"
                    :key="item.category"
                    class="token-chip"
                  >
                    <span>{{ item.label }} {{ item.count }}</span>
                  </span>
                </div>
                <div v-if="sensitiveItems.length" class="security-report-list">
                  <button
                    v-for="(item, index) in sensitiveItems"
                    :key="`${item.category}-${item.location}-${index}`"
                    :class="['security-report-list-row', 'security-report-list-button', { interactive: canLocateSensitiveItem(item) }]"
                    :disabled="!canLocateSensitiveItem(item)"
                    type="button"
                    @click="focusSensitiveItem(item)"
                  >
                    <div class="security-report-list-main">
                      <div class="security-report-list-head">
                        <strong>{{ item.label }}</strong>
                        <span class="security-report-muted">{{ sourceLabel(item.source) }}</span>
                      </div>
                      <div class="security-report-list-meta">
                        <span>{{ locationLabel(item.location) }}</span>
                        <span v-if="canLocateSensitiveItem(item)">点击定位</span>
                      </div>
                      <p class="code-inline security-report-evidence">{{ displayText(item.preview) }}</p>
                    </div>
                  </button>
                </div>
                <div v-else class="token-empty">未识别到敏感数据。</div>
              </article>
            </div>
          </PageSection>

          <PageSection eyebrow="原始数据" title="原始传递数据" tone="info">
            <template #toolbar>
              <div class="section-toolbar">
                <div class="section-toolbar-copy">
                  <h4>原始数据视图</h4>
                  <div class="section-toolbar-meta">
                    <span>命中行 {{ hitRawRows }}</span>
                    <span>总行数 {{ totalRawRows }}</span>
                    <span v-if="activeRawLocationKey">已定位到命中行</span>
                  </div>
                </div>
                <div class="section-toolbar-actions">
                  <button
                    class="ghost-button small"
                    :class="{ active: rawFilterMode === 'hits' }"
                    type="button"
                    @click="rawFilterMode = 'hits'"
                  >
                    只看命中行
                  </button>
                  <button
                    class="ghost-button small"
                    :class="{ active: rawFilterMode === 'all' }"
                    type="button"
                    @click="rawFilterMode = 'all'"
                  >
                    展开全部
                  </button>
                </div>
              </div>
            </template>

            <div v-if="visibleRawSectionViews.length" class="security-raw-section-list">
              <article
                v-for="item in visibleRawSectionViews"
                :key="item.section.key"
                class="field-card field-card-compact security-raw-section"
              >
                <div class="field-head">
                  <div>
                    <h4>{{ item.section.title }}</h4>
                  </div>
                  <small class="field-count">
                    {{ rawFilterMode === 'hits' ? item.rows.filter((row) => row.hasHits).length : item.rows.length }}
                    / {{ item.rows.length }}
                  </small>
                </div>
                <RawSectionHighlighter
                  :rows="item.rows"
                  :show-hits-only="rawFilterMode === 'hits'"
                  :active-location-key="activeRawLocationKey"
                />
              </article>
            </div>
            <div v-else class="empty-state">当前筛选条件下没有可显示的原始数据。</div>
          </PageSection>
        </div>

        <div class="security-report-side">
          <PageSection eyebrow="链路" title="执行链路" tone="safe">
            <div class="security-report-card-list">
              <article class="field-card field-card-compact">
                <div class="field-head">
                  <div>
                    <h4>授权判定</h4>
                  </div>
                  <small class="field-count">控制面</small>
                </div>
                <div v-if="guardTrace">
                  <div class="token-list">
                    <StatusPill
                      :label="guardDecisionLabel(guardTrace.decision)"
                      :tone="guardDecisionTone(guardTrace.decision)"
                    />
                    <StatusPill
                      :label="guardSourceLabel(guardTrace.source)"
                      :tone="guardTrace.reused ? 'safe' : 'info'"
                    />
                    <StatusPill
                      :label="guardTrace.ai_review_invoked ? '已触发 AI 复核' : '未触发 AI 复核'"
                      :tone="guardTrace.ai_review_invoked ? 'warn' : 'info'"
                    />
                  </div>
                  <div class="detail-block">
                    <p class="security-summary-note">{{ reportTriggerSummary }}</p>
                    <p class="security-summary-subnote">{{ `${guardSourceLabel(guardTrace.source)} / ${reportTriggerSupportText}` }}</p>
                  </div>
                </div>
                <div v-else class="token-empty">没有可用的授权链路数据。</div>
              </article>

              <article class="field-card field-card-compact">
                <div class="field-head">
                  <div>
                    <h4>操作日志</h4>
                  </div>
                  <small class="field-count">{{ operationLogs.length }} 条</small>
                </div>
                <div v-if="operationLogs.length" class="log-list">
                  <div
                    v-for="(item, index) in operationLogs"
                    :key="`${item.time}-${index}`"
                    class="log-row"
                  >
                    <strong>{{ operationActionLabel(item) }}</strong>
                    <span>{{ operationOperatorLabel(item) }} / {{ item.time }}</span>
                  </div>
                </div>
                <div v-else class="token-empty">当前事件没有操作日志。</div>
              </article>
            </div>
          </PageSection>
        </div>
      </section>
    </template>
  </section>
</template>
