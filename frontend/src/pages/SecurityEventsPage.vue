<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import {
  api,
  type GuardTrace,
  type SecurityEventDetail,
  type SecurityEventSummary,
  type SecurityTriggerItem,
  type SecurityTriggerSection,
} from '../services/api'
import {
  eventStatusLabel,
  eventStatusTone,
  normalizeEventStatus,
  type SecurityEventStatus,
} from '../services/eventStatus'
import { redactSensitiveText } from '../services/redaction'

type Tone = 'safe' | 'warn' | 'danger' | 'info'
type EventStatus = SecurityEventStatus
type EventFilter = '全部' | '高危' | '可疑' | '已拦截' | '已放行'
type TriggerSectionKey = SecurityTriggerSection['key']
type TriggerSection = SecurityTriggerSection

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

const router = useRouter()
const filters: EventFilter[] = ['全部', '高危', '可疑', '已拦截', '已放行']

const activeFilter = ref<EventFilter>('全部')
const currentPage = ref(1)
const pageSize = 10
const DETAIL_LOG_PAGE_SIZE = 5
const selectedEventIds = ref<number[]>([])
const selectedEventId = ref<number | null>(null)
const eventDetail = ref<SecurityEventDetail | null>(null)
const detailLoading = ref(false)
const detailError = ref<string | null>(null)
const mutatingKey = ref<string | null>(null)
const mutationError = ref<string | null>(null)
const detailLogPage = ref(1)
const triggerSectionExpanded = ref<Record<TriggerSectionKey, boolean>>(createCollapsedTriggerSectionState())

const { data, loading, error, refresh } = useAsyncData(
  () =>
    api.securityEvents({
      page: currentPage.value,
      page_size: pageSize,
      ...buildEventQuery(activeFilter.value)
    }),
  false
)

const allEvents = computed(() => data.value?.items ?? [])
const eventTotal = computed(() => data.value?.total ?? 0)
const eventTotalPages = computed(() => Math.max(1, Math.ceil(eventTotal.value / pageSize)))
const isMutating = computed(() => mutatingKey.value !== null)

const filteredEvents = computed(() => allEvents.value)

const selectedEvents = computed(() =>
  filteredEvents.value.filter((item) => selectedEventIds.value.includes(item.id))
)

const selectedEvent = computed(
  () =>
    filteredEvents.value.find((item) => item.id === selectedEventId.value) ??
    allEvents.value.find((item) => item.id === selectedEventId.value) ??
    null
)

const resolvedEventDetail = computed<SecurityEventDetail | null>(() => {
  if (eventDetail.value && eventDetail.value.id === selectedEventId.value) {
    return eventDetail.value
  }

  if (!selectedEvent.value) {
    return null
  }

  return {
    ...selectedEvent.value,
    hit_rules: selectedEvent.value.hit_rules ?? [],
    guard_trace: selectedEvent.value.guard_trace ?? null,
    raw_input: '',
    result: '',
    operation_logs: []
  }
})

const resolvedGuardTrace = computed<GuardTrace | null>(() => resolvedEventDetail.value?.guard_trace ?? selectedEvent.value?.guard_trace ?? null)
const detailLogs = computed(() => resolvedEventDetail.value?.operation_logs ?? [])
const detailLogTotalPages = computed(() => Math.max(1, Math.ceil(detailLogs.value.length / DETAIL_LOG_PAGE_SIZE)))
const pagedDetailLogs = computed(() => {
  const start = (detailLogPage.value - 1) * DETAIL_LOG_PAGE_SIZE
  return detailLogs.value.slice(start, start + DETAIL_LOG_PAGE_SIZE)
})
const triggerSections = computed<TriggerSection[]>(() => {
  if (resolvedEventDetail.value?.trigger_sections?.length) {
    return resolvedEventDetail.value.trigger_sections
  }

  const controls = uniqueStrings(resolvedGuardTrace.value?.matched_controls ?? [])
  const rules = uniqueStrings([
    ...(resolvedEventDetail.value?.hit_rules ?? []),
    ...(resolvedGuardTrace.value?.matched_rules ?? []),
    ...(resolvedGuardTrace.value?.rule_assessment?.hit_rules ?? [])
  ])
  const signals = uniqueStrings(resolvedGuardTrace.value?.rule_assessment?.matched_signals ?? [])

  return ([
    {
      key: 'control',
      label: '控制面',
      tone: 'safe',
      items: controls.map(
        (item) =>
          ({
            key: item,
            label: policyKeyLabel(item),
            detail: '',
            tone: 'safe',
            kind: 'control'
          } as SecurityTriggerItem)
      ),
      summary: buildTriggerSectionSummary('control', controls)
    },
    {
      key: 'rule',
      label: '规则',
      tone: 'warn',
      items: rules.map(
        (item) =>
          ({
            key: item,
            label: policyKeyLabel(item),
            detail: '',
            tone: 'warn',
            kind: 'rule'
          } as SecurityTriggerItem)
      ),
      summary: buildTriggerSectionSummary('rule', rules)
    },
    {
      key: 'signal',
      label: '信号',
      tone: 'danger',
      items: signals.map(
        (item) =>
          ({
            key: item,
            label: signalLabel(item),
            detail: '',
            tone: 'danger',
            kind: 'signal'
          } as SecurityTriggerItem)
      ),
      summary: buildTriggerSectionSummary('signal', signals)
    }
  ] satisfies TriggerSection[]).filter((section) => section.items.length)
})

watch(
  activeFilter,
  () => {
    selectedEventIds.value = []
    mutationError.value = null
    if (currentPage.value === 1) {
      void refresh()
      return
    }
    currentPage.value = 1
  }
)

watch(
  currentPage,
  () => {
    selectedEventIds.value = []
    mutationError.value = null
    void refresh()
  },
  { immediate: true }
)

watch(
  eventTotalPages,
  (totalPages) => {
    if (currentPage.value > totalPages) {
      currentPage.value = totalPages
    }
  }
)

watch(
  detailLogTotalPages,
  (totalPages) => {
    if (detailLogPage.value > totalPages) {
      detailLogPage.value = totalPages
    }
  }
)

watch(
  filteredEvents,
  (items) => {
    const visibleIds = new Set(items.map((item) => item.id))
    selectedEventIds.value = selectedEventIds.value.filter((item) => visibleIds.has(item))

    if (!items.length) {
      selectedEventId.value = null
      eventDetail.value = null
      detailError.value = null
      return
    }

    if (!selectedEventId.value || !visibleIds.has(selectedEventId.value)) {
      selectedEventId.value = items[0].id
    }
  },
  { immediate: true }
)

watch(selectedEventId, (eventId) => {
  triggerSectionExpanded.value = createCollapsedTriggerSectionState()
  detailLogPage.value = 1
  if (!eventId) {
    eventDetail.value = null
    detailError.value = null
    return
  }
  void loadEventDetail(eventId)
})

function displayText(value?: string | null) {
  return redactSensitiveText(value)
}

function normalizeEventLevel(level: string) {
  const lowered = level.toLowerCase()
  if (lowered === 'high') return 'high'
  if (lowered === 'low') return 'low'
  return 'medium'
}

function isHighRiskEvent(level: string) {
  return normalizeEventLevel(level) === 'high'
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
  return type.replace(/_/g, ' ')
}

function policyKeyLabel(value?: string | null) {
  const key = (value || '').trim()
  return CONTROL_LABELS[key] || RULE_LABELS[key] || key || '未命名项'
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

function createCollapsedTriggerSectionState(): Record<TriggerSectionKey, boolean> {
  return {
    control: false,
    rule: false,
    signal: false
  }
}

function buildEventQuery(filter: EventFilter) {
  if (filter === '高危') {
    return {
      event_level: 'high'
    }
  }
  if (filter === '可疑') {
    return {
      status: 'suspicious'
    }
  }
  if (filter === '已拦截') {
    return {
      status: 'intercepted'
    }
  }
  if (filter === '已放行') {
    return {
      status: 'allowed'
    }
  }
  return {}
}

function uniqueStrings(values: Array<string | null | undefined>) {
  const seen = new Set<string>()
  const items: string[] = []
  for (const value of values) {
    const normalized = String(value || '').trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    items.push(normalized)
  }
  return items
}

function isAiReviewDisabled(trace?: GuardTrace | null) {
  const reviewDecision = (trace?.review_decision || '').trim().toLowerCase()
  const reviewMode = (trace?.ai_review_mode || '').trim().toLowerCase()
  return reviewDecision === 'target_protection_disabled' || reviewDecision === 'rules_only_mode' || reviewMode === 'rules_only'
}

function buildTriggerSectionSummary(key: TriggerSectionKey, items: string[]) {
  if (!items.length) {
    return `当前没有 ${key === 'control' ? '控制面' : key === 'rule' ? '规则' : '信号'} 命中。`
  }

  const preview = items
    .slice(0, 2)
    .map((item) => (key === 'signal' ? signalLabel(item) : policyKeyLabel(item)))
    .join('、')
  const suffix = preview ? `：${preview}${items.length > 2 ? ' 等' : ''}` : ''

  if (key === 'control') return `命中 ${items.length} 个控制面${suffix}`
  if (key === 'rule') return `命中 ${items.length} 条规则${suffix}`
  return `识别 ${items.length} 个攻击信号${suffix}`
}

function buildEventTriggerHeadline(trace?: GuardTrace | null, hitRules: string[] = []) {
  const matchedRules = uniqueStrings([
    ...hitRules,
    ...(trace?.matched_rules ?? []),
    ...(trace?.rule_assessment?.hit_rules ?? [])
  ])
  const matchedControls = uniqueStrings(trace?.matched_controls ?? [])

  if (!trace) {
    return matchedRules.length ? `规则命中 ${matchedRules.length} 条` : '未记录具体触发链路'
  }

  if (trace.decision === 'deny') {
    if (trace.reused) return '复用预检结果后直接拦截'
    if (trace.rule_verdict === 'blocked' || matchedRules.length) return '规则已直接拦截'
    if (matchedControls.length) return '控制面已直接拦截'
    return '授权链路已直接拦截'
  }

  if (trace.decision === 'review') {
    return trace.ai_review_invoked ? '规则命中后进入 AI 复核' : '规则命中，当前等待复核'
  }

  if (trace.ai_review_invoked) return 'AI 复核后继续执行'
  if (trace.rule_verdict === 'clean') return '未命中明确攻击'
  if (matchedRules.length || matchedControls.length) return '已命中防护项'
  return '未记录具体触发链路'
}

function buildEventTriggerSupportText(trace?: GuardTrace | null, hitRules: string[] = []) {
  const matchedRules = uniqueStrings([
    ...hitRules,
    ...(trace?.matched_rules ?? []),
    ...(trace?.rule_assessment?.hit_rules ?? [])
  ])
  const matchedControls = uniqueStrings(trace?.matched_controls ?? [])
  const matchedSignals = uniqueStrings(trace?.rule_assessment?.matched_signals ?? [])
  const fragments: string[] = []

  if (!trace) {
    if (matchedRules.length) {
      fragments.push(`规则 ${matchedRules.length} 条`)
    }
    return fragments.join(' / ') || '没有控制面或 AI 复核记录'
  }

  if (trace.ai_review_invoked) {
    fragments.push('AI 复核已触发')
  } else if (trace.review_decision?.trim().toLowerCase() === 'target_protection_disabled') {
    fragments.push('AI 复核未开启')
  } else if (isAiReviewDisabled(trace)) {
    fragments.push('当前仅按规则判定')
  } else if (trace.review_decision?.trim().toLowerCase() === 'confirmed_by_policy') {
    fragments.push('已由规则直接定性')
  } else if (trace.review_decision?.trim().toLowerCase() === 'review_suspicious_only') {
    fragments.push('当前仅复核可疑流量')
  } else if (trace.review_decision?.trim().toLowerCase() === 'review_all_remaining') {
    fragments.push('当前其余流量可进 AI 复核')
  } else {
    fragments.push('未触发 AI 复核')
  }

  if (matchedControls.length) fragments.push(`控制面 ${matchedControls.length} 项`)
  if (matchedRules.length) fragments.push(`规则 ${matchedRules.length} 条`)
  if (matchedSignals.length) fragments.push(`信号 ${matchedSignals.length} 个`)

  return fragments.join(' / ')
}

function isTriggerSectionExpanded(key: TriggerSectionKey) {
  return triggerSectionExpanded.value[key]
}

function toggleTriggerSection(key: TriggerSectionKey) {
  triggerSectionExpanded.value = {
    ...triggerSectionExpanded.value,
    [key]: !triggerSectionExpanded.value[key]
  }
}

function isSelected(eventId: number) {
  return selectedEventIds.value.includes(eventId)
}

function focusEvent(eventId: number) {
  selectedEventId.value = eventId
  mutationError.value = null
}

function toggleSelection(eventId: number) {
  if (isSelected(eventId)) {
    selectedEventIds.value = selectedEventIds.value.filter((item) => item !== eventId)
    return
  }
  selectedEventIds.value = [...selectedEventIds.value, eventId]
}

function selectFilteredEvents() {
  selectedEventIds.value = filteredEvents.value.map((item) => item.id)
}

function clearSelection() {
  selectedEventIds.value = []
}

function replaceEventItem(updated: SecurityEventSummary) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    items: data.value.items.map((item) => (item.id === updated.id ? { ...item, ...updated } : item))
  }

  if (eventDetail.value?.id === updated.id) {
    eventDetail.value = {
      ...eventDetail.value,
      ...updated,
      hit_rules: updated.hit_rules ?? eventDetail.value.hit_rules
    }
  }
}

function replaceEventItems(updatedItems: SecurityEventSummary[]) {
  if (!data.value) {
    return
  }

  const updatedMap = new Map(updatedItems.map((item) => [item.id, item]))
  data.value = {
    ...data.value,
    items: data.value.items.map((item) => updatedMap.get(item.id) ?? item)
  }

  if (eventDetail.value && updatedMap.has(eventDetail.value.id)) {
    const updated = updatedMap.get(eventDetail.value.id)
    if (updated) {
      eventDetail.value = {
        ...eventDetail.value,
        ...updated,
        hit_rules: updated.hit_rules ?? eventDetail.value.hit_rules
      }
    }
  }
}

async function loadEventDetail(eventId: number) {
  detailLoading.value = true
  detailError.value = null

  try {
    const detail = await api.securityEvent(eventId)
    if (selectedEventId.value !== eventId) {
      return
    }
    eventDetail.value = detail
  } catch (err) {
    if (selectedEventId.value !== eventId) {
      return
    }
    eventDetail.value = null
    detailError.value = err instanceof Error ? err.message : '事件详情加载失败'
  } finally {
    if (selectedEventId.value === eventId) {
      detailLoading.value = false
    }
  }
}

async function updateStatus(eventId: number, status: EventStatus) {
  const currentItem = allEvents.value.find((item) => item.id === eventId)
  if (!currentItem || normalizeEventStatus(currentItem.status) === status) {
    return
  }

  mutatingKey.value = `event-${eventId}`
  mutationError.value = null
  try {
    await api.updateSecurityEventStatus(eventId, status)
    await refresh()
  } catch (err) {
    mutationError.value = err instanceof Error ? err.message : '事件状态更新失败'
    await refresh()
  } finally {
    mutatingKey.value = null
  }
}

async function batchHandle(status: EventStatus) {
  if (!selectedEventIds.value.length) {
    return
  }

  mutatingKey.value = `batch-${status}`
  mutationError.value = null
  try {
    await api.batchHandleSecurityEvents({ ids: [...selectedEventIds.value], status })
    await refresh()
    selectedEventIds.value = []
  } catch (err) {
    mutationError.value = err instanceof Error ? err.message : '批量处置失败'
    await refresh()
  } finally {
    mutatingKey.value = null
  }
}

function openReportPage(eventId: number) {
  const target = router.resolve({
    name: 'security-event-report',
    params: { eventId }
  })
  window.open(target.href, '_blank', 'noopener')
}

function previousPage() {
  if (currentPage.value <= 1) {
    return
  }
  currentPage.value -= 1
}

function nextPage() {
  if (currentPage.value >= eventTotalPages.value) {
    return
  }
  currentPage.value += 1
}

function previousDetailLogPage() {
  if (detailLogPage.value <= 1) {
    return
  }
  detailLogPage.value -= 1
}

function nextDetailLogPage() {
  if (detailLogPage.value >= detailLogTotalPages.value) {
    return
  }
  detailLogPage.value += 1
}
</script>

<template>
  <section class="page-grid">
    <section class="content-grid two-column">
      <PageSection eyebrow="事件" title="安全事件" tag="处置台" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>批量操作</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${selectedEvents.length} 条已选`" :tone="selectedEvents.length ? 'warn' : 'info'" />
                <span>当前筛选：{{ activeFilter }}</span>
                <span>第 {{ currentPage }} / {{ eventTotalPages }} 页</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <button class="ghost-button" :disabled="loading || isMutating" type="button" @click="selectFilteredEvents">
                选择当前页
              </button>
              <button class="ghost-button" :disabled="loading || isMutating || !selectedEventIds.length" type="button" @click="clearSelection">
                清空
              </button>
              <button class="ghost-button" :disabled="loading || isMutating || !selectedEventIds.length" type="button" @click="batchHandle('suspicious')">
                标记可疑
              </button>
              <button class="ghost-button" :disabled="loading || isMutating || !selectedEventIds.length" type="button" @click="batchHandle('intercepted')">
                批量拦截
              </button>
              <button class="primary-button" :disabled="loading || isMutating || !selectedEventIds.length" type="button" @click="batchHandle('allowed')">
                批量放行
              </button>
            </div>
          </div>

          <div class="section-toolbar section-toolbar-secondary">
            <div class="section-toolbar-fill">
              <div class="filter-row">
                <button
                  v-for="item in filters"
                  :key="item"
                  :class="['filter-chip', { active: item === activeFilter }]"
                  type="button"
                  @click="activeFilter = item"
                >
                  {{ item }}
                </button>
              </div>
            </div>
          </div>
        </template>

        <div v-if="mutationError" class="empty-state">{{ mutationError }}</div>
        <div v-if="loading" class="empty-state">正在加载安全事件...</div>
        <div v-else-if="error" class="empty-state">
          <p>加载失败：{{ error }}</p>
          <button class="ghost-button" type="button" @click="refresh">重试</button>
        </div>
        <div v-else-if="filteredEvents.length" class="event-worklist event-worklist-compact">
          <article
            v-for="item in filteredEvents"
            :key="item.id"
            :class="[
              'event-workitem',
              'event-workitem-compact',
              {
                active: item.id === selectedEventId,
                selected: isSelected(item.id)
              }
            ]"
          >
            <div class="event-workitem-main">
              <label class="event-workitem-check" title="选择事件">
                <input
                  class="row-selector"
                  :checked="isSelected(item.id)"
                  type="checkbox"
                  @click.stop
                  @change="toggleSelection(item.id)"
                />
              </label>

              <button class="event-workitem-focus" type="button" @click="focusEvent(item.id)">
                <div class="event-workitem-head">
                  <div class="event-workitem-copy">
                    <h4>{{ eventTypeLabel(item.event_type) }}</h4>
                    <p class="event-workitem-source">{{ item.source }} -> {{ item.target }}</p>
                  </div>
                  <div class="event-workitem-meta">
                    <span>{{ item.created_at }}</span>
                    <span>#{{ item.id }}</span>
                    <StatusPill :label="levelLabel(item.event_level)" :tone="levelTone(item.event_level)" />
                    <StatusPill :label="eventLabel(item.status)" :tone="eventTone(item.status)" />
                  </div>
                </div>

                <p class="event-workitem-detail">{{ displayText(item.detail) }}</p>

                <div class="event-workitem-trigger">
                  <strong>{{ item.trigger_summary || buildEventTriggerHeadline(item.guard_trace, item.hit_rules ?? []) }}</strong>
                  <span>{{ item.trigger_support_text || buildEventTriggerSupportText(item.guard_trace, item.hit_rules ?? []) }}</span>
                </div>
              </button>
            </div>

            <div class="event-workitem-actions">
              <div class="event-action-strip">
                <button class="ghost-button small event-report-button" type="button" @click.stop="openReportPage(item.id)">
                  报告
                </button>
                <div class="event-status-strip">
                  <button
                    :class="[
                      'event-status-button',
                      'status-suspicious',
                      { active: normalizeEventStatus(item.status) === 'suspicious' }
                    ]"
                    :aria-pressed="normalizeEventStatus(item.status) === 'suspicious'"
                    :disabled="isMutating"
                    type="button"
                    @click.stop="updateStatus(item.id, 'suspicious')"
                  >
                    可疑
                  </button>
                  <button
                    :class="[
                      'event-status-button',
                      'status-intercepted',
                      { active: normalizeEventStatus(item.status) === 'intercepted' }
                    ]"
                    :aria-pressed="normalizeEventStatus(item.status) === 'intercepted'"
                    :disabled="isMutating"
                    type="button"
                    @click.stop="updateStatus(item.id, 'intercepted')"
                  >
                    拦截
                  </button>
                  <button
                    :class="[
                      'event-status-button',
                      'status-allowed',
                      { active: normalizeEventStatus(item.status) === 'allowed' }
                    ]"
                    :aria-pressed="normalizeEventStatus(item.status) === 'allowed'"
                    :disabled="isMutating"
                    type="button"
                    @click.stop="updateStatus(item.id, 'allowed')"
                  >
                    放行
                  </button>
                </div>
              </div>
            </div>
          </article>
        </div>
        <div v-if="!loading && !error && filteredEvents.length && eventTotal > pageSize" class="sample-pagination">
          <button class="ghost-button" :disabled="currentPage <= 1" type="button" @click="previousPage">
            上一页
          </button>
          <button class="ghost-button" :disabled="currentPage >= eventTotalPages" type="button" @click="nextPage">
            下一页
          </button>
        </div>
        <div v-else-if="!loading && !error" class="empty-state">当前筛选条件下没有安全事件。</div>
      </PageSection>

      <PageSection eyebrow="详情" title="事件详情" tone="safe">
        <div v-if="selectedEvent" class="event-detail-grid">
          <article class="info-card">
            <div class="card-head">
              <div>
                <h4>{{ eventTypeLabel(selectedEvent.event_type) }}</h4>
              </div>
              <StatusPill :label="eventLabel(selectedEvent.status)" :tone="eventTone(selectedEvent.status)" />
            </div>
            <p class="code-inline">{{ displayText(selectedEvent.source) }} -> {{ displayText(selectedEvent.target) }}</p>
            <p>{{ displayText(selectedEvent.detail) }}</p>
            <div class="detail-block">
              <p class="security-summary-note">{{ resolvedEventDetail?.trigger_summary || buildEventTriggerHeadline(resolvedGuardTrace, resolvedEventDetail?.hit_rules ?? []) }}</p>
              <p class="security-summary-subnote">{{ resolvedEventDetail?.trigger_support_text || buildEventTriggerSupportText(resolvedGuardTrace, resolvedEventDetail?.hit_rules ?? []) }}</p>
            </div>
            <div class="section-toolbar section-toolbar-secondary detail-toolbar-inline">
              <div class="section-toolbar-meta">
                <span>事件编号 #{{ selectedEvent.id }}</span>
                <span>时间 {{ selectedEvent.created_at }}</span>
                <span v-if="selectedEvent.task_id">任务 #{{ selectedEvent.task_id }}</span>
              </div>
              <div class="section-toolbar-actions">
                <button class="primary-button small" type="button" @click="openReportPage(selectedEvent.id)">
                  查看安全报告
                </button>
              </div>
            </div>
          </article>

          <article class="field-card field-card-compact">
            <div class="field-head">
              <div>
                <h4>单条处置</h4>
              </div>
              <small class="field-count">状态切换</small>
            </div>
            <div class="mode-group">
              <button
                class="mode-button"
                :class="{ active: normalizeEventStatus(selectedEvent.status) === 'suspicious' }"
                :disabled="isMutating || normalizeEventStatus(selectedEvent.status) === 'suspicious'"
                type="button"
                @click="updateStatus(selectedEvent.id, 'suspicious')"
              >
                可疑
              </button>
              <button
                class="mode-button"
                :class="{ active: normalizeEventStatus(selectedEvent.status) === 'intercepted' }"
                :disabled="isMutating || normalizeEventStatus(selectedEvent.status) === 'intercepted'"
                type="button"
                @click="updateStatus(selectedEvent.id, 'intercepted')"
              >
                拦截
              </button>
              <button
                class="mode-button"
                :class="{ active: normalizeEventStatus(selectedEvent.status) === 'allowed' }"
                :disabled="isMutating || normalizeEventStatus(selectedEvent.status) === 'allowed'"
                type="button"
                @click="updateStatus(selectedEvent.id, 'allowed')"
              >
                放行
              </button>
            </div>
          </article>

          <article class="field-card field-card-compact">
            <div class="field-head">
              <div>
                <h4>告警触发</h4>
              </div>
              <small class="field-count">{{ triggerSections.length ? '默认收起' : '未命中详情' }}</small>
            </div>
            <div class="detail-block">
              <p class="security-summary-note">{{ resolvedEventDetail?.trigger_summary || buildEventTriggerHeadline(resolvedGuardTrace, resolvedEventDetail?.hit_rules ?? []) }}</p>
              <p class="security-summary-subnote">{{ resolvedEventDetail?.trigger_support_text || buildEventTriggerSupportText(resolvedGuardTrace, resolvedEventDetail?.hit_rules ?? []) }}</p>
            </div>
            <div v-if="triggerSections.length" class="security-disclosure-list">
              <article
                v-for="section in triggerSections"
                :key="section.key"
                class="security-disclosure-card"
              >
                <button class="security-disclosure-toggle" type="button" @click="toggleTriggerSection(section.key)">
                  <div class="security-disclosure-copy">
                    <strong>{{ section.label }}</strong>
                    <p>{{ section.summary }}</p>
                  </div>
                  <div class="security-disclosure-meta">
                    <StatusPill :label="`${section.items.length} 项`" :tone="section.tone" />
                    <span class="security-disclosure-action">{{ isTriggerSectionExpanded(section.key) ? '收起' : '展开' }}</span>
                  </div>
                </button>
                <div v-if="isTriggerSectionExpanded(section.key)" class="security-disclosure-body">
                  <div class="token-list">
                    <span
                      v-for="item in section.items"
                      :key="`${section.key}-${item.key}`"
                      class="token-chip"
                    >
                      <span>{{ item.label }}</span>
                    </span>
                  </div>
                </div>
              </article>
            </div>
            <div v-else class="token-empty">当前事件没有可展开的控制面、规则或信号明细。</div>
          </article>

          <article class="field-card field-card-compact">
            <div class="field-head">
              <div>
                <h4>操作日志</h4>
              </div>
              <small class="field-count">
                {{ detailLoading ? '加载中' : detailLogs.length ? `第 ${detailLogPage} / ${detailLogTotalPages} 页` : '事件审计' }}
              </small>
            </div>
            <div v-if="detailLoading" class="token-empty">正在加载事件日志...</div>
            <div v-else-if="detailError" class="empty-state">
              <p>详情加载失败：{{ detailError }}</p>
              <button class="ghost-button" type="button" @click="selectedEventId && loadEventDetail(selectedEventId)">重试</button>
            </div>
            <div v-else-if="detailLogs.length" class="log-list">
              <div
                v-for="(item, index) in pagedDetailLogs"
                :key="`${item.time}-${index}`"
                class="log-row"
              >
                <strong>{{ item.action }}</strong>
                <span>{{ item.operator }} / {{ item.time }}</span>
              </div>
              <div v-if="detailLogs.length > DETAIL_LOG_PAGE_SIZE" class="sample-pagination detail-log-pagination">
                <button class="ghost-button" :disabled="detailLogPage <= 1" type="button" @click="previousDetailLogPage">
                  上一页
                </button>
                <button
                  class="ghost-button"
                  :disabled="detailLogPage >= detailLogTotalPages"
                  type="button"
                  @click="nextDetailLogPage"
                >
                  下一页
                </button>
              </div>
            </div>
            <div v-else class="token-empty">当前事件还没有日志。</div>
          </article>
        </div>
        <div v-else class="empty-state">先从左侧选择一条安全事件。</div>
      </PageSection>
    </section>
  </section>
</template>
