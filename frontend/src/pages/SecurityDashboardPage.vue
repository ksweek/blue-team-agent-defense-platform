<script setup lang="ts">
import { computed, ref } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import { api } from '../services/api'
import { eventStatusLabel, eventStatusRank, eventStatusTone, normalizeEventStatus } from '../services/eventStatus'

type Tone = 'safe' | 'warn' | 'danger' | 'info'
type TrendMetricKey = 'attack' | 'block' | 'false_positive'
type EventSortMode = 'latest' | 'high-risk' | 'suspicious'
type TrendItem = {
  day: string
  attack: number
  block: number
  false_positive: number
}
type DashboardEvent = {
  id: string | number
  created_at: string
  event_type: string
  event_level: string
  status: string
  source: string
  target: string
  detail: string
}
type TrendInsight = TrendItem & {
  total: number
  totalDelta: number | null
  previousDay: string | null
  metricDeltas: Record<TrendMetricKey, number | null>
}

const shortcutItems = [
  { label: '安全事件', to: '/security-events', meta: '告警研判与处置', tone: 'danger' as Tone },
  { label: '防御配置', to: '/defense-config', meta: '规则、模式与覆盖面', tone: 'safe' as Tone },
  { label: '资产保护', to: '/asset-protection', meta: '路径、白名单与保护对象', tone: 'info' as Tone },
  { label: 'AI 目标', to: '/ai-endpoints', meta: '模型接入与防护路由', tone: 'warn' as Tone },
] as const

const surfaceItems = [
  {
    title: '提示注入',
    tag: '高危',
    tone: 'danger' as Tone,
    detail: '覆盖直接注入、间接注入、多轮污染和组合式攻击链。'
  },
  {
    title: '越权调用',
    tag: '高危',
    tone: 'danger' as Tone,
    detail: '关注未授权工具、受保护路径、技能与插件链调用。'
  },
  {
    title: '权限绕过',
    tag: '中高',
    tone: 'warn' as Tone,
    detail: '重点观察角色借用、审批绕过和跨插件联动失控。'
  },
  {
    title: '输出泄露',
    tag: '中高',
    tone: 'warn' as Tone,
    detail: '核查原始响应、敏感数据脱敏和回传内容暴露风险。'
  },
] as const

const eventSortOptions = [
  { key: 'latest', label: '最新' },
  { key: 'high-risk', label: '高危优先' },
  { key: 'suspicious', label: '可疑优先' },
] as const satisfies ReadonlyArray<{ key: EventSortMode; label: string }>
const eventSortMode = ref<EventSortMode>('latest')

const { data, loading, error, refresh } = useAsyncData(async () => {
  const [overview, trends, sessions, events] = await Promise.all([
    api.dashboardOverview(),
    api.dashboardTrends(),
    api.dashboardSessions(),
    api.securityEvents(),
  ])

  return { overview, trends, sessions, events }
})

const overview = computed(() => ({
  attackCount: data.value?.overview.attack_count ?? 0,
  blockedCount: data.value?.overview.blocked_count ?? 0,
  defenseCount: data.value?.overview.enabled_defense_count ?? 0,
  highRiskCount: data.value?.overview.high_risk_event_count ?? 0,
  activeTaskCount: data.value?.overview.active_task_count ?? 0,
}))

const blockRate = computed(() => {
  if (!overview.value.attackCount) {
    return 0
  }
  return Math.round((overview.value.blockedCount / overview.value.attackCount) * 100)
})

const heroTone = computed<Tone>(() => {
  if (overview.value.highRiskCount >= 6) return 'danger'
  if (overview.value.highRiskCount >= 2 || overview.value.activeTaskCount >= 3) return 'warn'
  return 'safe'
})

const heroSummary = computed(() => {
  if (overview.value.highRiskCount >= 6) {
    return '高危事件持续堆积，建议优先进入安全事件页处理。'
  }
  if (overview.value.activeTaskCount >= 3) {
    return '当前有多条执行链路活跃，建议关注运行态与报告回传。'
  }
  if (overview.value.attackCount) {
    return '整体处于可控区间，当前可重点关注覆盖面与趋势变化。'
  }
  return '当前没有新增攻击压力，可继续完善防线覆盖与联动策略。'
})

const heroMeta = computed(() => [
  `拦截率 ${blockRate.value}%`,
  `启用防线 ${overview.value.defenseCount}`,
  `活跃任务 ${overview.value.activeTaskCount}`,
])

const statCards = computed(() => [
  {
    label: '总攻击任务',
    value: overview.value.attackCount,
    note: '累计进入执行链的任务',
    tone: 'danger' as Tone,
  },
  {
    label: '已拦截',
    value: overview.value.blockedCount,
    note: '命中规则或控制面后拦截',
    tone: 'safe' as Tone,
  },
  {
    label: '高危事件',
    value: overview.value.highRiskCount,
    note: '需要优先关注的告警',
    tone: 'warn' as Tone,
  },
  {
    label: '启用防线',
    value: overview.value.defenseCount,
    note: '当前已生效的防御项',
    tone: 'info' as Tone,
  },
  {
    label: '活跃任务',
    value: overview.value.activeTaskCount,
    note: '运行中或待研判执行链',
    tone: 'warn' as Tone,
  },
])

const sessionCards = computed(() => data.value?.sessions.items ?? [])
const sessionPreview = computed(() => sessionCards.value.slice(0, 5))
const sessionOverflowCount = computed(() => Math.max(sessionCards.value.length - sessionPreview.value.length, 0))

const trendSeries = computed<TrendItem[]>(() => data.value?.trends.items ?? [])
const trendInsights = computed<TrendInsight[]>(() =>
  trendSeries.value.map((item, index, items) => {
    const previous = index > 0 ? items[index - 1] : null
    const total = item.attack + item.block + item.false_positive
    const previousTotal = previous ? previous.attack + previous.block + previous.false_positive : null

    return {
      ...item,
      total,
      totalDelta: previousTotal === null ? null : total - previousTotal,
      previousDay: previous?.day ?? null,
      metricDeltas: {
        attack: previous ? item.attack - previous.attack : null,
        block: previous ? item.block - previous.block : null,
        false_positive: previous ? item.false_positive - previous.false_positive : null,
      },
    }
  }),
)
const totalTrendAttack = computed(() => trendSeries.value.reduce((sum, item) => sum + item.attack, 0))
const totalTrendBlock = computed(() => trendSeries.value.reduce((sum, item) => sum + item.block, 0))
const totalTrendFalsePositive = computed(() => trendSeries.value.reduce((sum, item) => sum + item.false_positive, 0))
const maxTrendTotal = computed(() => Math.max(1, ...trendInsights.value.map((item) => item.total)))
const trendPeakDay = computed(() => {
  if (!trendInsights.value.length) {
    return null
  }

  return trendInsights.value.reduce((peak, item) => {
    return item.total > peak.total ? item : peak
  })
})
const trendThresholds = computed<Record<TrendMetricKey, number>>(() => ({
  attack: buildTrendThreshold(trendSeries.value.map((item) => item.attack)),
  block: buildTrendThreshold(trendSeries.value.map((item) => item.block)),
  false_positive: buildTrendThreshold(trendSeries.value.map((item) => item.false_positive)),
}))
const trendTotalThreshold = computed(() =>
  buildTrendThreshold(
    trendSeries.value.map((item) => item.attack + item.block + item.false_positive),
  ),
)
const trendAnomalyDays = computed(() => trendInsights.value.filter((item) => isTrendAnomalyDay(item)))
const trendAnomalySummary = computed(() => {
  if (!trendAnomalyDays.value.length) {
    return '当前未出现超阈值波动'
  }

  return trendAnomalyDays.value.map((item) => compactDayLabel(item.day)).join(' / ')
})

const dashboardEvents = computed<DashboardEvent[]>(() => data.value?.events.items ?? [])
const recentEvents = computed(() => {
  const items = [...dashboardEvents.value]

  items.sort((left, right) => compareDashboardEvents(left, right))
  return items.slice(0, 6)
})
const blockedRecentEvents = computed(
  () => recentEvents.value.filter((item) => normalizeEventStatus(item.status) === 'intercepted').length,
)
const highRiskRecentEvents = computed(
  () => recentEvents.value.filter((item) => normalizeLevel(item.event_level) === 'high').length,
)

function normalizeLevel(level: string) {
  const lowered = level.toLowerCase()
  if (lowered === 'high' || level.includes('高')) return 'high'
  if (lowered === 'low' || level.includes('低')) return 'low'
  return 'medium'
}

function levelTone(level: string): Tone {
  if (normalizeLevel(level) === 'high') return 'danger'
  if (normalizeLevel(level) === 'medium') return 'warn'
  return 'safe'
}

function levelLabel(level: string) {
  if (normalizeLevel(level) === 'high') return '高危'
  if (normalizeLevel(level) === 'medium') return '中危'
  return '低危'
}

function statusTone(status: string): Tone {
  if (status === 'running') return 'warn'
  if (status === 'queued') return 'info'
  if (status === 'done') return 'safe'
  return eventStatusTone(status)
}

function statusLabel(status: string) {
  if (status === 'running') return '运行中'
  if (status === 'queued') return '排队中'
  if (status === 'done') return '已完成'
  return eventStatusLabel(status)
}

function eventTypeLabel(type: string) {
  if (type === 'prompt_injection') return '提示注入'
  if (type === 'asset_access') return '资产访问'
  if (type === 'skill_scan') return '技能扫描'
  return type.replace(/_/g, ' ')
}

function eventLevelRank(level: string) {
  if (normalizeLevel(level) === 'high') return 0
  if (normalizeLevel(level) === 'medium') return 1
  return 2
}

function eventTimeValue(value: string) {
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? 0 : parsed
}

function compareDashboardEvents(left: DashboardEvent, right: DashboardEvent) {
  const timeDelta = eventTimeValue(right.created_at) - eventTimeValue(left.created_at)

  if (eventSortMode.value === 'high-risk') {
    const levelDelta = eventLevelRank(left.event_level) - eventLevelRank(right.event_level)
    if (levelDelta !== 0) return levelDelta

    const statusDelta = eventStatusRank(left.status) - eventStatusRank(right.status)
    if (statusDelta !== 0) return statusDelta

    return timeDelta
  }

  if (eventSortMode.value === 'suspicious') {
    const statusDelta = eventStatusRank(left.status) - eventStatusRank(right.status)
    if (statusDelta !== 0) return statusDelta

    const levelDelta = eventLevelRank(left.event_level) - eventLevelRank(right.event_level)
    if (levelDelta !== 0) return levelDelta

    return timeDelta
  }

  const levelDelta = eventLevelRank(left.event_level) - eventLevelRank(right.event_level)
  if (timeDelta !== 0) return timeDelta
  return levelDelta
}

function buildTrendThreshold(values: number[]) {
  if (!values.length) {
    return 1
  }

  const average = values.reduce((sum, value) => sum + value, 0) / values.length
  const variance = values.reduce((sum, value) => sum + (value - average) ** 2, 0) / values.length
  const deviation = Math.sqrt(variance)

  if (deviation < 0.35) {
    return Math.ceil(Math.max(...values) + 1)
  }

  return Math.max(1, Math.ceil(average + deviation * 0.6))
}

function trendTotalFillWidth(total: number) {
  if (!total) {
    return '0%'
  }

  return `${Math.max(10, (total / maxTrendTotal.value) * 100)}%`
}

function trendMetricWidth(value: number, total: number) {
  if (!value || !total) {
    return '0%'
  }

  return `${(value / total) * 100}%`
}

function isTrendPeakDay(day: string) {
  return trendPeakDay.value?.day === day
}

function isTrendMetricAnomaly(item: TrendItem | TrendInsight, key: TrendMetricKey) {
  return item[key] >= trendThresholds.value[key] && item[key] > 0
}

function isTrendAnomalyDay(item: TrendItem | TrendInsight) {
  const total = 'total' in item ? item.total : item.attack + item.block + item.false_positive
  return (
    total >= trendTotalThreshold.value ||
    isTrendMetricAnomaly(item, 'attack') ||
    isTrendMetricAnomaly(item, 'block') ||
    isTrendMetricAnomaly(item, 'false_positive')
  )
}

function trendMetricLabel(key: TrendMetricKey) {
  if (key === 'attack') return '攻击'
  if (key === 'block') return '拦截'
  return '放行'
}

function trendDeltaTone(delta: number | null, key?: TrendMetricKey): Tone {
  if (delta === null || delta === 0) {
    return 'info'
  }

  if (key === 'block') {
    return delta > 0 ? 'safe' : 'warn'
  }

  if (key === 'false_positive') {
    return delta > 0 ? 'info' : 'warn'
  }

  return delta > 0 ? 'danger' : 'safe'
}

function formatSignedDelta(delta: number | null) {
  if (delta === null) {
    return '基线'
  }

  if (delta > 0) {
    return `+${delta}`
  }

  return `${delta}`
}

function trendDeltaSummary(delta: number | null, previousDay?: string | null) {
  if (delta === null) {
    return '首日基线'
  }

  const base = previousDay ? `较 ${compactDayLabel(previousDay)}` : '较前日'
  if (delta > 0) {
    return `${base}上升 ${delta}`
  }
  if (delta < 0) {
    return `${base}回落 ${Math.abs(delta)}`
  }
  return `${base}持平`
}

function trendAnomalyReasons(item: TrendInsight) {
  const reasons: string[] = []

  if (item.total >= trendTotalThreshold.value) {
    reasons.push(`总量 ${item.total}/${trendTotalThreshold.value}`)
  }

  ;(['attack', 'block', 'false_positive'] as TrendMetricKey[]).forEach((key) => {
    if (isTrendMetricAnomaly(item, key)) {
      reasons.push(`${trendMetricLabel(key)} ${item[key]}/${trendThresholds.value[key]}`)
    }
  })

  return reasons
}

function trendTooltipPlacement(index: number, total: number) {
  if (index <= 1) {
    return 'align-start'
  }

  if (index >= total - 2) {
    return 'align-end'
  }

  return ''
}

function compactDayLabel(day: string) {
  if (day.includes('-')) {
    return day.split('-').slice(1).join('/')
  }
  return day
}
</script>

<template>
  <section class="page-grid dashboard-page dashboard-revamp">
    <section class="dashboard-hero-shell">
      <article :class="['dashboard-hero-card', `tone-${heroTone}`]">
        <div class="dashboard-hero-copy">
          <div class="dashboard-hero-head">
            <p class="eyebrow">Security Overview</p>
            <StatusPill :label="heroTone === 'danger' ? '高压态势' : heroTone === 'warn' ? '波动中' : '运行平稳'" :tone="heroTone" />
          </div>
          <h1>蓝队防御运行态总览</h1>
          <p class="dashboard-hero-summary">{{ heroSummary }}</p>
          <div class="dashboard-hero-meta">
            <span v-for="item in heroMeta" :key="item">{{ item }}</span>
          </div>
          <div class="dashboard-hero-actions">
            <RouterLink class="primary-button" to="/security-events">进入事件处置</RouterLink>
            <RouterLink class="ghost-button" to="/defense-config">查看防御配置</RouterLink>
          </div>
        </div>

        <div class="dashboard-hero-side">
          <div class="dashboard-hero-side-panel">
            <div class="dashboard-hero-side-head">
              <strong>快捷入口</strong>
              <span>{{ shortcutItems.length }} 个常用入口</span>
            </div>
            <div class="dashboard-hero-shortcuts">
              <RouterLink
                v-for="item in shortcutItems"
                :key="item.to"
                :class="['dashboard-shortcut-row', `tone-${item.tone}`]"
                :to="item.to"
              >
                <span :class="['dashboard-shortcut-strip', `tone-${item.tone}`]"></span>
                <div class="dashboard-shortcut-copy">
                  <strong>{{ item.label }}</strong>
                  <span>{{ item.meta }}</span>
                </div>
                <span class="dashboard-shortcut-arrow" aria-hidden="true">›</span>
              </RouterLink>
            </div>
          </div>
        </div>
      </article>

      <div class="dashboard-stat-strip">
        <article
          v-for="item in statCards"
          :key="item.label"
          :class="['dashboard-stat-card', `tone-${item.tone}`]"
        >
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
          <small>{{ item.note }}</small>
        </article>
      </div>
    </section>

    <section class="dashboard-main-grid">
      <PageSection class="dashboard-panel-trend" eyebrow="趋势" title="近 7 日攻击趋势" tag="趋势变化" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>趋势汇总</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`攻击 ${totalTrendAttack}`" tone="danger" />
                <StatusPill :label="`拦截 ${totalTrendBlock}`" tone="safe" />
                <StatusPill :label="`放行 ${totalTrendFalsePositive}`" tone="warn" />
              </div>
            </div>
          </div>
        </template>

        <div v-if="trendSeries.length" class="dashboard-trend-band">
          <div class="dashboard-trend-band-head compact">
            <div class="dashboard-trend-band-legend">
              <span class="dashboard-trend-legend danger">攻击</span>
              <span class="dashboard-trend-legend safe">拦截</span>
              <span class="dashboard-trend-legend warn">放行</span>
            </div>
            <div v-if="trendAnomalyDays.length" class="dashboard-trend-strip-status">
              <span class="dashboard-trend-strip-badge is-anomaly">异常日 {{ trendAnomalyDays.length }}</span>
            </div>
          </div>

          <div class="dashboard-trend-strip-track">
            <div
              v-for="(item, index) in trendInsights"
              :key="`day-${item.day}`"
              :class="[
                'dashboard-trend-strip-item',
                { 'is-peak': isTrendPeakDay(item.day), 'is-anomaly': isTrendAnomalyDay(item) },
              ]"
              tabindex="0"
            >
              <span class="dashboard-trend-strip-day">{{ compactDayLabel(item.day) }}</span>
              <div class="dashboard-trend-strip-meter">
                <div class="dashboard-trend-strip-fill" :style="{ width: trendTotalFillWidth(item.total) }">
                  <span class="dashboard-trend-strip-segment danger" :style="{ width: trendMetricWidth(item.attack, item.total) }"></span>
                  <span class="dashboard-trend-strip-segment safe" :style="{ width: trendMetricWidth(item.block, item.total) }"></span>
                  <span class="dashboard-trend-strip-segment warn" :style="{ width: trendMetricWidth(item.false_positive, item.total) }"></span>
                </div>
              </div>
              <span
                v-if="isTrendAnomalyDay(item) && item.totalDelta !== null"
                :class="['dashboard-trend-strip-corner', 'dashboard-trend-delta-chip', 'compact', `tone-${trendDeltaTone(item.totalDelta)}`]"
              >
                {{ formatSignedDelta(item.totalDelta) }}
              </span>
              <div :class="['dashboard-trend-tooltip', 'compact', trendTooltipPlacement(index, trendInsights.length)]">
                <div class="dashboard-trend-tooltip-head">
                  <strong>{{ item.day }}</strong>
                  <span :class="['dashboard-trend-delta-chip', `tone-${trendDeltaTone(item.totalDelta)}`]">
                    {{ trendDeltaSummary(item.totalDelta, item.previousDay) }}
                  </span>
                </div>
                <p>总量 {{ item.total }}</p>
                <div class="dashboard-trend-tooltip-metrics">
                  <div class="dashboard-trend-tooltip-metric">
                    <span>攻击</span>
                    <strong>{{ item.attack }}</strong>
                    <em :class="`tone-${trendDeltaTone(item.metricDeltas.attack, 'attack')}`">
                      {{ formatSignedDelta(item.metricDeltas.attack) }}
                    </em>
                  </div>
                  <div class="dashboard-trend-tooltip-metric">
                    <span>拦截</span>
                    <strong>{{ item.block }}</strong>
                    <em :class="`tone-${trendDeltaTone(item.metricDeltas.block, 'block')}`">
                      {{ formatSignedDelta(item.metricDeltas.block) }}
                    </em>
                  </div>
                  <div class="dashboard-trend-tooltip-metric">
                    <span>放行</span>
                    <strong>{{ item.false_positive }}</strong>
                    <em :class="`tone-${trendDeltaTone(item.metricDeltas.false_positive, 'false_positive')}`">
                      {{ formatSignedDelta(item.metricDeltas.false_positive) }}
                    </em>
                  </div>
                </div>
                <div v-if="isTrendAnomalyDay(item)" class="dashboard-trend-tooltip-tags">
                  <span
                    v-for="reason in trendAnomalyReasons(item)"
                    :key="`${item.day}-${reason}`"
                  >
                    {{ reason }}
                  </span>
                </div>
              </div>
            </div>
          </div>

        </div>
        <div v-else class="empty-state">暂无趋势数据。</div>
      </PageSection>

      <section class="dashboard-main-columns">
        <div class="dashboard-main-column dashboard-main-column-primary">
          <PageSection class="dashboard-panel-surface" eyebrow="防线" title="攻击面覆盖" tag="覆盖态势" tone="danger">
            <template #toolbar>
              <div class="section-toolbar">
                <div class="section-toolbar-copy">
                  <h4>当前重点风险面</h4>
                  <div class="section-toolbar-meta">
                    <StatusPill :label="`${surfaceItems.length} 类`" tone="danger" />
                    <span>聚焦最容易进入执行链的高风险面</span>
                  </div>
                </div>
              </div>
            </template>

            <div class="dashboard-surface-grid">
              <article
                v-for="item in surfaceItems"
                :key="item.title"
                :class="['dashboard-surface-card', `tone-${item.tone}`]"
              >
                <div class="card-head">
                  <h4>{{ item.title }}</h4>
                  <StatusPill :label="item.tag" :tone="item.tone" />
                </div>
                <p>{{ item.detail }}</p>
              </article>
            </div>
          </PageSection>

          <PageSection class="dashboard-panel-events" eyebrow="事件" title="最近安全事件" tag="重点告警" tone="danger">
            <template #actions>
              <RouterLink class="ghost-button small" to="/security-events">进入事件处置</RouterLink>
            </template>

            <template #toolbar>
              <div class="section-toolbar">
                <div class="section-toolbar-copy">
                  <h4>事件焦点</h4>
                  <div class="section-toolbar-meta">
                    <StatusPill :label="`${recentEvents.length} 条`" tone="danger" />
                    <StatusPill :label="`高危 ${highRiskRecentEvents}`" tone="warn" />
                    <StatusPill :label="`拦截 ${blockedRecentEvents}`" tone="safe" />
                  </div>
                </div>
                <div class="section-toolbar-actions">
                  <div class="dashboard-sort-switch" role="tablist" aria-label="事件排序">
                    <button
                      v-for="option in eventSortOptions"
                      :key="option.key"
                      :class="['dashboard-sort-button', { active: eventSortMode === option.key }]"
                      type="button"
                      @click="eventSortMode = option.key"
                    >
                      {{ option.label }}
                    </button>
                  </div>
                </div>
              </div>
            </template>

            <div v-if="loading" class="empty-state">正在汇总最近事件...</div>
            <div v-else-if="error" class="empty-state">
              <p>事件加载失败：{{ error }}</p>
              <button class="ghost-button" type="button" @click="refresh">重试</button>
            </div>
            <div v-else-if="recentEvents.length" class="dashboard-event-list dashboard-table-list">
              <div class="dashboard-table-head dashboard-event-row">
                <span>级</span>
                <span>事件类型</span>
                <span>源 / 目标</span>
                <span>摘要</span>
                <span>处置状态</span>
                <span>时间</span>
              </div>
              <RouterLink
                v-for="event in recentEvents"
                :key="`${event.id}-${event.created_at}`"
                class="dashboard-event-row dashboard-table-row"
                to="/security-events"
              >
                <div class="dashboard-table-cell dashboard-event-row-severity" :title="levelLabel(event.event_level)">
                  <span :class="['dashboard-severity-strip', `tone-${levelTone(event.event_level)}`]"></span>
                </div>
                <div class="dashboard-table-cell dashboard-event-row-copy">
                  <strong>{{ eventTypeLabel(event.event_type) }}</strong>
                </div>
                <div class="dashboard-table-cell dashboard-event-row-route">
                  <span>{{ event.source }}</span>
                  <small>{{ event.target }}</small>
                </div>
                <div class="dashboard-table-cell dashboard-event-row-detail-cell">
                  <p class="dashboard-event-row-detail">{{ event.detail }}</p>
                </div>
                <div class="dashboard-table-cell dashboard-event-row-meta">
                  <StatusPill :label="levelLabel(event.event_level)" :tone="levelTone(event.event_level)" />
                  <StatusPill :label="statusLabel(event.status)" :tone="statusTone(event.status)" />
                </div>
                <div class="dashboard-table-cell dashboard-event-row-time">
                  <span>{{ event.created_at }}</span>
                </div>
              </RouterLink>
            </div>
            <div v-else class="empty-state">暂无最近安全事件。</div>
          </PageSection>
        </div>

        <div class="dashboard-main-column dashboard-main-column-side">
          <PageSection class="dashboard-panel-sessions" eyebrow="联动" title="最近联动会话" tag="运行态" tone="info">
            <template #actions>
              <button class="ghost-button small" type="button" @click="refresh">刷新</button>
            </template>

            <template #toolbar>
              <div class="section-toolbar">
                <div class="section-toolbar-copy">
                  <h4>会话快照</h4>
                  <div class="section-toolbar-meta">
                    <StatusPill :label="`${sessionCards.length} 条`" tone="info" />
                    <span v-if="sessionOverflowCount">另有 {{ sessionOverflowCount }} 条未展开</span>
                    <span v-else>展示最近运行态变化</span>
                  </div>
                </div>
              </div>
            </template>

            <div v-if="loading" class="dashboard-session-list">
              <div class="dashboard-session-card muted">
                <strong>加载中</strong>
              </div>
            </div>
            <div v-else-if="error" class="dashboard-session-list">
              <div class="dashboard-session-card muted">
                <strong>加载失败</strong>
                <p>{{ error }}</p>
              </div>
            </div>
            <div v-else-if="!sessionPreview.length" class="dashboard-session-list">
              <div class="dashboard-session-card muted">
                <strong>暂无联动</strong>
              </div>
            </div>
            <div v-else class="dashboard-session-list dashboard-table-list">
              <div class="dashboard-table-head dashboard-session-row">
                <span>会话名称</span>
                <span>风险级别</span>
                <span>运行状态</span>
                <span>会话标识</span>
              </div>
              <article
                v-for="item in sessionPreview"
                :key="item.session_id"
                class="dashboard-session-card dashboard-session-row dashboard-table-row"
              >
                <div class="dashboard-table-cell dashboard-session-name">
                  <strong>{{ item.session_name }}</strong>
                </div>
                <div class="dashboard-table-cell dashboard-session-level">
                  <StatusPill :label="levelLabel(item.risk_level)" :tone="levelTone(item.risk_level)" />
                </div>
                <div class="dashboard-table-cell dashboard-session-status">
                  <StatusPill :label="statusLabel(item.status)" :tone="statusTone(item.status)" />
                </div>
                <div class="dashboard-table-cell dashboard-session-id">
                  <span>{{ item.session_id }}</span>
                </div>
              </article>

              <article
                v-if="sessionOverflowCount"
                class="dashboard-session-card dashboard-session-row dashboard-table-row muted"
              >
                <div class="dashboard-table-cell dashboard-session-name">
                  <strong>+{{ sessionOverflowCount }}</strong>
                </div>
                <div class="dashboard-table-cell dashboard-session-level">
                  <small>未展开</small>
                </div>
                <div class="dashboard-table-cell dashboard-session-status">
                  <small>历史会话</small>
                </div>
                <div class="dashboard-table-cell dashboard-session-id">
                  <small>查看更多</small>
                </div>
              </article>
            </div>
          </PageSection>
        </div>
      </section>
    </section>
  </section>
</template>
