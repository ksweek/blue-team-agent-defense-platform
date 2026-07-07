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
type TrendChartPoint = TrendInsight & {
  x: number
  xPercent: number
  positions: Record<TrendMetricKey, number>
}

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

const overviewStatItems = computed(() => [
  { label: '攻击', value: overview.value.attackCount, tone: 'danger' as Tone, detail: '累计攻击触发' },
  { label: '拦截', value: overview.value.blockedCount, tone: 'safe' as Tone, detail: '已阻断高风险请求' },
  { label: '高危', value: overview.value.highRiskCount, tone: 'warn' as Tone, detail: '待优先处置事件' },
  { label: '防线', value: overview.value.defenseCount, tone: 'info' as Tone, detail: '当前启用策略数量' },
  { label: '活跃', value: overview.value.activeTaskCount, tone: 'warn' as Tone, detail: '运行中的任务与联动' },
])

const heroTone = computed<Tone>(() => {
  if (overview.value.highRiskCount >= 6) return 'danger'
  if (overview.value.highRiskCount >= 2 || overview.value.activeTaskCount >= 3) return 'warn'
  return 'safe'
})

const sessionCards = computed(() => data.value?.sessions.items ?? [])
const sessionPreview = computed(() => sessionCards.value.slice(0, 5))
const highRiskSessionCount = computed(
  () => sessionCards.value.filter((item) => normalizeLevel(item.risk_level) === 'high').length,
)
const sessionSummaryLead = computed(() => {
  const focus = sessionPreview.value[0]
  if (!focus) {
    return '最近没有运行态联动会话。'
  }

  return `最近 ${sessionCards.value.length} 条会话中，高危 ${highRiskSessionCount.value} 条；最新会话为 ${focus.session_name}。`
})

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
const trendMetricMax = computed(() =>
  Math.max(
    1,
    ...trendInsights.value.map((item) => Math.max(item.attack, item.block, item.false_positive)),
  ),
)
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
const trendChartHeight = 156
const trendChartWidth = 1000
const trendChartPaddingX = 40
const trendChartPaddingY = 14
const trendChartPlotWidth = trendChartWidth - trendChartPaddingX * 2
const trendChartPlotHeight = trendChartHeight - trendChartPaddingY * 2
const trendGridValues = computed(() => {
  const ceiling = trendMetricMax.value
  return [1, 0.5].map((ratio) => Math.round(ceiling * ratio))
})
const trendChartPoints = computed<TrendChartPoint[]>(() => {
  const items = trendInsights.value
  if (!items.length) {
    return []
  }

  const slotWidth = items.length > 1 ? trendChartPlotWidth / (items.length - 1) : trendChartPlotWidth

  return items.map((item, index) => {
    const x = items.length > 1 ? trendChartPaddingX + slotWidth * index : trendChartWidth / 2

    return {
      ...item,
      x,
      xPercent: (x / trendChartWidth) * 100,
      positions: {
        attack: trendChartY(item.attack),
        block: trendChartY(item.block),
        false_positive: trendChartY(item.false_positive),
      },
    }
  })
})
const trendLinePaths = computed<Record<TrendMetricKey, string>>(() => ({
  attack: buildTrendPolyline('attack'),
  block: buildTrendPolyline('block'),
  false_positive: buildTrendPolyline('false_positive'),
}))

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
const eventSummaryLead = computed(() => {
  const focus = recentEvents.value[0]
  if (!focus) {
    return '最近没有需要处置的安全事件。'
  }

  const blockedText = blockedRecentEvents.value > 0 ? `已拦截 ${blockedRecentEvents.value} 条` : '暂无拦截事件'
  return `最近 ${recentEvents.value.length} 条事件中，高危 ${highRiskRecentEvents.value} 条，${blockedText}；最新事件为 ${eventTypeLabel(focus.event_type)}。`
})

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

function shouldShowEventLevel(event: DashboardEvent) {
  return !(normalizeEventStatus(event.status) === 'allowed' && normalizeLevel(event.event_level) === 'low')
}

function normalizeRuntimeStatus(status: string) {
  const lowered = status.trim().toLowerCase()
  if (lowered === 'failed' || lowered === 'failure' || lowered === 'error') return 'failed'
  if (lowered === 'done' || lowered === 'completed' || lowered === 'success') return 'done'
  if (lowered === 'running') return 'running'
  if (lowered === 'queued') return 'queued'
  return lowered
}

function shouldShowSessionStatus(status: string) {
  return normalizeRuntimeStatus(status) !== 'failed'
}

function sessionFlowTone(status: string, riskLevel: string): Tone {
  if (shouldShowSessionStatus(status)) {
    return statusTone(status)
  }

  return levelTone(riskLevel)
}

function sessionFlowText(status: string, riskLevel: string) {
  if (shouldShowSessionStatus(status)) {
    return `${levelLabel(riskLevel)} / ${statusLabel(status)}`
  }

  return levelLabel(riskLevel)
}

function statusTone(status: string): Tone {
  const normalized = normalizeRuntimeStatus(status)
  if (normalized === 'failed') return 'danger'
  if (normalized === 'running') return 'warn'
  if (normalized === 'queued') return 'info'
  if (normalized === 'done') return 'safe'
  return eventStatusTone(status)
}

function statusLabel(status: string) {
  const normalized = normalizeRuntimeStatus(status)
  if (normalized === 'failed') return '失败'
  if (normalized === 'running') return '运行中'
  if (normalized === 'queued') return '排队中'
  if (normalized === 'done') return '已完成'
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

function trendChartY(value: number) {
  if (trendMetricMax.value <= 0) {
    return trendChartHeight - trendChartPaddingY
  }

  const ratio = value / trendMetricMax.value
  return trendChartHeight - trendChartPaddingY - ratio * trendChartPlotHeight
}

function buildTrendPolyline(key: TrendMetricKey) {
  return trendChartPoints.value.map((point) => `${point.x},${point.positions[key]}`).join(' ')
}

function trendHotspotStyle(point: TrendChartPoint, total: number) {
  const widthPercent = total > 1 ? Math.min(18, Math.max(10, 100 / total)) : 100

  return {
    left: `${point.xPercent}%`,
    width: `${widthPercent}%`,
  }
}

function compactDayLabel(day: string) {
  if (day.includes('-')) {
    return day.split('-').slice(1).join('/')
  }
  return day
}

function formatOverviewValue(value: number) {
  return value.toLocaleString('zh-CN')
}
</script>

<template>
  <section class="page-grid dashboard-page dashboard-revamp">
    <section class="dashboard-hero-shell">
      <article :class="['dashboard-hero-card', 'dashboard-hero-card-compact', 'dashboard-hero-card-single', `tone-${heroTone}`]">
        <div class="dashboard-hero-copy">
          <div class="dashboard-hero-head">
            <div class="dashboard-hero-brand">
              <h1 class="dashboard-hero-title">GuardianAgent</h1>
            </div>
          </div>
          <p class="dashboard-hero-summary">
            面向 Function-Calling Agent 的多维AI防御与评估平台
          </p>
          <div class="dashboard-hero-footer">
            <div class="dashboard-hero-actions">
              <RouterLink class="primary-button" to="/security-events">进入事件处置</RouterLink>
              <RouterLink class="ghost-button" to="/ai-endpoints">目标治理</RouterLink>
            </div>
          </div>
        </div>
      </article>

      <section class="dashboard-runtime-panel">
        <div class="dashboard-runtime-head">
          <span>运行态</span>
          <strong>防御总览</strong>
        </div>
        <div class="dashboard-stat-strip">
          <article
            v-for="item in overviewStatItems"
            :key="item.label"
            :class="['dashboard-stat-card', `tone-${item.tone}`]"
          >
            <span>{{ item.label }}</span>
            <strong>{{ formatOverviewValue(item.value) }}</strong>
            <small>{{ item.detail }}</small>
          </article>
        </div>
      </section>

    </section>

    <section class="dashboard-main-grid">
      <PageSection class="dashboard-panel-trend" eyebrow="趋势" title="近 7 日攻击趋势" tone="warn">
        <div v-if="trendSeries.length" class="dashboard-trend-band merged">
          <div class="dashboard-trend-compact-head">
            <div class="dashboard-trend-titleline">
              <span>趋势</span>
              <strong>近 7 日攻击趋势</strong>
            </div>
            <div class="dashboard-trend-summary-line compact">
              <span class="dashboard-trend-summary-item danger">攻击 {{ totalTrendAttack }}</span>
              <span class="dashboard-trend-summary-item safe">拦截 {{ totalTrendBlock }}</span>
              <span class="dashboard-trend-summary-item warn">放行 {{ totalTrendFalsePositive }}</span>
              <span class="dashboard-trend-summary-item neutral">异常日 {{ trendAnomalyDays.length }}</span>
            </div>
          </div>

          <div class="dashboard-trend-line-shell">
            <div class="dashboard-trend-line-axis">
              <span v-for="(value, index) in trendGridValues" :key="`grid-label-${index}`">{{ value }}</span>
              <span>0</span>
            </div>

            <div class="dashboard-trend-line-panel">
              <svg
                class="dashboard-trend-line-chart"
                :viewBox="`0 0 ${trendChartWidth} ${trendChartHeight}`"
                preserveAspectRatio="none"
                aria-hidden="true"
              >
                <g class="dashboard-trend-grid">
                  <line
                    v-for="(value, index) in trendGridValues"
                    :key="`line-${index}`"
                    :x1="trendChartPaddingX"
                    :x2="trendChartWidth - trendChartPaddingX"
                    :y1="trendChartY(value)"
                    :y2="trendChartY(value)"
                  />
                  <line
                    :x1="trendChartPaddingX"
                    :x2="trendChartWidth - trendChartPaddingX"
                    :y1="trendChartHeight - trendChartPaddingY"
                    :y2="trendChartHeight - trendChartPaddingY"
                  />
                </g>

                <g class="dashboard-trend-series">
                  <polyline class="dashboard-trend-line danger" :points="trendLinePaths.attack" />
                  <polyline class="dashboard-trend-line safe" :points="trendLinePaths.block" />
                  <polyline class="dashboard-trend-line warn" :points="trendLinePaths.false_positive" />
                </g>

                <g
                  v-for="point in trendChartPoints"
                  :key="`markers-${point.day}`"
                  class="dashboard-trend-marker-cluster"
                >
                  <circle :cx="point.x" :cy="point.positions.attack" r="3" class="dashboard-trend-marker danger" />
                  <circle :cx="point.x" :cy="point.positions.block" r="3" class="dashboard-trend-marker safe" />
                  <circle :cx="point.x" :cy="point.positions.false_positive" r="3" class="dashboard-trend-marker warn" />
                </g>
              </svg>

              <div class="dashboard-trend-hotspot-layer">
                <div
                  v-for="(item, index) in trendChartPoints"
                  :key="`hotspot-${item.day}`"
                  :class="[
                    'dashboard-trend-hotspot',
                    { 'is-peak': isTrendPeakDay(item.day), 'is-anomaly': isTrendAnomalyDay(item) },
                  ]"
                  :style="trendHotspotStyle(item, trendChartPoints.length)"
                  tabindex="0"
                >
                  <span class="dashboard-trend-hotspot-stem"></span>
                  <span
                    v-if="isTrendAnomalyDay(item) && item.totalDelta !== null"
                    :class="['dashboard-trend-strip-corner', 'dashboard-trend-delta-chip', 'compact', `tone-${trendDeltaTone(item.totalDelta)}`]"
                  >
                    {{ formatSignedDelta(item.totalDelta) }}
                  </span>
                  <div :class="['dashboard-trend-tooltip', 'compact', trendTooltipPlacement(index, trendChartPoints.length)]">
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
                  <span class="dashboard-trend-hotspot-day">{{ compactDayLabel(item.day) }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="empty-state">暂无趋势数据。</div>
      </PageSection>

      <section class="dashboard-main-columns">
        <div class="dashboard-main-column dashboard-main-column-primary">
          <PageSection class="dashboard-panel-events" eyebrow="事件" title="最近安全事件" tag="重点告警" tone="danger">
            <div v-if="loading" class="empty-state">正在汇总最近事件...</div>
            <div v-else-if="error" class="empty-state">
              <p>事件加载失败：{{ error }}</p>
              <button class="ghost-button" type="button" @click="refresh">重试</button>
            </div>
            <div v-else-if="recentEvents.length" class="dashboard-event-summary-card">
              <div class="dashboard-event-summary-head">
                <div class="dashboard-event-summary-title">
                  <span>事件</span>
                  <strong>最近安全事件</strong>
                  <StatusPill label="重点告警" tone="danger" />
                </div>
                <RouterLink class="ghost-button small" to="/security-events">进入事件处置</RouterLink>
              </div>

              <div class="dashboard-event-summary-toolbar">
                <div class="dashboard-event-summary-metrics">
                  <span class="dashboard-event-summary-metric danger">{{ recentEvents.length }} 条</span>
                  <span class="dashboard-event-summary-metric warn">高危 {{ highRiskRecentEvents }}</span>
                  <span class="dashboard-event-summary-metric safe">拦截 {{ blockedRecentEvents }}</span>
                </div>
                <div class="dashboard-sort-switch dashboard-event-sort-switch compact" role="tablist" aria-label="事件排序">
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

              <RouterLink class="dashboard-event-summary-body" to="/security-events">
                <div class="dashboard-event-summary-copy">
                  <span>事件焦点</span>
                  <strong>{{ eventSummaryLead }}</strong>
                  <p>{{ recentEvents[0].source }} / {{ recentEvents[0].target }}：{{ recentEvents[0].detail }}</p>
                </div>

                <div class="dashboard-event-flow">
                  <article
                    v-for="event in recentEvents"
                    :key="`${event.id}-${event.created_at}`"
                    class="dashboard-event-flow-item"
                  >
                    <span :class="['dashboard-event-flow-dot', `tone-${levelTone(event.event_level)}`]"></span>
                    <div class="dashboard-event-flow-main">
                      <div class="dashboard-event-flow-line">
                        <strong>{{ eventTypeLabel(event.event_type) }}</strong>
                        <span>{{ event.created_at }}</span>
                      </div>
                      <p>{{ event.source }} / {{ event.target }}：{{ event.detail }}</p>
                    </div>
                    <div class="dashboard-event-flow-status">
                      <StatusPill
                        v-if="shouldShowEventLevel(event)"
                        :label="levelLabel(event.event_level)"
                        :tone="levelTone(event.event_level)"
                      />
                      <StatusPill :label="statusLabel(event.status)" :tone="statusTone(event.status)" />
                    </div>
                  </article>
                </div>
              </RouterLink>
            </div>
            <div v-else class="empty-state">暂无最近安全事件。</div>
          </PageSection>
        </div>

        <div class="dashboard-main-column dashboard-main-column-side">
          <PageSection class="dashboard-panel-sessions" eyebrow="联动" title="最近联动会话" tag="运行态" tone="info">
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
            <div v-else class="dashboard-session-summary-card">
              <div class="dashboard-session-summary-head">
                <div class="dashboard-session-summary-title">
                  <span>联动</span>
                  <strong>最近联动会话</strong>
                  <StatusPill label="运行态" tone="info" />
                </div>
                <button class="ghost-button small" type="button" @click="refresh">刷新</button>
              </div>

              <div class="dashboard-session-summary-toolbar">
                <span class="dashboard-session-summary-metric info">{{ sessionCards.length }} 条</span>
                <span class="dashboard-session-summary-metric danger">高危 {{ highRiskSessionCount }}</span>
              </div>

              <div class="dashboard-session-summary-body">
                <div class="dashboard-session-summary-copy">
                  <span>运行态</span>
                  <strong>{{ sessionSummaryLead }}</strong>
                  <p>{{ sessionPreview[0].session_name }} / {{ sessionPreview[0].session_id }}</p>
                </div>

                <div class="dashboard-session-flow">
                  <article
                    v-for="item in sessionPreview"
                    :key="item.session_id"
                    class="dashboard-session-flow-item"
                  >
                    <span :class="['dashboard-session-flow-dot', `tone-${sessionFlowTone(item.status, item.risk_level)}`]"></span>
                    <div class="dashboard-session-flow-main">
                      <div class="dashboard-session-flow-line">
                        <strong>{{ item.session_name }}</strong>
                        <span>{{ item.session_id }}</span>
                      </div>
                      <p>{{ sessionFlowText(item.status, item.risk_level) }}</p>
                    </div>
                    <div class="dashboard-session-flow-status">
                      <StatusPill :label="levelLabel(item.risk_level)" :tone="levelTone(item.risk_level)" />
                      <StatusPill
                        v-if="shouldShowSessionStatus(item.status)"
                        :label="statusLabel(item.status)"
                        :tone="statusTone(item.status)"
                      />
                    </div>
                  </article>
                </div>
              </div>
            </div>
          </PageSection>
        </div>

      </section>
    </section>
  </section>
</template>
