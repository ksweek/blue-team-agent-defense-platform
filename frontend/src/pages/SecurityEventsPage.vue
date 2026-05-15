<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import { buildAttackSummary } from '../services/attackSummary'
import {
  api,
  type SecurityEventDetail,
  type SecurityEventSummary,
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

const router = useRouter()
const filters: EventFilter[] = ['全部', '高危', '可疑', '已拦截', '已放行']

const activeFilter = ref<EventFilter>('全部')
const currentPage = ref(1)
const pageSize = 10
const selectedEventIds = ref<number[]>([])
const selectedEventId = ref<number | null>(null)
const eventDetail = ref<SecurityEventDetail | null>(null)
const detailLoading = ref(false)
const detailError = ref<string | null>(null)
const mutatingKey = ref<string | null>(null)
const mutationError = ref<string | null>(null)

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

const selectedEventAttackSummary = computed(() => buildEventAttackSummary(resolvedEventDetail.value ?? selectedEvent.value))

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

function buildEventAttackSummary(
  event?: Pick<SecurityEventSummary, 'event_type' | 'hit_rules' | 'guard_trace'> | null
) {
  return buildAttackSummary({
    eventType: event?.event_type ?? null,
    hitRules: event?.hit_rules ?? [],
    guardTrace: event?.guard_trace ?? null
  })
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

                <div class="event-workitem-trigger">
                  <strong>{{ buildEventAttackSummary(item).label }}</strong>
                  <span>{{ buildEventAttackSummary(item).brief }}</span>
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
                <h4>攻击结论</h4>
              </div>
              <small class="field-count">{{ detailLoading ? '同步详情中' : selectedEventAttackSummary.brief }}</small>
            </div>
            <div class="detail-block">
              <p class="security-summary-note">{{ selectedEventAttackSummary.label }}</p>
              <p class="security-summary-subnote">{{ selectedEventAttackSummary.supportText }}</p>
              <p class="security-summary-subnote">{{ selectedEventAttackSummary.brief }}</p>
            </div>
            <div class="token-list">
              <StatusPill :label="`控制面 ${selectedEventAttackSummary.counts.controls}`" tone="safe" />
              <StatusPill :label="`规则 ${selectedEventAttackSummary.counts.rules}`" tone="warn" />
              <StatusPill :label="`信号 ${selectedEventAttackSummary.counts.signals}`" tone="danger" />
            </div>
            <div v-if="detailError" class="empty-state">
              <p>详情加载失败，已先按列表数据归类：{{ detailError }}</p>
              <button class="ghost-button" type="button" @click="selectedEventId && loadEventDetail(selectedEventId)">重试</button>
            </div>
          </article>
        </div>
        <div v-else class="empty-state">先从左侧选择一条安全事件。</div>
      </PageSection>
    </section>
  </section>
</template>
