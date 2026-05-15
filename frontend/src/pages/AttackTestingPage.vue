<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import {
  api,
  type AiEndpointItem,
  type AttackTaskItem,
  type AttackWorkerStatus,
  type SampleCatalogSummary,
  type SampleListItem,
  type SampleSectionItem,
} from '../services/api'
import { formatBeijingTime } from '../services/time'

type Tone = 'safe' | 'warn' | 'danger' | 'info'

type AttackSet = {
  key: string
  label: string
  entryCount: number
  riskLevel: string
  attackStage: string
  groupKey: string
  groupLabel: string
}

type AttackSetGroup = {
  key: string
  label: string
  entryCount: number
  sectionCount: number
  sets: AttackSet[]
}

type TaskBucketCounts = {
  running: number
  pending: number
  finished: number
}

const SAMPLE_PAGE_SIZE = 100
const FINISHED_TASK_STATUSES = ['done', 'failed', 'cancelled', 'dead_letter'] as const
const PENDING_TASK_STATUSES = ['ready', 'queued', 'scheduled'] as const

const loading = ref(true)
const refreshingTasks = ref(false)
const executing = ref(false)
const error = ref<string | null>(null)
const actionMessage = ref('等待选择攻击集')
const lastActionAt = ref('')

const sampleSummary = ref<SampleCatalogSummary | null>(null)
const sectionItems = ref<SampleSectionItem[]>([])
const aiEndpoints = ref<AiEndpointItem[]>([])
const selectedEndpointId = ref('')
const selectedSetKeys = ref<string[]>([])
const runningTaskItems = ref<AttackTaskItem[]>([])
const finishedTaskItems = ref<AttackTaskItem[]>([])
const workerStatus = ref<AttackWorkerStatus | null>(null)
const lastSubmittedTaskIds = ref<number[]>([])
const taskCounts = ref<TaskBucketCounts>({
  running: 0,
  pending: 0,
  finished: 0,
})

let pollingTimer: ReturnType<typeof setInterval> | null = null

const enabledEndpoints = computed(() => aiEndpoints.value.filter((item) => item.enabled))
const selectedEndpoint = computed(() =>
  enabledEndpoints.value.find((item) => String(item.id) === selectedEndpointId.value) ?? null
)

const attackGroups = computed<AttackSetGroup[]>(() => buildAttackSetGroups(sampleSummary.value, sectionItems.value))
const allAttackSets = computed(() => attackGroups.value.flatMap((group) => group.sets))
const selectedSets = computed(() => {
  const selected = new Set(selectedSetKeys.value)
  return allAttackSets.value.filter((item) => selected.has(item.key))
})
const selectedSampleEstimate = computed(() =>
  selectedSets.value.reduce((total, item) => total + item.entryCount, 0)
)
const totalSampleCount = computed(() => sampleSummary.value?.total_entries ?? 0)
const canExecute = computed(() => Boolean(selectedEndpoint.value && selectedSets.value.length && !executing.value))
const runningTasks = computed(() => runningTaskItems.value)
const finishedTasks = computed(() => finishedTaskItems.value)

watch(selectedEndpointId, () => {
  void refreshTaskWorkspace()
})

onMounted(() => {
  void initializePage()
})

onBeforeUnmount(() => {
  stopPolling()
})

function buildAttackSetGroups(summary: SampleCatalogSummary | null, sections: SampleSectionItem[]): AttackSetGroup[] {
  const sectionMap = new Map(sections.map((item) => [item.section_name, item]))
  const consumed = new Set<string>()
  const groups: AttackSetGroup[] = []

  for (const group of summary?.classification_groups ?? []) {
    const sets = group.sections
      .map((sectionName) => sectionMap.get(sectionName))
      .filter((item): item is SampleSectionItem => Boolean(item))
      .map((item) => {
        consumed.add(item.section_name)
        return buildAttackSet(item, group.key, group.label)
      })

    if (sets.length) {
      groups.push({
        key: group.key,
        label: group.label,
        entryCount: group.entry_count,
        sectionCount: sets.length,
        sets,
      })
    }
  }

  const fallbackBuckets = new Map<string, AttackSetGroup>()
  for (const section of sections) {
    if (consumed.has(section.section_name)) {
      continue
    }
    const key = section.classification?.primary_key || 'other'
    const label = section.classification?.primary_label || '其他攻击集'
    const bucket = fallbackBuckets.get(key) ?? {
      key,
      label,
      entryCount: 0,
      sectionCount: 0,
      sets: [],
    }
    bucket.sets.push(buildAttackSet(section, key, label))
    bucket.entryCount += section.entry_count
    bucket.sectionCount += 1
    fallbackBuckets.set(key, bucket)
  }

  return [...groups, ...fallbackBuckets.values()].sort((left, right) => {
    if (right.entryCount !== left.entryCount) {
      return right.entryCount - left.entryCount
    }
    return left.label.localeCompare(right.label, 'zh-CN')
  })
}

function buildAttackSet(section: SampleSectionItem, groupKey: string, groupLabel: string): AttackSet {
  return {
    key: section.section_name,
    label: section.classification?.section_label || section.section_name,
    entryCount: section.entry_count,
    riskLevel: section.risk_level,
    attackStage: section.attack_stage,
    groupKey,
    groupLabel,
  }
}

function selectDefaultEndpoint() {
  const candidates = enabledEndpoints.value
  const endpoint =
    candidates.find((item) => item.protection_enabled && item.is_default) ??
    candidates.find((item) => item.protection_enabled) ??
    candidates.find((item) => item.is_default) ??
    candidates[0]

  selectedEndpointId.value = endpoint ? String(endpoint.id) : ''
}

async function initializePage() {
  loading.value = true
  error.value = null

  try {
    const [summary, sectionsPayload, endpointsPayload] = await Promise.all([
      api.sampleCatalogSummary(),
      api.sampleSections(),
      api.aiEndpoints(),
    ])
    sampleSummary.value = summary
    sectionItems.value = sectionsPayload.items
    aiEndpoints.value = endpointsPayload.items
    selectDefaultEndpoint()
    selectAllSets()
    await refreshTaskWorkspace()
    actionMessage.value = '已加载攻击集，确认目标后可开始攻击'
    startPolling()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '攻击实验室加载失败'
    actionMessage.value = '加载失败'
  } finally {
    loading.value = false
  }
}

function startPolling() {
  if (pollingTimer) {
    return
  }
  pollingTimer = setInterval(() => {
    void refreshTaskWorkspace(true)
  }, 3000)
}

function stopPolling() {
  if (!pollingTimer) {
    return
  }
  clearInterval(pollingTimer)
  pollingTimer = null
}

async function refreshTaskWorkspace(silent = false) {
  if (refreshingTasks.value) {
    return
  }

  refreshingTasks.value = true
  try {
    const endpointId = selectedEndpoint.value?.id
    const [runningPayload, worker, ...taskPayloads] = await Promise.all([
      api.attackTasks(buildTaskQuery({ endpointId, status: 'running', pageSize: 24 })),
      api.attackWorkerStatus(),
      ...PENDING_TASK_STATUSES.map((status) =>
        api.attackTasks(buildTaskQuery({ endpointId, status, pageSize: 1 }))
      ),
      ...FINISHED_TASK_STATUSES.map((status) =>
        api.attackTasks(buildTaskQuery({ endpointId, status, pageSize: 16 }))
      ),
    ])

    const pendingPayloads = taskPayloads.slice(0, PENDING_TASK_STATUSES.length)
    const finishedPayloads = taskPayloads.slice(PENDING_TASK_STATUSES.length)

    runningTaskItems.value = sortTasks(runningPayload.items, ['started_at', 'updated_at', 'created_at'])
    finishedTaskItems.value = sortTasks(
      mergeTaskLists(finishedPayloads.flatMap((payload) => payload.items)),
      ['finished_at', 'updated_at', 'created_at']
    )
    taskCounts.value = {
      running: runningPayload.total,
      pending: pendingPayloads.reduce((total, payload) => total + payload.total, 0),
      finished: finishedPayloads.reduce((total, payload) => total + payload.total, 0),
    }
    workerStatus.value = worker
    if (!silent) {
      actionMessage.value = '任务状态已刷新'
      lastActionAt.value = formatBeijingTime()
    }
  } catch (err) {
    if (!silent) {
      error.value = err instanceof Error ? err.message : '任务状态刷新失败'
    }
  } finally {
    refreshingTasks.value = false
  }
}

function buildTaskQuery({
  endpointId,
  status,
  pageSize,
}: {
  endpointId?: number
  status: string
  pageSize: number
}) {
  return {
    page_size: pageSize,
    source_type: 'dataset_sample',
    ai_endpoint_id: endpointId,
    status,
  }
}

function mergeTaskLists(items: AttackTaskItem[]) {
  const taskMap = new Map<number, AttackTaskItem>()
  for (const item of items) {
    taskMap.set(item.id, item)
  }
  return Array.from(taskMap.values())
}

function sortTasks(items: AttackTaskItem[], fields: Array<'started_at' | 'finished_at' | 'updated_at' | 'created_at'>) {
  return [...items].sort((left, right) => {
    return selectTaskSortTime(right, fields).localeCompare(selectTaskSortTime(left, fields))
  })
}

function selectTaskSortTime(task: AttackTaskItem, fields: Array<'started_at' | 'finished_at' | 'updated_at' | 'created_at'>) {
  for (const field of fields) {
    const value = task[field]
    if (typeof value === 'string' && value) {
      return value
    }
  }
  return ''
}

function activeWorkerIds(status: AttackWorkerStatus | null) {
  if (!status) {
    return []
  }
  if (Array.isArray(status.active_task_ids)) {
    return status.active_task_ids.filter((item): item is number => Number.isInteger(item))
  }
  if (typeof status.active_task_id === 'number') {
    return [status.active_task_id]
  }
  return []
}

function isTaskRunning(status?: string | null) {
  return status === 'running'
}

function isTaskPending(status?: string | null) {
  return status === 'ready' || status === 'queued' || status === 'scheduled'
}

function pendingSummaryLabel() {
  if (taskCounts.value.pending <= 0) {
    return '当前无排队'
  }
  return `${taskCounts.value.pending} 个排队中`
}

function runningSummaryLabel() {
  if (taskCounts.value.running <= 0) {
    return '当前无运行任务'
  }
  return `${taskCounts.value.running} 个正在执行`
}

function isTaskActive(status?: string | null) {
  return isTaskRunning(status) || isTaskPending(status)
}

function workerLabel(status: AttackWorkerStatus | null) {
  if (!status) return '未连接'
  const activeIds = activeWorkerIds(status)
  if (activeIds.length === 1) return `运行 #${activeIds[0]}`
  if (activeIds.length > 1) return `运行 ${activeIds.length} 项`
  if ((status.running_tasks ?? 0) > 0) return `运行 ${status.running_tasks} 项`
  if (status.queued_tasks > 0) return '队列待执行'
  if (status.scheduled_tasks > 0) return '等待调度'
  return '空闲'
}

function workerTone(status: AttackWorkerStatus | null): Tone {
  if (!status) return 'info'
  if (activeWorkerIds(status).length > 0 || (status.running_tasks ?? 0) > 0) return 'warn'
  if (status.queued_tasks > 0 || status.scheduled_tasks > 0) return 'info'
  return 'safe'
}

function isSetSelected(key: string) {
  return selectedSetKeys.value.includes(key)
}

function toggleSet(key: string) {
  if (isSetSelected(key)) {
    selectedSetKeys.value = selectedSetKeys.value.filter((item) => item !== key)
    return
  }
  selectedSetKeys.value = [...selectedSetKeys.value, key]
}

function isGroupSelected(group: AttackSetGroup) {
  return Boolean(group.sets.length) && group.sets.every((item) => isSetSelected(item.key))
}

function isGroupPartial(group: AttackSetGroup) {
  return group.sets.some((item) => isSetSelected(item.key)) && !isGroupSelected(group)
}

function toggleGroup(group: AttackSetGroup) {
  const current = new Set(selectedSetKeys.value)
  if (isGroupSelected(group)) {
    for (const item of group.sets) {
      current.delete(item.key)
    }
  } else {
    for (const item of group.sets) {
      current.add(item.key)
    }
  }
  selectedSetKeys.value = Array.from(current)
}

function selectAllSets() {
  selectedSetKeys.value = allAttackSets.value.map((item) => item.key)
}

function clearSelectedSets() {
  selectedSetKeys.value = []
}

async function runSelectedAttacks() {
  if (!selectedEndpoint.value) {
    actionMessage.value = '先选择要攻击的 AI'
    return
  }
  if (!selectedSets.value.length) {
    actionMessage.value = '先选择攻击集'
    return
  }

  executing.value = true
  error.value = null
  actionMessage.value = `正在展开 ${selectedSets.value.length} 个攻击集...`

  try {
    const sampleIds = await resolveSelectedSampleIds(selectedSets.value)
    if (!sampleIds.length) {
      throw new Error('选中的攻击集没有可执行样本')
    }

    actionMessage.value = `已解析 ${sampleIds.length} 条攻击样本，正在提交任务...`
    const response = await api.createAttackTasksFromSamples({
      sample_ids: sampleIds,
      target_agent: targetAgentName(selectedEndpoint.value),
      ai_endpoint_id: selectedEndpoint.value.id,
      auto_run: true,
      params_json: {
        initiated_from: 'attack_lab',
        attack_set_count: selectedSets.value.length,
        attack_sets: selectedSets.value.map((item) => item.key),
        attack_groups: Array.from(new Set(selectedSets.value.map((item) => item.groupKey))),
      },
    })

    lastSubmittedTaskIds.value = response.items.map((item) => item.id)
    await refreshTaskWorkspace(true)
    actionMessage.value = `已提交 ${response.created} 个攻击任务，入队 ${response.enqueued_task_ids.length} 个`
    lastActionAt.value = formatBeijingTime()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '攻击任务提交失败'
    actionMessage.value = '提交失败'
  } finally {
    executing.value = false
  }
}

async function resolveSelectedSampleIds(sets: AttackSet[]) {
  const ids = new Set<string>()
  for (const set of sets) {
    actionMessage.value = `正在读取攻击集：${set.label}`
    const sectionIds = await fetchAllSampleIdsBySection(set.key)
    for (const id of sectionIds) {
      ids.add(id)
    }
  }
  return Array.from(ids)
}

async function fetchAllSampleIdsBySection(section: string) {
  const ids: string[] = []
  let page = 1
  let total = 0

  do {
    const payload = await api.samples({
      section,
      page,
      page_size: SAMPLE_PAGE_SIZE,
    })
    total = payload.total
    ids.push(...payload.items.map((item: SampleListItem) => item.id))
    page += 1
  } while (ids.length < total)

  return ids
}

function targetAgentName(endpoint: AiEndpointItem) {
  return endpoint.display_name || endpoint.endpoint_key || `ai-endpoint-${endpoint.id}`
}

function endpointLabel(endpoint?: AiEndpointItem | null) {
  if (!endpoint) return '未选择'
  return endpoint.display_name || endpoint.endpoint_key
}

function endpointMeta(endpoint?: AiEndpointItem | null) {
  if (!endpoint) return '无目标'
  return `${endpoint.endpoint_group || '默认分组'} / ${endpoint.model_name || endpoint.provider_type}`
}

function endpointTone(endpoint?: AiEndpointItem | null): Tone {
  if (!endpoint) return 'info'
  if (!endpoint.protection_enabled) return 'warn'
  if (endpoint.protection_mode === 'enforce') return 'safe'
  if (endpoint.protection_mode === 'observe') return 'warn'
  return 'info'
}

function endpointProtectionLabel(endpoint?: AiEndpointItem | null) {
  if (!endpoint) return '未选择'
  if (!endpoint.protection_enabled) return '未开启防护'
  if (endpoint.protection_mode === 'enforce') return '强拦截'
  if (endpoint.protection_mode === 'observe') return '观察'
  return '关闭'
}

function taskStatusLabel(status: string) {
  if (status === 'ready') return '待执行'
  if (status === 'queued') return '排队中'
  if (status === 'scheduled') return '已调度'
  if (status === 'running') return '运行中'
  if (status === 'done') return '已完成'
  if (status === 'failed') return '失败'
  if (status === 'cancelled') return '已取消'
  if (status === 'dead_letter') return '死信'
  return status
}

function taskTone(status?: string | null): Tone {
  if (status === 'done') return 'safe'
  if (status === 'failed' || status === 'dead_letter') return 'danger'
  if (status === 'running' || status === 'scheduled') return 'warn'
  return 'info'
}

function riskTone(value?: string): Tone {
  if (value === 'critical' || value === 'high') return 'danger'
  if (value === 'medium') return 'warn'
  if (value === 'low') return 'safe'
  return 'info'
}

function riskLabel(value?: string) {
  if (value === 'critical') return '严重'
  if (value === 'high') return '高危'
  if (value === 'medium') return '中危'
  if (value === 'low') return '低危'
  return value || '未分级'
}

function taskTime(task: AttackTaskItem) {
  return task.finished_at || task.started_at || task.scheduled_at || task.created_at || ''
}

function isLastSubmitted(taskId: number) {
  return lastSubmittedTaskIds.value.includes(taskId)
}
</script>

<template>
  <section class="attack-testing-shell attack-lab-simple">
    <header class="attack-testing-header attack-lab-header">
      <div class="attack-testing-copy">
        <p class="attack-testing-kicker">攻击实验室</p>
        <h1>选择攻击集后直接验证防护效果</h1>
      </div>
      <div class="attack-testing-actions">
        <RouterLink class="ghost-button" to="/ai-endpoints">AI 目标</RouterLink>
        <button class="ghost-button" type="button" :disabled="refreshingTasks" @click="refreshTaskWorkspace()">
          刷新状态
        </button>
      </div>
    </header>

    <div v-if="error" class="attack-lab-alert">{{ error }}</div>

    <section class="attack-lab-console">
      <div class="attack-lab-target">
        <label for="attack-target-select">攻击目标</label>
        <select id="attack-target-select" v-model="selectedEndpointId" class="select-input">
          <option value="">选择要攻击的 AI</option>
          <option v-for="endpoint in enabledEndpoints" :key="endpoint.id" :value="String(endpoint.id)">
            {{ endpointLabel(endpoint) }}
          </option>
        </select>
        <div class="attack-lab-target-meta">
          <strong>{{ endpointLabel(selectedEndpoint) }}</strong>
          <span>{{ endpointMeta(selectedEndpoint) }}</span>
          <StatusPill :label="endpointProtectionLabel(selectedEndpoint)" :tone="endpointTone(selectedEndpoint)" />
        </div>
      </div>

      <div class="attack-lab-metrics">
        <div>
          <span>已选攻击集</span>
          <strong>{{ selectedSets.length }} / {{ allAttackSets.length }}</strong>
        </div>
        <div>
          <span>预计样本</span>
          <strong>{{ selectedSampleEstimate }} / {{ totalSampleCount }}</strong>
        </div>
        <div>
          <span>执行器</span>
          <strong>{{ workerLabel(workerStatus) }}</strong>
        </div>
      </div>

      <button class="primary-button attack-lab-run-button" type="button" :disabled="!canExecute" @click="runSelectedAttacks">
        {{ executing ? '正在提交...' : '开始攻击' }}
      </button>
    </section>

    <section class="attack-lab-workspace">
      <main class="attack-lab-set-panel">
        <div class="attack-lab-set-toolbar">
          <div>
            <h2>攻击集</h2>
            <p>{{ actionMessage }}<span v-if="lastActionAt"> / {{ lastActionAt }}</span></p>
          </div>
          <div class="attack-lab-set-actions">
            <button class="ghost-button small" type="button" :disabled="loading || !allAttackSets.length" @click="selectAllSets">
              一键选择全部攻击集
            </button>
            <button class="ghost-button small" type="button" :disabled="loading || !selectedSetKeys.length" @click="clearSelectedSets">
              清空
            </button>
          </div>
        </div>

        <div v-if="loading" class="empty-state">正在加载攻击集...</div>
        <div v-else-if="!attackGroups.length" class="empty-state">暂无可用攻击集。</div>
        <div v-else class="attack-set-groups">
          <article
            v-for="group in attackGroups"
            :key="group.key"
            :class="[
              'attack-set-group',
              {
                selected: isGroupSelected(group),
                partial: isGroupPartial(group),
              },
            ]"
          >
            <div class="attack-set-group-head">
              <button class="attack-set-group-toggle" type="button" @click="toggleGroup(group)">
                {{ isGroupSelected(group) ? '取消本类' : '选择本类' }}
              </button>
              <div class="attack-set-group-title">
                <h3>{{ group.label }}</h3>
                <span>{{ group.sectionCount }} 个攻击集 / {{ group.entryCount }} 条</span>
              </div>
            </div>

            <div class="attack-set-list">
              <label v-for="set in group.sets" :key="set.key" :class="['attack-set-row', { selected: isSetSelected(set.key) }]">
                <input type="checkbox" :checked="isSetSelected(set.key)" @change="toggleSet(set.key)" />
                <span class="attack-set-name">{{ set.label }}</span>
                <span class="attack-set-count">{{ set.entryCount }} 条</span>
                <StatusPill :label="riskLabel(set.riskLevel)" :tone="riskTone(set.riskLevel)" />
              </label>
            </div>
          </article>
        </div>
      </main>

      <aside class="attack-lab-task-panel">
        <section class="attack-task-summary">
          <div>
            <span>任务状态</span>
            <strong>{{ taskCounts.running }} 运行中 / {{ taskCounts.pending }} 排队中 / {{ taskCounts.finished }} 已结束</strong>
          </div>
          <StatusPill :label="workerLabel(workerStatus)" :tone="workerTone(workerStatus)" />
        </section>

        <section class="attack-task-stream-card">
          <div class="attack-task-list-head">
            <h3>攻击执行状态</h3>
            <span>{{ taskCounts.running + taskCounts.finished }}</span>
          </div>
          <div class="attack-task-stream">
            <section class="attack-task-section">
              <div class="attack-task-section-head running">
                <strong>正在运行</strong>
                <span>{{ taskCounts.running }}</span>
              </div>
              <div v-if="!runningTasks.length" class="attack-task-empty">
                当前没有运行中的攻击。{{ pendingSummaryLabel() }}
              </div>
              <div v-else class="attack-task-list">
                <article v-for="task in runningTasks" :key="task.id" class="attack-task-row active">
                  <div>
                    <strong>#{{ task.id }} {{ task.task_name }}</strong>
                    <span>{{ task.source_ref || task.attack_type }} / {{ task.target_agent }}</span>
                  </div>
                  <div class="attack-task-row-side">
                    <StatusPill v-if="isLastSubmitted(task.id)" label="本次" tone="info" />
                    <StatusPill :label="taskStatusLabel(task.status)" :tone="taskTone(task.status)" />
                  </div>
                </article>
              </div>
            </section>

            <section class="attack-task-section">
              <div class="attack-task-section-head">
                <strong>已经结束</strong>
                <span>{{ taskCounts.finished }}</span>
              </div>
              <div v-if="!finishedTasks.length" class="attack-task-empty">还没有结束的攻击任务。</div>
              <div v-else class="attack-task-list">
                <article v-for="task in finishedTasks" :key="task.id" class="attack-task-row">
                  <div>
                    <strong>#{{ task.id }} {{ task.task_name }}</strong>
                    <span>{{ task.result_summary || task.source_ref || task.attack_type }}</span>
                    <small v-if="taskTime(task)">{{ taskTime(task) }}</small>
                  </div>
                  <div class="attack-task-row-side">
                    <StatusPill v-if="isLastSubmitted(task.id)" label="本次" tone="info" />
                    <StatusPill :label="taskStatusLabel(task.status)" :tone="taskTone(task.status)" />
                  </div>
                </article>
              </div>
            </section>
          </div>
        </section>
      </aside>
    </section>
  </section>
</template>
