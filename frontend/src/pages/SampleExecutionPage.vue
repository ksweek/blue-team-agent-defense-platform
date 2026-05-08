<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import {
  api,
  type AiEndpointItem,
  type AttackTaskItem,
  type AttackWorkerStatus,
  type DownloadedFile,
  type ReportItem,
  type SampleCatalogSummary,
  type SampleDetail,
  type SampleListItem,
  type SamplePackItem,
  type SampleSectionItem,
  type SecurityEventDetail,
  type SystemActionTone,
} from '../services/api'
import { redactSensitiveText } from '../services/redaction'
import { formatBeijingTime } from '../services/time'

type Tone = SystemActionTone
type SyncState = 'idle' | 'saving' | 'saved' | 'error'
type ProtectionMode = AiEndpointItem['protection_mode']

const PAGE_SIZE = 10

const loading = ref(true)
const error = ref<string | null>(null)

const sampleSummary = ref<SampleCatalogSummary | null>(null)
const sectionItems = ref<SampleSectionItem[]>([])
const packItems = ref<SamplePackItem[]>([])
const sampleItems = ref<SampleListItem[]>([])
const sampleTotal = ref(0)
const currentPage = ref(1)
const activeEndpointGroup = ref('all')

const selectedSampleIds = ref<string[]>([])
const focusedSampleId = ref<string | null>(null)
const focusedSample = ref<SampleDetail | null>(null)

const taskItems = ref<AttackTaskItem[]>([])
const aiEndpoints = ref<AiEndpointItem[]>([])
const selectedTaskIds = ref<number[]>([])
const focusedTaskId = ref<number | null>(null)
const focusedTask = ref<AttackTaskItem | null>(null)
const focusedEvent = ref<SecurityEventDetail | null>(null)
const focusedReport = ref<ReportItem | null>(null)
const workerStatus = ref<AttackWorkerStatus | null>(null)

const filters = reactive({
  section: '',
  pack: '',
  risk_level: '',
  test_mode: '',
  keyword: '',
})

const form = reactive({
  aiEndpointId: '',
  targetAgent: 'web-agent-prod',
  taskName: '',
  batchLabel: '',
  scheduleAt: '',
})

const activeAction = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('等待执行')
const lastActionAt = ref('')

let pollingTimer: ReturnType<typeof setInterval> | null = null
let keywordTimer: ReturnType<typeof setTimeout> | null = null

const totalSamplePages = computed(() => Math.max(1, Math.ceil(sampleTotal.value / PAGE_SIZE)))
const defaultAiEndpoint = computed(() => aiEndpoints.value.find((item) => item.is_default) ?? aiEndpoints.value[0] ?? null)
const selectedAiEndpoint = computed(() =>
  form.aiEndpointId ? aiEndpoints.value.find((item) => String(item.id) === form.aiEndpointId) ?? null : null
)
const resolvedAiEndpoint = computed(() => selectedAiEndpoint.value ?? defaultAiEndpoint.value)
const usingDefaultRoute = computed(() => !form.aiEndpointId && Boolean(defaultAiEndpoint.value))
const canOperateCurrent = computed(() => Boolean(focusedSampleId.value && form.targetAgent.trim() && resolvedAiEndpoint.value))
const canOperateBatch = computed(() => Boolean(selectedSampleIds.value.length && form.targetAgent.trim() && resolvedAiEndpoint.value))
const canScheduleBatch = computed(() => canOperateBatch.value && Boolean(form.scheduleAt))

const endpointGroupTabs = computed(() => {
  const counters = new Map<string, { label: string; count: number }>()
  for (const item of aiEndpoints.value) {
    const key = normalizeEndpointGroup(item.endpoint_group)
    const bucket = counters.get(key)
    if (bucket) {
      bucket.count += 1
      continue
    }
    counters.set(key, { label: endpointGroupLabel(item.endpoint_group), count: 1 })
  }

  return [
    { key: 'all', label: '全部', count: aiEndpoints.value.length },
    ...Array.from(counters.entries())
      .sort((left, right) => left[0].localeCompare(right[0], 'zh-CN'))
      .map(([key, value]) => ({
        key,
        label: value.label,
        count: value.count,
      })),
  ]
})

const visibleAiEndpoints = computed(() =>
  activeEndpointGroup.value === 'all'
    ? aiEndpoints.value
    : aiEndpoints.value.filter((item) => normalizeEndpointGroup(item.endpoint_group) === activeEndpointGroup.value)
)

const selectedTasks = computed(() => {
  const idSet = new Set(selectedTaskIds.value)
  return taskItems.value.filter((item) => idSet.has(item.id))
})

const readySelectedTaskCount = computed(() =>
  selectedTasks.value.filter((item) => Boolean(item.latest_report_id)).length
)
const activeTaskCount = computed(() =>
  taskItems.value.filter((item) => isTaskActive(item.status)).length
)
const completedSelectedTaskCount = computed(() =>
  selectedTasks.value.filter((item) => item.status === 'done').length
)
const failedSelectedTaskCount = computed(() =>
  selectedTasks.value.filter((item) => item.status === 'failed').length
)

const syncTone = computed<Tone>(() => {
  if (syncState.value === 'saved') return 'safe'
  if (syncState.value === 'error') return 'danger'
  if (syncState.value === 'saving') return 'warn'
  return 'info'
})

const syncLabel = computed(() => {
  if (syncState.value === 'saving') return '处理中'
  if (syncState.value === 'saved') return '已同步'
  if (syncState.value === 'error') return '失败'
  return '就绪'
})

const selectedSampleTurns = computed(() => {
  const turns = focusedSample.value?.turns
  if (Array.isArray(turns) && turns.length) {
    return turns
  }
  if (focusedSample.value?.content) {
    return [{ role: 'user', stage: 'prompt', content: focusedSample.value.content }]
  }
  return [] as Array<{ role: string; stage?: string; content: string }>
})

const focusedTaskTone = computed<Tone>(() => mapTaskTone(focusedTask.value?.status))
const focusedGuardTrace = computed(() => focusedTask.value?.guard_trace ?? null)

const statusItems = computed(
  () =>
    [
      {
        label: '样本池',
        value: `${selectedSampleIds.value.length} 个`,
        meta: focusedSample.value ? `当前预览 ${focusedSample.value.id}` : '未预览样本',
        tone: selectedSampleIds.value.length ? ('info' as Tone) : ('warn' as Tone),
      },
      {
        label: '目标路由',
        value: resolvedAiEndpoint.value ? (usingDefaultRoute.value ? '默认' : '指定') : '未配置',
        meta: resolvedAiEndpoint.value
          ? `${resolvedAiEndpoint.value.display_name} / ${endpointGroupLabel(resolvedAiEndpoint.value.endpoint_group)}`
          : '先配置 AI 目标',
        tone: resolvedAiEndpoint.value ? ('safe' as Tone) : ('danger' as Tone),
      },
      {
        label: '任务列表',
        value: `${selectedTaskIds.value.length} 个`,
        meta: selectedTaskIds.value.length
          ? `可下载报告 ${readySelectedTaskCount.value} 份`
          : '未选择任务',
        tone: selectedTaskIds.value.length ? ('info' as Tone) : ('warn' as Tone),
      },
      {
        label: '批次进度',
        value: selectedTaskIds.value.length
          ? `${completedSelectedTaskCount.value} 完成 / ${failedSelectedTaskCount.value} 失败`
          : '等待批次',
        meta: selectedTaskIds.value.length
          ? `运行中 ${selectedTasks.value.filter((item) => isTaskActive(item.status)).length} 个`
          : '先创建批量任务',
        tone: failedSelectedTaskCount.value ? ('danger' as Tone) : ('safe' as Tone),
      },
      {
        label: '执行器',
        value: workerStatus.value ? workerLabel(workerStatus.value) : '加载中',
        meta: workerStatus.value
          ? `队列 ${workerStatus.value.queued_tasks} / 定时 ${workerStatus.value.scheduled_tasks}`
          : '等待状态',
        tone: workerTone(workerStatus.value),
      },
    ] as Array<{ label: string; value: string; meta: string; tone: Tone }>
)

const focusedTaskTimeline = computed(() => {
  const items: Array<{ label: string; value: string; tone: Tone }> = []
  if (focusedTask.value?.created_at) {
    items.push({ label: '任务创建', value: focusedTask.value.created_at, tone: 'info' })
  }
  if (focusedTask.value?.scheduled_at) {
    items.push({ label: '已调度', value: focusedTask.value.scheduled_at, tone: 'warn' })
  }
  if (focusedTask.value?.started_at) {
    items.push({ label: '开始执行', value: focusedTask.value.started_at, tone: 'warn' })
  }
  if (focusedTask.value?.finished_at) {
    items.push({ label: '执行结束', value: focusedTask.value.finished_at, tone: mapTaskTone(focusedTask.value.status) })
  }
  if (focusedReport.value?.created_at) {
    items.push({ label: '报告归档', value: focusedReport.value.created_at, tone: 'safe' })
  }
  return items
})

watch(
  () => [filters.section, filters.pack, filters.risk_level, filters.test_mode],
  () => {
    currentPage.value = 1
    void loadSamples()
  }
)

watch(currentPage, () => {
  void loadSamples()
})

watch(
  () => filters.keyword,
  () => {
    if (keywordTimer) {
      clearTimeout(keywordTimer)
    }
    keywordTimer = setTimeout(() => {
      currentPage.value = 1
      void loadSamples()
    }, 280)
  }
)

watch(
  activeTaskCount,
  (count) => {
    if (count > 0) {
      startPolling()
      return
    }
    stopPolling()
  },
  { immediate: true }
)

onMounted(() => {
  void initializePage()
})

onBeforeUnmount(() => {
  stopPolling()
  if (keywordTimer) {
    clearTimeout(keywordTimer)
    keywordTimer = null
  }
})

function isTaskActive(status?: string | null) {
  return status === 'queued' || status === 'running' || status === 'scheduled'
}

function mapTaskTone(status?: string | null): Tone {
  if (status === 'done') return 'safe'
  if (status === 'failed') return 'danger'
  if (status === 'running' || status === 'scheduled') return 'warn'
  return 'info'
}

function normalizeEndpointGroup(value?: string | null) {
  return (value ?? '').trim() || 'default'
}

function endpointGroupLabel(value?: string | null) {
  const key = normalizeEndpointGroup(value)
  if (key === 'default') return '默认分组'
  if (key === 'environment') return '环境回退'
  return key
}

function endpointProtectionLabel(
  item?: { protection_enabled: boolean; protection_mode: ProtectionMode } | null
) {
  if (!item || !item.protection_enabled) return '未防护'
  if (item.protection_mode === 'enforce') return '强拦截'
  if (item.protection_mode === 'observe') return '观察'
  return '关闭'
}

function endpointProtectionTone(
  item?: { protection_enabled: boolean; protection_mode: ProtectionMode } | null
): Tone {
  if (!item || !item.protection_enabled) return 'info'
  if (item.protection_mode === 'enforce') return 'safe'
  return 'warn'
}

function workerTone(status: AttackWorkerStatus | null): Tone {
  if (!status) return 'info'
  if (status.active_task_id) return 'warn'
  if (status.queued_tasks > 0 || status.scheduled_tasks > 0) return 'info'
  return 'safe'
}

function taskStatusLabel(status: string) {
  if (status === 'ready') return '待执行'
  if (status === 'queued') return '排队中'
  if (status === 'scheduled') return '已调度'
  if (status === 'running') return '运行中'
  if (status === 'done') return '已完成'
  if (status === 'failed') return '失败'
  return status
}

function guardDecisionTone(decision?: string | null): Tone {
  if (decision === 'deny') return 'danger'
  if (decision === 'review') return 'warn'
  if (decision === 'allow') return 'safe'
  return 'info'
}

function guardDecisionLabel(decision?: string | null) {
  if (decision === 'deny') return '阻断'
  if (decision === 'review') return '复核'
  if (decision === 'allow') return '放行'
  return '未判定'
}

function guardSourceLabel(source?: string | null) {
  if (source === 'worker_preflight_reused') return 'worker 预检复用'
  if (source === 'worker_preflight_blocked') return 'worker 预检阻断'
  if (source === 'runtime_authorization_snapshot') return '运行时授权快照'
  if (source === 'task_runner_evaluated') return '执行阶段评估'
  if (source === 'raw_response_embedded') return '响应内嵌结果'
  return '未记录'
}

function guardVerdictLabel(verdict?: string | null) {
  if (verdict === 'blocked') return '命中阻断'
  if (verdict === 'suspicious') return '命中可疑'
  if (verdict === 'clean') return '规则放行'
  return '未记录'
}

function workerLabel(status: AttackWorkerStatus) {
  if (status.active_task_id) return `运行 #${status.active_task_id}`
  if (status.queued_tasks > 0) return '队列待执行'
  if (status.scheduled_tasks > 0) return '等待调度'
  return '空闲'
}

function riskLabel(value?: string) {
  if (value === 'critical') return '严重'
  if (value === 'high') return '高危'
  if (value === 'medium') return '中危'
  if (value === 'low') return '低危'
  return value || '-'
}

function riskTone(value?: string): Tone {
  if (value === 'critical' || value === 'high') return 'danger'
  if (value === 'medium') return 'warn'
  return 'info'
}

function displayText(value?: string | null) {
  return redactSensitiveText(value)
}

function modeLabel(value?: string) {
  if (value === 'multi_turn') return '多轮'
  if (value === 'single_turn') return '单轮'
  return value || '单轮'
}

function sampleFamilyLabel(item?: { attack_family?: string; classification?: { family_label?: string } } | null) {
  return item?.classification?.family_label || item?.attack_family || '-'
}

function sampleSectionLabel(item?: { mapped_section?: string; classification?: { section_label?: string } } | null) {
  return item?.classification?.section_label || item?.mapped_section || '-'
}

function samplePrimaryLabel(item?: { classification?: { primary_label?: string } } | null) {
  return item?.classification?.primary_label || '未分类攻击面'
}

function sampleSourceLabel(item?: { source_repo?: string; classification?: { source_label?: string } } | null) {
  return item?.classification?.source_label || item?.source_repo || '-'
}

function normalizeEndpointDisplayName(name?: string | null) {
  if (!name) return '默认路由'
  return name === 'Environment Default' ? '环境默认路由' : name
}

function taskEndpointLabel(task?: AttackTaskItem | null) {
  return normalizeEndpointDisplayName(task?.ai_endpoint?.display_name || task?.ai_endpoint?.endpoint_key)
}

function selectedEndpointLabel() {
  if (usingDefaultRoute.value && resolvedAiEndpoint.value) {
    return `默认路由 / ${normalizeEndpointDisplayName(resolvedAiEndpoint.value.display_name || resolvedAiEndpoint.value.endpoint_key)}`
  }
  if (selectedAiEndpoint.value) {
    return normalizeEndpointDisplayName(selectedAiEndpoint.value.display_name || selectedAiEndpoint.value.endpoint_key)
  }
  return '未配置 AI'
}

function ensureEndpointRouteState() {
  if (!aiEndpoints.value.length) {
    form.aiEndpointId = ''
    activeEndpointGroup.value = 'all'
    return
  }

  if (form.aiEndpointId && !aiEndpoints.value.some((item) => String(item.id) === form.aiEndpointId)) {
    form.aiEndpointId = ''
  }

  if (activeEndpointGroup.value !== 'all' && !endpointGroupTabs.value.some((item) => item.key === activeEndpointGroup.value)) {
    activeEndpointGroup.value = 'all'
  }
}

function selectExplicitEndpoint(endpointId: number) {
  form.aiEndpointId = String(endpointId)
}

function useDefaultRoute() {
  form.aiEndpointId = ''
}

function formatActionTime() {
  return formatBeijingTime()
}

function beginAction(key: string, message: string) {
  activeAction.value = key
  syncState.value = 'saving'
  syncMessage.value = message
}

function finishAction(message: string) {
  activeAction.value = null
  syncState.value = 'saved'
  syncMessage.value = message
  lastActionAt.value = formatActionTime()
}

function failAction(message: string) {
  activeAction.value = null
  syncState.value = 'error'
  syncMessage.value = message
}

function buildCommonTaskParams(sampleCount: number) {
  const params: Record<string, unknown> = {
    initiated_from: 'sample_execution_page',
    sample_count: sampleCount,
  }

  if (form.batchLabel.trim()) {
    params.batch_label = form.batchLabel.trim()
  }

  return params
}

function taskBatchLabel(task: AttackTaskItem) {
  const label = task.params_json?.batch_label
  return typeof label === 'string' ? label : ''
}

function triggerFileDownload(file: DownloadedFile) {
  const url = window.URL.createObjectURL(file.blob)
  const link = document.createElement('a')
  link.href = url
  link.download = file.filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

async function initializePage() {
  loading.value = true
  error.value = null

  try {
    const [summary, sectionsPayload, packsPayload, endpointsPayload] = await Promise.all([
      api.sampleCatalogSummary(),
      api.sampleSections(),
      api.samplePacks(),
      api.aiEndpoints(),
    ])

     sampleSummary.value = summary
     sectionItems.value = sectionsPayload.items
     packItems.value = packsPayload.items
     aiEndpoints.value = endpointsPayload.items.filter((item) => item.enabled)
     ensureEndpointRouteState()
     if (!aiEndpoints.value.length) {
       syncState.value = 'error'
       syncMessage.value = '先到 AI 目标页配置可用端点'
     }

    await Promise.all([loadSamples(), refreshTaskWorkspace()])

    if (!focusedSampleId.value && sampleItems.value.length) {
      await focusSample(sampleItems.value[0].id)
    }

    if (!focusedTaskId.value && taskItems.value.length) {
      await focusTask(taskItems.value[0].id)
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function loadSamples() {
  const response = await api.samples({
    page: currentPage.value,
    page_size: PAGE_SIZE,
    section: filters.section || undefined,
    pack: filters.pack || undefined,
    risk_level: filters.risk_level || undefined,
    test_mode: filters.test_mode || undefined,
    keyword: filters.keyword.trim() || undefined,
  })

  sampleItems.value = response.items
  sampleTotal.value = response.total

  if (!focusedSampleId.value && sampleItems.value.length) {
    await focusSample(sampleItems.value[0].id)
  }
}

async function refreshTaskWorkspace() {
  const [tasksPayload, worker] = await Promise.all([
    api.attackTasks({ page_size: 24, source_type: 'dataset_sample' }),
    api.attackWorkerStatus(),
  ])

  taskItems.value = tasksPayload.items
  workerStatus.value = worker

  const visibleTaskIds = new Set(taskItems.value.map((item) => item.id))
  selectedTaskIds.value = selectedTaskIds.value.filter((item) => visibleTaskIds.has(item))
}

async function focusSample(sampleId: string) {
  focusedSampleId.value = sampleId
  focusedSample.value = await api.sampleDetail(sampleId)
  syncState.value = 'idle'
  syncMessage.value = `已切换样本 ${sampleId}`
}

function isSampleSelected(sampleId: string) {
  return selectedSampleIds.value.includes(sampleId)
}

function toggleSampleSelection(sampleId: string) {
  if (isSampleSelected(sampleId)) {
    selectedSampleIds.value = selectedSampleIds.value.filter((item) => item !== sampleId)
    return
  }
  selectedSampleIds.value = [...selectedSampleIds.value, sampleId]
}

function selectAllVisibleSamples() {
  const merged = new Set(selectedSampleIds.value)
  for (const item of sampleItems.value) {
    merged.add(item.id)
  }
  selectedSampleIds.value = Array.from(merged)
  syncState.value = 'idle'
  syncMessage.value = `已选择本页 ${sampleItems.value.length} 个样本`
}

function clearSelectedSamples() {
  selectedSampleIds.value = []
  syncState.value = 'idle'
  syncMessage.value = '已清空样本选择'
}

async function focusTask(taskId: number) {
  focusedTaskId.value = taskId
  await refreshFocusedTask(taskId)
}

function isTaskSelected(taskId: number) {
  return selectedTaskIds.value.includes(taskId)
}

function toggleTaskSelection(taskId: number) {
  if (isTaskSelected(taskId)) {
    selectedTaskIds.value = selectedTaskIds.value.filter((item) => item !== taskId)
    return
  }
  selectedTaskIds.value = [...selectedTaskIds.value, taskId]
}

function selectTasksWithReports() {
  selectedTaskIds.value = taskItems.value
    .filter((item) => Boolean(item.latest_report_id))
    .map((item) => item.id)
  syncState.value = 'idle'
  syncMessage.value = selectedTaskIds.value.length ? '已选择可下载报告的任务' : '当前没有可下载报告的任务'
}

function clearSelectedTasks() {
  selectedTaskIds.value = []
  syncState.value = 'idle'
  syncMessage.value = '已清空任务选择'
}

async function refreshFocusedTask(taskId?: number) {
  const id = taskId ?? focusedTaskId.value
  if (!id) {
    focusedTask.value = null
    focusedEvent.value = null
    focusedReport.value = null
    return
  }

  const task = await api.attackTask(id)
  focusedTask.value = task

  const [event, report] = await Promise.all([
    task.latest_event_id ? api.securityEvent(task.latest_event_id) : Promise.resolve(null),
    task.latest_report_id ? api.report(task.latest_report_id) : Promise.resolve(null),
  ])

  focusedEvent.value = event
  focusedReport.value = report
}

async function createCurrentTaskInternal() {
  const aiEndpointId = form.aiEndpointId ? Number(form.aiEndpointId) : undefined
  if (!focusedSampleId.value || !form.targetAgent.trim() || !resolvedAiEndpoint.value) {
    throw new Error('先选择样本、目标路由并填写目标实例')
  }

  const response = await api.createAttackTaskFromSample({
    sample_id: focusedSampleId.value,
    target_agent: form.targetAgent.trim(),
    ai_endpoint_id: aiEndpointId,
    task_name: form.taskName.trim() || undefined,
    params_json: buildCommonTaskParams(1),
    auto_run: false,
  })

  await refreshTaskWorkspace()
  selectedTaskIds.value = [response.task.id]
  await focusTask(response.task.id)
  return response.task
}

async function ensureCurrentTaskForFocusedSample() {
  const targetAgent = form.targetAgent.trim()
  const aiEndpointId = resolvedAiEndpoint.value?.id ?? null
  if (
    focusedTask.value &&
    focusedTask.value.source_ref === focusedSampleId.value &&
    focusedTask.value.target_agent === targetAgent &&
    focusedTask.value.ai_endpoint?.id === aiEndpointId
  ) {
    return focusedTask.value
  }

  return createCurrentTaskInternal()
}

async function createCurrentTask() {
  beginAction('create-current', '正在创建当前样本任务...')

  try {
    const task = await createCurrentTaskInternal()
    finishAction(`任务 #${task.id} 已创建`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '创建失败')
  }
}

async function runCurrentSample() {
  beginAction('run-current', '正在执行当前样本...')

  try {
    const task = await ensureCurrentTaskForFocusedSample()
    const result = await api.runAttackTask(task.id)
    await refreshTaskWorkspace()
    await refreshFocusedTask(result.task.id)
    finishAction(`任务 #${result.task.id} 已进入 ${taskStatusLabel(result.task.status)}`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '执行失败')
  }
}

async function createBatchTasks(autoRun: boolean, scheduleAt?: string) {
  const aiEndpointId = form.aiEndpointId ? Number(form.aiEndpointId) : undefined
  if (!selectedSampleIds.value.length || !form.targetAgent.trim() || !resolvedAiEndpoint.value) {
    throw new Error('先勾选样本、确认目标路由并填写目标实例')
  }

  const response = await api.createAttackTasksFromSamples({
    sample_ids: selectedSampleIds.value,
    target_agent: form.targetAgent.trim(),
    ai_endpoint_id: aiEndpointId,
    params_json: buildCommonTaskParams(selectedSampleIds.value.length),
    auto_run: autoRun,
    schedule_at: scheduleAt,
  })

  await refreshTaskWorkspace()
  selectedTaskIds.value = response.items.map((item) => item.id)

  if (response.items.length) {
    await focusTask(response.items[0].id)
  }

  return response
}

async function createBatchOnly() {
  beginAction('batch-create', '正在批量创建任务...')

  try {
    const response = await createBatchTasks(false)
    finishAction(`已创建 ${response.created} 个批量任务`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '批量创建失败')
  }
}

async function runBatchNow() {
  beginAction('batch-run', '正在批量提交执行...')

  try {
    const response = await createBatchTasks(true)
    finishAction(`已创建并入队 ${response.created} 个任务`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '批量执行失败')
  }
}

async function scheduleBatchRun() {
  if (!form.scheduleAt) {
    failAction('先选择调度时间')
    return
  }

  beginAction('batch-schedule', '正在创建批量调度...')

  try {
    const response = await createBatchTasks(true, new Date(form.scheduleAt).toISOString())
    finishAction(`已调度 ${response.created} 个任务`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '批量调度失败')
  }
}

async function refreshWorkspace() {
  beginAction('refresh-workspace', '正在刷新任务状态...')

  try {
    await refreshTaskWorkspace()
    await refreshFocusedTask()
    finishAction('任务状态已刷新')
  } catch (err) {
    failAction(err instanceof Error ? err.message : '刷新失败')
  }
}

async function exportCurrentReport() {
  if (!focusedTask.value?.latest_report_id) {
    failAction('当前任务还没有报告')
    return
  }

  beginAction('report-export', '正在导出当前报告...')

  try {
    const report = await api.exportReport(focusedTask.value.latest_report_id, 'docx')
    focusedReport.value = report
    finishAction(`报告 #${report.id} 已导出`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '导出失败')
  }
}

async function downloadCurrentReport() {
  if (!focusedTask.value?.latest_report_id) {
    failAction('当前任务还没有报告')
    return
  }

  beginAction('report-download', '正在下载当前报告...')

  try {
    const report = await api.exportReport(focusedTask.value.latest_report_id, 'docx')
    focusedReport.value = report
    const file = await api.downloadReport(report.id, 'docx')
    triggerFileDownload(file)
    finishAction(`报告 #${report.id} 已下载`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '下载失败')
  }
}

async function downloadBatchReports() {
  if (!selectedTaskIds.value.length) {
    failAction('先勾选任务')
    return
  }

  beginAction('bundle-download', '正在打包整批报告...')

  try {
    const file = await api.downloadReportBundle({
      task_ids: selectedTaskIds.value,
      include_manifest: true,
      formats: ['docx', 'html', 'json'],
    })
    triggerFileDownload(file)
    finishAction(`已下载 ${selectedTaskIds.value.length} 个任务的整批报告`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '整批下载失败')
  }
}

function startPolling() {
  if (pollingTimer) {
    return
  }

  pollingTimer = setInterval(() => {
    void pollWorkspace()
  }, 2000)
}

function stopPolling() {
  if (!pollingTimer) {
    return
  }

  clearInterval(pollingTimer)
  pollingTimer = null
}

async function pollWorkspace() {
  try {
    await refreshTaskWorkspace()
    if (focusedTaskId.value) {
      await refreshFocusedTask(focusedTaskId.value)
    }
  } catch {
    // Keep the last known state during background refresh.
  }
}

function previousPage() {
  if (currentPage.value > 1) {
    currentPage.value -= 1
  }
}

function nextPage() {
  if (currentPage.value < totalSamplePages.value) {
    currentPage.value += 1
  }
}
</script>

<template>
  <section class="page-grid">
    <div v-if="loading" class="empty-state">正在加载攻击测试台...</div>
    <div v-else-if="error" class="empty-state">
      <p>{{ error }}</p>
      <button class="ghost-button" type="button" @click="initializePage">重试</button>
    </div>

    <section v-else class="content-grid two-column sample-execution-layout">
      <PageSection eyebrow="样本池" title="攻击样本" tag="筛选" tone="info">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>批量回归样本池</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${selectedSampleIds.length} 已选`" :tone="selectedSampleIds.length ? 'info' : 'warn'" />
                <span>总样本 {{ sampleSummary?.total_entries ?? 0 }}</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <button class="ghost-button" type="button" @click="selectAllVisibleSamples">全选本页</button>
              <button class="ghost-button" :disabled="!selectedSampleIds.length" type="button" @click="clearSelectedSamples">清空</button>
            </div>
          </div>

          <div class="section-toolbar section-toolbar-secondary">
            <div class="section-toolbar-fill">
              <div class="sample-filter-grid">
                <select v-model="filters.section" class="select-input">
                  <option value="">全部章节</option>
                  <option v-for="item in sectionItems" :key="item.catalog_file" :value="item.section_name">
                    {{ item.section_name }}
                  </option>
                </select>

                <select v-model="filters.pack" class="select-input">
                  <option value="">全部专项包</option>
                  <option v-for="item in packItems" :key="item.pack_file" :value="item.pack_name">
                    {{ item.pack_name }}
                  </option>
                </select>

                <select v-model="filters.risk_level" class="select-input">
                  <option value="">全部风险</option>
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                </select>

                <select v-model="filters.test_mode" class="select-input">
                  <option value="">全部模式</option>
                  <option value="single_turn">单轮</option>
                  <option value="multi_turn">多轮</option>
                </select>

                <input
                  v-model="filters.keyword"
                  class="text-input sample-search-input"
                  placeholder="搜索样本 / 家族 / 关键词"
                  type="text"
                />
              </div>
            </div>
            <div class="section-toolbar-actions">
              <span class="section-toolbar-note">第 {{ currentPage }} / {{ totalSamplePages }} 页</span>
            </div>
          </div>
        </template>

        <div v-if="sampleItems.length" class="sample-list">
          <article
            v-for="item in sampleItems"
            :key="item.id"
            :class="['sample-list-button', { active: item.id === focusedSampleId }]"
          >
            <div class="card-head">
              <label class="selection-toggle" @click.stop>
                <input
                  class="row-selector"
                  :checked="isSampleSelected(item.id)"
                  type="checkbox"
                  @change="toggleSampleSelection(item.id)"
                />
                <span>{{ item.id }}</span>
              </label>
              <StatusPill :label="riskLabel(item.risk_level)" :tone="riskTone(item.risk_level)" />
            </div>

            <button class="sample-focus-button" type="button" @click="focusSample(item.id)">
              <p class="sample-list-title">{{ item.title }}</p>
              <div class="sample-list-meta">
                <StatusPill :label="modeLabel(item.test_mode)" tone="info" />
                <span>{{ sampleFamilyLabel(item) }}</span>
                <span>{{ sampleSourceLabel(item) }}</span>
              </div>
            </button>
          </article>
        </div>
        <div v-else class="empty-state">当前筛选没有样本。</div>

        <div class="sample-pagination">
          <button class="ghost-button" :disabled="currentPage <= 1" type="button" @click="previousPage">
            上一页
          </button>
          <button class="ghost-button" :disabled="currentPage >= totalSamplePages" type="button" @click="nextPage">
            下一页
          </button>
        </div>

        <div v-if="selectedSampleIds.length" class="token-list">
          <span v-for="sampleId in selectedSampleIds" :key="sampleId" class="token-chip">
            <span>{{ sampleId }}</span>
            <button class="token-chip-remove" type="button" @click="toggleSampleSelection(sampleId)">x</button>
          </span>
        </div>

        <article v-if="focusedSample" class="info-card sample-preview-card">
          <div class="card-head">
            <div>
              <h4>{{ focusedSample.title || focusedSample.id }}</h4>
              <p class="card-subtitle">{{ focusedSample.id }} / {{ sampleSourceLabel(focusedSample) }}</p>
            </div>
            <div class="sample-preview-tags">
              <StatusPill :label="riskLabel(focusedSample.risk_level)" :tone="riskTone(focusedSample.risk_level)" />
              <StatusPill :label="modeLabel(focusedSample.test_mode)" tone="info" />
            </div>
          </div>

          <p class="code-inline">{{ samplePrimaryLabel(focusedSample) }} / {{ sampleFamilyLabel(focusedSample) }}</p>
          <p class="card-subtitle">{{ sampleSectionLabel(focusedSample) }}</p>

          <div class="sample-turn-list">
            <article
              v-for="(turn, index) in selectedSampleTurns"
              :key="`${turn.role}-${turn.stage}-${index}`"
              class="sample-turn-card"
            >
              <div class="card-head">
                <StatusPill :label="turn.role" tone="info" />
                <span class="card-subtitle">{{ turn.stage || `turn-${index + 1}` }}</span>
              </div>
              <p>{{ turn.content }}</p>
            </article>
          </div>
        </article>
      </PageSection>

      <div class="page-grid">
        <PageSection eyebrow="执行编排" title="路由与任务" tag="编排" tone="warn">
          <template #toolbar>
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>当前路由</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="usingDefaultRoute ? '默认回退' : '显式绑定'" :tone="usingDefaultRoute ? 'info' : 'safe'" />
                  <span>{{ selectedEndpointLabel() }}</span>
                  <span v-if="resolvedAiEndpoint">{{ endpointGroupLabel(resolvedAiEndpoint.endpoint_group) }}</span>
                  <span>{{ form.batchLabel.trim() ? `批次 ${form.batchLabel.trim()}` : '未设置批次标签' }}</span>
                </div>
              </div>
              <div class="section-toolbar-actions">
                <RouterLink class="ghost-button" to="/ai-endpoints">管理 AI 目标</RouterLink>
                <RouterLink class="ghost-button" to="/defense-config">查看防御配置</RouterLink>
                <RouterLink class="ghost-button" to="/security-events">查看安全事件</RouterLink>
              </div>
            </div>
          </template>

          <div v-if="!aiEndpoints.length" class="empty-state">
            <p>还没有可用 AI 端点。先到“AI 目标”页新增并启用一个端点。</p>
            <RouterLink class="ghost-button" to="/ai-endpoints">前往配置</RouterLink>
          </div>

          <template v-else>
            <div class="ai-group-tabs">
              <button
                v-for="group in endpointGroupTabs"
                :key="group.key"
                :class="['ai-group-tab', { active: activeEndpointGroup === group.key }]"
                type="button"
                @click="activeEndpointGroup = group.key"
              >
                <span>{{ group.label }}</span>
                <strong>{{ group.count }}</strong>
              </button>
            </div>

            <div class="route-target-grid">
              <button
                :class="['asset-list-button', 'endpoint-list-card', 'route-target-card', { active: usingDefaultRoute }]"
                type="button"
                @click="useDefaultRoute"
              >
                <div class="endpoint-card-top">
                  <strong class="route-card-title">默认路由</strong>
                  <div class="sample-preview-tags">
                    <StatusPill label="自动回退" tone="info" />
                    <StatusPill
                      :label="defaultAiEndpoint ? endpointProtectionLabel(defaultAiEndpoint) : '未配置'"
                      :tone="defaultAiEndpoint ? endpointProtectionTone(defaultAiEndpoint) : 'danger'"
                    />
                  </div>
                </div>
                <div class="route-card-copy">
                  <h4>{{ defaultAiEndpoint?.display_name || '未配置默认路由' }}</h4>
                  <p class="card-subtitle">
                    {{ defaultAiEndpoint ? `${endpointGroupLabel(defaultAiEndpoint.endpoint_group)} / ${defaultAiEndpoint.model_name}` : '需先在 AI 目标页设置默认端点' }}
                  </p>
                </div>
              </button>

              <button
                v-for="item in visibleAiEndpoints.filter((entry) => entry.id !== defaultAiEndpoint?.id)"
                :key="item.id"
                :class="['asset-list-button', 'endpoint-list-card', 'route-target-card', { active: selectedAiEndpoint?.id === item.id }]"
                type="button"
                @click="selectExplicitEndpoint(item.id)"
              >
                <div class="endpoint-card-top">
                  <strong class="route-card-title">{{ item.display_name }}</strong>
                  <div class="sample-preview-tags">
                    <StatusPill v-if="item.is_default" label="默认" tone="info" />
                    <StatusPill :label="endpointProtectionLabel(item)" :tone="endpointProtectionTone(item)" />
                  </div>
                </div>
                <div class="route-card-copy">
                  <p class="card-subtitle">{{ endpointGroupLabel(item.endpoint_group) }} / {{ item.model_name }}</p>
                  <p class="route-card-meta">{{ item.base_url }}</p>
                </div>
              </button>
            </div>

            <div v-if="!visibleAiEndpoints.length" class="empty-state">
              当前分组下没有可用端点，可以切到其他分组或新增端点。
            </div>
          </template>

          <div class="sample-form-grid compact">
            <article class="settings-form-row">
              <div class="settings-form-copy">
                <h4>目标实例</h4>
              </div>
              <div class="settings-form-control">
                <input v-model="form.targetAgent" class="text-input settings-form-input" placeholder="例如 web-agent-prod" type="text" />
              </div>
            </article>

            <article class="settings-form-row">
              <div class="settings-form-copy">
                <h4>当前任务名</h4>
              </div>
              <div class="settings-form-control">
                <input v-model="form.taskName" class="text-input settings-form-input" placeholder="为空则使用样本标题" type="text" />
              </div>
            </article>

            <article class="settings-form-row">
              <div class="settings-form-copy">
                <h4>批次标签</h4>
              </div>
              <div class="settings-form-control">
                <input v-model="form.batchLabel" class="text-input settings-form-input" placeholder="例如 round-01" type="text" />
              </div>
            </article>

            <article class="settings-form-row">
              <div class="settings-form-copy">
                <h4>调度时间</h4>
              </div>
              <div class="settings-form-control">
                <input v-model="form.scheduleAt" class="text-input settings-form-input" type="datetime-local" />
              </div>
            </article>
          </div>

          <div class="action-group">
            <span class="action-group-label">当前样本</span>
            <div class="table-actions">
              <button class="ghost-button" :disabled="activeAction !== null || !canOperateCurrent" type="button" @click="createCurrentTask">
                创建任务
              </button>
              <button class="primary-button" :disabled="activeAction !== null || !canOperateCurrent" type="button" @click="runCurrentSample">
                立即执行
              </button>
            </div>
          </div>

          <div class="action-group">
            <span class="action-group-label">批量样本</span>
            <div class="table-actions">
              <button class="ghost-button" :disabled="activeAction !== null || !canOperateBatch" type="button" @click="createBatchOnly">
                批量建任务
              </button>
              <button class="primary-button" :disabled="activeAction !== null || !canOperateBatch" type="button" @click="runBatchNow">
                批量执行
              </button>
              <button class="ghost-button" :disabled="activeAction !== null || !canScheduleBatch" type="button" @click="scheduleBatchRun">
                批量调度
              </button>
            </div>
          </div>
        </PageSection>

        <PageSection eyebrow="运行回显" title="当前任务" tag="回显" :tone="focusedTaskTone">
          <template #actions>
            <button class="ghost-button small" :disabled="activeAction !== null" type="button" @click="refreshWorkspace">
              刷新状态
            </button>
            <button
              class="ghost-button small"
              :disabled="activeAction !== null || !focusedTask?.latest_report_id"
              type="button"
              @click="exportCurrentReport"
            >
              导出报告
            </button>
            <button
              class="primary-button small"
              :disabled="activeAction !== null || !focusedTask?.latest_report_id"
              type="button"
              @click="downloadCurrentReport"
            >
              下载报告
            </button>
          </template>

          <div v-if="focusedTask" class="list-stack">
            <article class="info-card task-focus-card">
              <div class="card-head">
                <div>
                  <h4>{{ focusedTask.task_name }}</h4>
                  <p class="card-subtitle">执行路由 / {{ taskEndpointLabel(focusedTask) }}</p>
                  <p class="card-subtitle">任务 #{{ focusedTask.id }} / {{ focusedTask.target_agent }}</p>
                </div>
                <div class="sample-preview-tags">
                  <StatusPill :label="taskStatusLabel(focusedTask.status)" :tone="focusedTaskTone" />
                  <StatusPill v-if="focusedTask.ai_endpoint" :label="taskEndpointLabel(focusedTask)" tone="info" />
                  <StatusPill
                    v-if="taskBatchLabel(focusedTask)"
                    :label="taskBatchLabel(focusedTask)"
                    tone="info"
                  />
                </div>
              </div>

              <p v-if="focusedTask.result_summary">{{ displayText(focusedTask.result_summary) }}</p>
              <p v-else class="card-subtitle">等待执行结果</p>

              <div v-if="focusedGuardTrace" class="detail-block">
                <div class="token-list">
                  <StatusPill
                    :label="guardDecisionLabel(focusedGuardTrace.decision)"
                    :tone="guardDecisionTone(focusedGuardTrace.decision)"
                  />
                  <StatusPill
                    :label="guardSourceLabel(focusedGuardTrace.source)"
                    :tone="focusedGuardTrace.reused ? 'safe' : 'info'"
                  />
                  <StatusPill
                    :label="guardVerdictLabel(focusedGuardTrace.rule_verdict)"
                    :tone="guardDecisionTone(focusedGuardTrace.decision)"
                  />
                  <StatusPill
                    :label="focusedGuardTrace.ai_review_invoked ? '已触发 AI 复核' : '未触发 AI 复核'"
                    :tone="focusedGuardTrace.ai_review_invoked ? 'warn' : 'info'"
                  />
                </div>
                <p class="field-helper">授权摘要</p>
                <p class="code-inline detail-code">
                  {{ displayText(focusedGuardTrace.summary || focusedGuardTrace.detail || '当前任务没有授权评估摘要。') }}
                </p>
                <div v-if="focusedGuardTrace.matched_controls.length">
                  <p class="field-helper">命中控制面</p>
                  <div class="token-list">
                    <span
                      v-for="item in focusedGuardTrace.matched_controls"
                      :key="item"
                      class="token-chip"
                    >
                      <span>{{ item }}</span>
                    </span>
                  </div>
                </div>
              </div>

              <div class="timeline-grid">
                <article
                  v-for="item in focusedTaskTimeline"
                  :key="item.label"
                  :class="['timeline-chip', `tone-${item.tone}`]"
                >
                  <span>{{ item.label }}</span>
                  <strong>{{ item.value }}</strong>
                </article>
              </div>

            </article>

            <article v-if="focusedEvent" class="info-card">
              <div class="card-head">
                <h4>安全事件</h4>
                <StatusPill :label="riskLabel(focusedEvent.event_level)" :tone="riskTone(focusedEvent.event_level)" />
              </div>
              <p>{{ displayText(focusedEvent.detail) }}</p>
              <p class="code-inline">{{ focusedEvent.event_type }} / {{ focusedEvent.status }}</p>
            </article>

            <article v-if="focusedReport" class="info-card">
              <div class="card-head">
                <h4>归档报告</h4>
                <StatusPill :label="focusedReport.report_type" tone="safe" />
              </div>
              <p>{{ displayText(focusedReport.summary_text) }}</p>
              <p class="code-inline">{{ displayText(focusedReport.file_path) }}</p>
            </article>
          </div>
          <div v-else class="empty-state">先创建或选中一个任务。</div>
        </PageSection>

        <PageSection eyebrow="任务记录" title="任务与报告" tag="归档" tone="info">
          <template #toolbar>
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>整批报告下载</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${selectedTaskIds.length} 任务`" :tone="selectedTaskIds.length ? 'info' : 'warn'" />
                  <span>可下载报告 {{ readySelectedTaskCount }} 份</span>
                </div>
              </div>
              <div class="section-toolbar-actions">
                <button class="ghost-button" type="button" @click="selectTasksWithReports">选择有报告</button>
                <button class="ghost-button" :disabled="!selectedTaskIds.length" type="button" @click="clearSelectedTasks">清空</button>
                <button
                  class="primary-button"
                  :disabled="activeAction !== null || !selectedTaskIds.length || !readySelectedTaskCount"
                  type="button"
                  @click="downloadBatchReports"
                >
                  下载整批报告
                </button>
              </div>
            </div>
          </template>

          <div v-if="taskItems.length" class="audit-log-list">
            <article
              v-for="item in taskItems"
              :key="item.id"
              :class="['audit-log-button', { active: item.id === focusedTaskId }]"
            >
              <div class="card-head">
                <label class="selection-toggle" @click.stop>
                  <input
                    class="row-selector"
                    :checked="isTaskSelected(item.id)"
                    type="checkbox"
                    @change="toggleTaskSelection(item.id)"
                  />
                  <span>任务 #{{ item.id }}</span>
                </label>
                <div class="sample-preview-tags">
                  <StatusPill :label="taskStatusLabel(item.status)" :tone="mapTaskTone(item.status)" />
                  <StatusPill v-if="taskBatchLabel(item)" :label="taskBatchLabel(item)" tone="info" />
                </div>
              </div>

              <button class="task-focus-button" type="button" @click="focusTask(item.id)">
                <h4>{{ item.task_name }}</h4>
                <p class="card-subtitle">{{ item.source_ref || item.attack_type }} / {{ item.target_agent }}</p>
                <p class="card-subtitle">执行路由 / {{ taskEndpointLabel(item) }}</p>
                <p v-if="item.result_summary">{{ displayText(item.result_summary) }}</p>
                <div class="sample-list-meta">
                  <span>{{ item.created_at || '-' }}</span>
                  <span v-if="item.latest_event_id">事件 #{{ item.latest_event_id }}</span>
                  <span v-if="item.latest_report_id">报告 #{{ item.latest_report_id }}</span>
                </div>
              </button>
            </article>
          </div>
          <div v-else class="empty-state">还没有样本任务。</div>
        </PageSection>
      </div>
    </section>
  </section>
</template>
