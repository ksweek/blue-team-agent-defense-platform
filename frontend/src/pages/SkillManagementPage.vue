<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import { useRouteSectionFocus } from '../composables/useRouteSectionFocus'
import {
  api,
  type FormFieldMeta,
  type FormFieldTone,
  type SkillActionButton,
  type SkillActionMeta,
  type SkillActionSummaryItem,
  type SkillControlActionDefinition,
  type SkillCreateFieldMeta,
  type SkillDirectoryImportFieldMeta,
  type SkillIntakeMeta,
  type SkillImportPreviewResponse,
  type SkillImportResponse,
  type SkillItem,
  type SkillResultBlock,
  type SkillResultList,
  type SkillResultMeta,
  type SkillResultPanel,
} from '../services/api'
import { redactSensitiveText } from '../services/redaction'
import { formatBeijingTime } from '../services/time'

type Tone = FormFieldTone
type SyncState = 'idle' | 'saving' | 'saved' | 'error'
const SKILL_PAGE_SIZE = 8
const SCAN_TASK_PAGE_SIZE = 6

const FALLBACK_SOURCE_PATH_FIELD_META: FormFieldMeta = {
  control: 'text',
  placeholder: 'backend/data/demo_skills/filesystem-reader 或 /srv/skills/my-skill',
  helper_text: '扫描路径按后端机器文件系统解析，支持绝对路径和相对项目根目录。',
  button_text: '',
  empty_text: '',
  options: [],
}

const FALLBACK_TRUST_FIELD_META: FormFieldMeta = {
  control: 'segmented',
  placeholder: '',
  helper_text: '点击任一信任状态会立即提交到后端，并在技能清单中即时回显。',
  button_text: '',
  empty_text: '',
  options: [
    { label: '可信', value: 'trusted', tone: 'safe' },
    { label: '待审核', value: 'pending', tone: 'warn' },
  ],
}

const FALLBACK_TEXT_FIELD_META: FormFieldMeta = {
  control: 'text',
  placeholder: '',
  helper_text: '',
  button_text: '',
  empty_text: '',
  options: [],
}

const FALLBACK_SELECT_FIELD_META: FormFieldMeta = {
  control: 'select',
  placeholder: '',
  helper_text: '',
  button_text: '',
  empty_text: '',
  options: [],
}

const FALLBACK_SKILL_INTAKE_META: SkillIntakeMeta = {
  create_skill: {
    title: '新增 Skill',
    helper_text: '',
    submit_button_text: '新增',
    field_meta: {
      skill_name: FALLBACK_TEXT_FIELD_META,
      skill_type: FALLBACK_SELECT_FIELD_META,
      provider: FALLBACK_SELECT_FIELD_META,
      source_path: FALLBACK_SOURCE_PATH_FIELD_META,
      trust_status: FALLBACK_TRUST_FIELD_META,
    },
  },
  directory_import: {
    title: '导入 Skill 目录',
    helper_text: '',
    preview_button_text: '预览导入',
    confirm_button_text: '确认入库',
    recursive_enabled_text: '递归导入',
    recursive_disabled_text: '当前仅一层',
    recursive_default: true,
    preview_title: '导入预览',
    preview_empty_text: '当前目录未发现可导入的 skill。',
    field_meta: {
      directory_path: FALLBACK_TEXT_FIELD_META,
      skill_type: FALLBACK_SELECT_FIELD_META,
      provider: FALLBACK_SELECT_FIELD_META,
      trust_status: FALLBACK_TRUST_FIELD_META,
    },
  },
}

const FALLBACK_SKILL_ACTION_META: SkillActionMeta = {
  actions: [
    {
      key: 'scan_selection',
      action_type: 'selection_toolbar',
      title: '扫描选择与即时审批',
      summary_items: [
        {
          key: 'selected',
          template: '{count} 个已选',
          source: 'selected',
          display: 'pill',
          tone: 'info',
          empty_tone: 'safe',
        },
        {
          key: 'pending',
          template: '待审核 {count} 个',
          source: 'pending',
          display: 'text',
          tone: 'info',
        },
      ],
      buttons: [
        { action_key: 'select_pending', label: '选择待审核', tone: 'ghost' },
        { action_key: 'clear_selection', label: '清空选择', tone: 'ghost', requires_selection: true },
        { action_key: 'scan_selected', label: '扫描所选技能', tone: 'primary', requires_selection: true },
      ],
      messages: {
        select_pending_template: '已选中 {count} 个待审核技能。',
        select_pending_empty_text: '当前没有待审核技能。',
        clear_selection_text: '已清空选择',
        missing_selection_text: '先选择需要联动扫描的技能。',
        scan_creating_template: '正在为 {count} 个技能创建扫描任务...',
        scan_completed_template: '已完成 {count} 个技能的联动扫描{event_suffix}{report_suffix}。',
        scan_queued_template: '已创建 {count} 个后台任务，执行结果将自动回显。',
        task_refresh_failed_text: '任务状态刷新失败',
        task_finished_template: '任务 {task_name} 已完成，结果已自动回写。',
        task_failed_template: '任务 {task_name} 执行失败',
        scan_create_failed_text: '技能扫描任务创建失败',
        event_suffix_template: '，事件 #{event_id}',
        report_suffix_template: '，报告 #{report_id}',
      },
      task_status_map: {
        queued: { label: '排队中', tone: 'info' },
        running: { label: '运行中', tone: 'warn' },
        done: { label: '已完成', tone: 'safe' },
        failed: { label: '执行失败', tone: 'danger' },
      },
    },
    {
      key: 'create_skill',
      action_type: 'form',
      model_key: 'create_skill',
      title: '新增 Skill',
      helper_text: '',
      fields: [
        { key: 'skill_name', field_meta: FALLBACK_TEXT_FIELD_META },
        { key: 'skill_type', field_meta: FALLBACK_SELECT_FIELD_META },
        { key: 'provider', field_meta: FALLBACK_SELECT_FIELD_META },
        { key: 'source_path', field_meta: FALLBACK_SOURCE_PATH_FIELD_META },
        { key: 'trust_status', field_meta: FALLBACK_TRUST_FIELD_META },
      ],
      submit_action: { action_key: 'create_skill', label: '新增', tone: 'primary' },
    },
    {
      key: 'directory_import',
      action_type: 'form',
      model_key: 'directory_import',
      title: '导入 Skill 目录',
      helper_text: '',
      fields: [
        { key: 'directory_path', field_meta: FALLBACK_TEXT_FIELD_META },
        { key: 'skill_type', field_meta: FALLBACK_SELECT_FIELD_META },
        { key: 'provider', field_meta: FALLBACK_SELECT_FIELD_META },
        { key: 'trust_status', field_meta: FALLBACK_TRUST_FIELD_META },
      ],
      secondary_actions: [
        {
          action_key: 'toggle_import_recursive',
          label: '递归导入',
          alternate_label: '当前仅一层',
          tone: 'ghost',
          toggle_state_key: 'recursive',
        },
      ],
      submit_action: { action_key: 'preview_import_directory', label: '预览导入', tone: 'primary' },
    },
  ],
}

const FALLBACK_SKILL_RESULT_META: SkillResultMeta = {
  panels: [],
  lists: [
    {
      key: 'skill_scan_tasks',
      panel_type: 'result_list',
      title: '扫描任务',
      empty_text: '当前还没有扫描或联动任务，选择技能后可直接创建。',
      total: 0,
      page: 1,
      page_size: SCAN_TASK_PAGE_SIZE,
      items: [],
    },
  ],
  blocks: [
    {
      key: 'skill_scan_tasks',
      block_type: 'result_list',
      section: {
        id: 'scan-tasks',
        eyebrow: '任务',
        title: '扫描任务',
        tag: '',
        tone: 'warn',
      },
      result_list: {
        key: 'skill_scan_tasks',
        panel_type: 'result_list',
        title: '扫描任务',
        empty_text: '当前还没有扫描或联动任务，选择技能后可直接创建。',
        total: 0,
        page: 1,
        page_size: SCAN_TASK_PAGE_SIZE,
        items: [],
      },
      result_panel: null,
    },
  ],
}

const currentSkillPage = ref(1)
const currentScanTaskPage = ref(1)
const expandedActionKeys = ref<Record<string, boolean>>({})
const { data, loading, error, refresh } = useAsyncData(
  async () => {
    const skills = await api.skills({
      page: currentSkillPage.value,
      page_size: SKILL_PAGE_SIZE,
      scan_task_page: currentScanTaskPage.value,
      scan_task_page_size: SCAN_TASK_PAGE_SIZE,
    })
    return { skills }
  },
  false
)

const activeKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('待操作')
const lastActionAt = ref('')
const selectedSkillIds = ref<number[]>([])
const trackedTaskId = ref<number | null>(null)
const activeSourcePathId = ref<number | null>(null)
const intakeMetaInitialized = ref(false)
const sourcePathDrafts = reactive<Record<number, string>>({})
const createSkillDraft = reactive({
  skill_name: '',
  skill_type: '',
  provider: '',
  source_path: '',
  trust_status: '',
})
const importSkillDraft = reactive({
  directory_path: '',
  skill_type: '',
  provider: '',
  trust_status: '',
  recursive: true,
})
const importPreview = ref<SkillImportPreviewResponse | null>(null)
let taskRefreshTimer: ReturnType<typeof setInterval> | null = null

const skillItems = computed<SkillItem[]>(() => data.value?.skills.items ?? [])
const skillTotal = computed(() => data.value?.skills.total ?? 0)
const skillTotalPages = computed(() => Math.max(1, Math.ceil(skillTotal.value / SKILL_PAGE_SIZE)))
const skillIntakeMeta = computed<SkillIntakeMeta>(
  () => data.value?.skills.intake_meta ?? FALLBACK_SKILL_INTAKE_META
)
const skillActionMeta = computed<SkillActionMeta>(
  () => data.value?.skills.action_meta ?? FALLBACK_SKILL_ACTION_META
)
const skillResultMeta = computed<SkillResultMeta>(
  () => data.value?.skills.result_meta ?? FALLBACK_SKILL_RESULT_META
)
const skillActionDefinitions = computed<SkillControlActionDefinition[]>(
  () => skillActionMeta.value.actions ?? FALLBACK_SKILL_ACTION_META.actions
)
const previewResultBlocks = computed<SkillResultBlock[]>(() => importPreview.value?.result_blocks ?? [])
const previewImportResultPanel = computed<SkillResultPanel | null>(
  () =>
    previewResultBlocks.value.find((item) => item.key === 'directory_import_preview')?.result_panel ??
    importPreview.value?.result_panel ??
    null
)
const backendSkillResultBlocks = computed<SkillResultBlock[]>(
  () => (skillResultMeta.value.blocks?.length ? skillResultMeta.value.blocks : FALLBACK_SKILL_RESULT_META.blocks)
)
const displayedSkillResultBlocks = computed<SkillResultBlock[]>(() =>
  previewResultBlocks.value.length
    ? [...previewResultBlocks.value, ...backendSkillResultBlocks.value]
    : backendSkillResultBlocks.value
)
const scanTaskResultBlock = computed<SkillResultBlock>(
  () =>
    backendSkillResultBlocks.value.find((item) => item.key === 'skill_scan_tasks') ??
    FALLBACK_SKILL_RESULT_META.blocks[0]
)
const scanTaskResultList = computed<SkillResultList>(
  () => scanTaskResultBlock.value.result_list ?? FALLBACK_SKILL_RESULT_META.lists[0]
)
const scanTaskResultItems = computed(() => scanTaskResultList.value.items ?? [])
const scanTaskTotal = computed(() => scanTaskResultList.value.total ?? 0)
const scanTaskTotalPages = computed(() =>
  Math.max(1, Math.ceil(scanTaskTotal.value / Math.max(1, scanTaskResultList.value.page_size || SCAN_TASK_PAGE_SIZE)))
)
const selectionToolbarAction = computed<SkillControlActionDefinition>(
  () =>
    skillActionDefinitions.value.find((item) => item.action_type === 'selection_toolbar') ??
    FALLBACK_SKILL_ACTION_META.actions[0]
)
const formActions = computed<SkillControlActionDefinition[]>(() =>
  skillActionDefinitions.value.filter((item) => item.action_type === 'form')
)
const createSkillMeta = computed(() => skillIntakeMeta.value.create_skill)
const directoryImportMeta = computed(() => skillIntakeMeta.value.directory_import)
const scanSelectionMeta = computed(() => selectionToolbarAction.value)
const pendingSkills = computed(() => skillItems.value.filter((item) => item.trust_status === 'pending'))
const selectedSkills = computed(() =>
  skillItems.value.filter((item) => selectedSkillIds.value.includes(item.id))
)
const activeScanCount = computed(
  () =>
    scanTaskResultItems.value.filter((item) => item.status === 'queued' || item.status === 'running').length
)
const isMutating = computed(() => activeKey.value !== null)

useRouteSectionFocus()

watch(
  [currentSkillPage, currentScanTaskPage],
  () => {
    void refresh()
  },
  { immediate: true }
)

watch(skillTotalPages, (totalPages) => {
  if (currentSkillPage.value > totalPages) {
    currentSkillPage.value = totalPages
  }
})

watch(scanTaskTotalPages, (totalPages) => {
  if (currentScanTaskPage.value > totalPages) {
    currentScanTaskPage.value = totalPages
  }
})

watch(skillItems, (items) => {
  const validIds = new Set(items.map((item) => item.id))
  selectedSkillIds.value = selectedSkillIds.value.filter((item) => validIds.has(item))

  for (const item of items) {
    if (activeSourcePathId.value !== item.id) {
      sourcePathDrafts[item.id] = item.source_path || ''
    }
  }

  for (const key of Object.keys(sourcePathDrafts)) {
    const skillId = Number(key)
    if (!validIds.has(skillId)) {
      delete sourcePathDrafts[skillId]
    }
  }
})

watch(
  () => [
    importSkillDraft.directory_path,
    importSkillDraft.skill_type,
    importSkillDraft.provider,
    importSkillDraft.trust_status,
    importSkillDraft.recursive,
  ],
  () => {
    importPreview.value = null
  }
)

watch(
  skillIntakeMeta,
  (meta) => {
    createSkillDraft.skill_type = normalizeOptionValue(
      createSkillDraft.skill_type,
      meta.create_skill.field_meta.skill_type
    )
    createSkillDraft.provider = normalizeOptionValue(
      createSkillDraft.provider,
      meta.create_skill.field_meta.provider
    )
    createSkillDraft.trust_status = normalizeOptionValue(
      createSkillDraft.trust_status,
      meta.create_skill.field_meta.trust_status
    )

    importSkillDraft.skill_type = normalizeOptionValue(
      importSkillDraft.skill_type,
      meta.directory_import.field_meta.skill_type
    )
    importSkillDraft.provider = normalizeOptionValue(
      importSkillDraft.provider,
      meta.directory_import.field_meta.provider
    )
    importSkillDraft.trust_status = normalizeOptionValue(
      importSkillDraft.trust_status,
      meta.directory_import.field_meta.trust_status
    )

    if (!intakeMetaInitialized.value) {
      importSkillDraft.recursive = Boolean(meta.directory_import.recursive_default)
      intakeMetaInitialized.value = true
    }
  },
  { immediate: true }
)

watch(
  activeScanCount,
  (count) => {
    if (count > 0) {
      if (taskRefreshTimer === null) {
        taskRefreshTimer = setInterval(() => {
          void refreshTaskItems()
        }, 2000)
      }
      return
    }

    if (taskRefreshTimer !== null) {
      clearInterval(taskRefreshTimer)
      taskRefreshTimer = null
    }
  },
  { immediate: true }
)

watch(scanTaskResultItems, (items) => {
  const taskId = trackedTaskId.value
  if (taskId === null) {
    return
  }

  const task = items.find((item) => item.task_id === taskId)
  if (!task) {
    return
  }

  if (task.status === 'done') {
    trackedTaskId.value = null
    finishAction(task.summary_text || scanSelectionMessages().task_finished_template)
    return
  }

  if (task.status === 'failed') {
    trackedTaskId.value = null
    failAction(task.summary_text || scanSelectionMessages().task_failed_template)
  }
})

onBeforeUnmount(() => {
  if (taskRefreshTimer !== null) {
    clearInterval(taskRefreshTimer)
    taskRefreshTimer = null
  }
})

function formatTime(date = new Date()) {
  return formatBeijingTime(date)
}

function trustFieldMeta(skill?: SkillItem | null) {
  return skill?.field_meta?.trust_status ?? FALLBACK_TRUST_FIELD_META
}

function sourcePathFieldMeta(skill?: SkillItem | null) {
  return skill?.field_meta?.source_path ?? FALLBACK_SOURCE_PATH_FIELD_META
}

function createSkillFieldMeta(field: keyof SkillCreateFieldMeta) {
  return createSkillMeta.value.field_meta[field]
}

function directoryImportFieldMeta(field: keyof SkillDirectoryImportFieldMeta) {
  return directoryImportMeta.value.field_meta[field]
}

function findOption(meta: FormFieldMeta, value: string) {
  return meta.options.find((item) => item.value === value)
}

function fieldLabel(meta: FormFieldMeta, value: string) {
  return findOption(meta, value)?.label ?? value
}

function fieldTone(meta: FormFieldMeta, value: string): Tone {
  return findOption(meta, value)?.tone ?? 'info'
}

function formatTemplate(template: string, values: Record<string, string | number | null | undefined>) {
  return template.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = values[key]
    return value === null || value === undefined ? '' : String(value)
  })
}

function defaultOptionValue(meta: FormFieldMeta) {
  return meta.options[0]?.value ?? ''
}

function normalizeOptionValue(value: string, meta: FormFieldMeta) {
  if (!meta.options.length) {
    return value
  }
  return meta.options.some((item) => item.value === value) ? value : defaultOptionValue(meta)
}

function selectedSummaryLabel() {
  const summary = selectionSummaryItem('selected')
  return summary
    ? formatTemplate(summary.template, {
        count: selectedSkillIds.value.length,
      })
    : ''
}

function selectedSummaryTone(): Tone {
  const summary = selectionSummaryItem('selected')
  if (!summary) {
    return selectedSkillIds.value.length ? 'info' : 'safe'
  }
  return selectedSkillIds.value.length ? summary.tone ?? 'info' : summary.empty_tone ?? summary.tone ?? 'safe'
}

function pendingSummaryLabel() {
  const summary = selectionSummaryItem('pending')
  return summary
    ? formatTemplate(summary.template, {
        count: pendingSkills.value.length,
      })
    : ''
}

function isActionExpanded(actionKey: string) {
  return Boolean(expandedActionKeys.value[actionKey])
}

function toggleAction(actionKey: string) {
  expandedActionKeys.value = {
    ...expandedActionKeys.value,
    [actionKey]: !expandedActionKeys.value[actionKey],
  }
}

function actionSummaryText(action: SkillControlActionDefinition) {
  if (action.model_key === 'directory_import') {
    return importSkillDraft.directory_path.trim() || directoryImportMeta.value.helper_text || '填写后端 skill 目录后再展开配置。'
  }
  return createSkillDraft.skill_name.trim() || createSkillMeta.value.helper_text || '填写技能名称和扫描路径后再展开配置。'
}

function taskStatusMeta(status: string) {
  return scanSelectionMeta.value.task_status_map?.[status]
}

function selectionSummaryItem(source: SkillActionSummaryItem['source']) {
  return scanSelectionMeta.value.summary_items?.find((item) => item.source === source)
}

function scanSelectionMessages() {
  return (
    scanSelectionMeta.value.messages ??
    FALLBACK_SKILL_ACTION_META.actions[0].messages ?? {
      select_pending_template: '',
      select_pending_empty_text: '',
      clear_selection_text: '',
      missing_selection_text: '',
      scan_creating_template: '',
      scan_completed_template: '',
      scan_queued_template: '',
      task_refresh_failed_text: '',
      task_finished_template: '',
      task_failed_template: '',
      scan_create_failed_text: '',
      event_suffix_template: '',
      report_suffix_template: '',
    }
  )
}

function resultBlockList(block: SkillResultBlock) {
  return block.result_list ?? null
}

function resultBlockPanel(block: SkillResultBlock) {
  return block.result_panel ?? null
}

function controlButtonClass(button: SkillActionButton) {
  return button.tone === 'primary' ? 'primary-button' : 'ghost-button'
}

function controlButtonLabel(button: SkillActionButton) {
  if (button.toggle_state_key === 'recursive') {
    return importSkillDraft.recursive ? button.label : button.alternate_label ?? button.label
  }
  return button.label
}

function previousSkillPage() {
  if (currentSkillPage.value <= 1) {
    return
  }
  currentSkillPage.value -= 1
}

function nextSkillPage() {
  if (currentSkillPage.value >= skillTotalPages.value) {
    return
  }
  currentSkillPage.value += 1
}

function previousScanTaskPage() {
  if (currentScanTaskPage.value <= 1) {
    return
  }
  currentScanTaskPage.value -= 1
}

function nextScanTaskPage() {
  if (currentScanTaskPage.value >= scanTaskTotalPages.value) {
    return
  }
  currentScanTaskPage.value += 1
}

function isControlButtonDisabled(button: SkillActionButton) {
  if (loading.value || isMutating.value) {
    return true
  }
  if (button.disabled) {
    return true
  }
  if (button.requires_selection && !selectedSkillIds.value.length) {
    return true
  }
  return false
}

function runControlAction(actionKey: string) {
  if (actionKey === 'select_pending') {
    selectPendingSkills()
    return
  }
  if (actionKey === 'clear_selection') {
    clearSelection()
    return
  }
  if (actionKey === 'scan_selected') {
    void scanSelectedSkills()
    return
  }
  if (actionKey === 'create_skill') {
    void createSkill()
    return
  }
  if (actionKey === 'toggle_import_recursive') {
    importSkillDraft.recursive = !importSkillDraft.recursive
    return
  }
  if (actionKey === 'preview_import_directory') {
    void previewSkillDirectoryImport()
    return
  }
  if (actionKey === 'confirm_import_directory') {
    void confirmImportSkillDirectory()
    return
  }
}

function actionFormState(modelKey: SkillControlActionDefinition['model_key']) {
  if (modelKey === 'directory_import') {
    return importSkillDraft as Record<string, string | boolean>
  }
  return createSkillDraft as Record<string, string | boolean>
}

function actionFieldValue(action: SkillControlActionDefinition, fieldKey: string) {
  const form = actionFormState(action.model_key)
  const value = form[fieldKey]
  return typeof value === 'string' ? value : ''
}

function updateActionFieldValue(action: SkillControlActionDefinition, fieldKey: string, value: string) {
  const form = actionFormState(action.model_key)
  form[fieldKey] = value
}

function beginAction(key: string, message = '正在同步技能治理动作...') {
  activeKey.value = key
  syncState.value = 'saving'
  syncMessage.value = redactSensitiveText(message)
}

function finishAction(message: string) {
  activeKey.value = null
  syncState.value = 'saved'
  syncMessage.value = redactSensitiveText(message)
  lastActionAt.value = formatTime()
}

function failAction(message: string) {
  activeKey.value = null
  syncState.value = 'error'
  syncMessage.value = redactSensitiveText(message)
}

function displayText(value?: string | null) {
  return redactSensitiveText(value)
}

function replaceSkillItem(updated: SkillItem) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    skills: {
      ...data.value.skills,
      items: data.value.skills.items.map((item) => (item.id === updated.id ? updated : item)),
    },
  }
}

function upsertSkillItems(items: SkillItem[]) {
  if (!data.value || !items.length) {
    return
  }

  const existingById = new Map(data.value.skills.items.map((item) => [item.id, item]))
  for (const item of items) {
    existingById.set(item.id, item)
  }

  data.value = {
    ...data.value,
    skills: {
      ...data.value.skills,
      total: Math.max(data.value.skills.total, existingById.size),
      items: Array.from(existingById.values()).sort((left, right) => right.id - left.id),
    },
  }
}

async function refreshTaskItems() {
  if (!data.value) {
    await refresh()
    return
  }

  try {
    const skills = await api.skills({
      page: currentSkillPage.value,
      page_size: SKILL_PAGE_SIZE,
      scan_task_page: currentScanTaskPage.value,
      scan_task_page_size: SCAN_TASK_PAGE_SIZE,
    })
    data.value = {
      ...data.value,
      skills,
    }
  } catch (err) {
    failAction(err instanceof Error ? err.message : scanSelectionMessages().task_refresh_failed_text)
  }
}

function providerTone(provider: string): Tone {
  if (provider === 'official') return 'safe'
  if (provider === 'third-party') return 'warn'
  return 'info'
}

function providerLabel(provider: string) {
  if (provider === 'official') return '官方'
  if (provider === 'third-party') return '第三方'
  return provider
}

function sourcePathStateLabel(skill: SkillItem) {
  if (skill.source_path_state === 'ready') return '就绪'
  if (skill.source_path_state === 'missing') return '缺失'
  return '未配置'
}

function sourcePathStateTone(skill: SkillItem): Tone {
  if (skill.source_path_state === 'ready') return 'safe'
  if (skill.source_path_state === 'missing') return 'danger'
  return 'info'
}

function sourcePathPreview(skill: SkillItem) {
  if (skill.resolved_source_path) {
    return displayText(skill.resolved_source_path)
  }
  if (skill.source_path_state === 'missing') {
    return '后端机器未找到该路径'
  }
  return '填写后端机器上的真实 skill 目录'
}

function sourcePathDraft(skill: SkillItem) {
  return sourcePathDrafts[skill.id] ?? skill.source_path ?? ''
}

function resetSourcePathDraft(skill: SkillItem) {
  sourcePathDrafts[skill.id] = skill.source_path || ''
  activeSourcePathId.value = null
}

function isSelected(skillId: number) {
  return selectedSkillIds.value.includes(skillId)
}

function toggleSkillSelection(skillId: number) {
  if (isSelected(skillId)) {
    selectedSkillIds.value = selectedSkillIds.value.filter((item) => item !== skillId)
    return
  }

  selectedSkillIds.value = [...selectedSkillIds.value, skillId]
}

function selectPendingSkills() {
  selectedSkillIds.value = pendingSkills.value.map((item) => item.id)
  syncState.value = 'idle'
  syncMessage.value = pendingSkills.value.length
    ? formatTemplate(scanSelectionMessages().select_pending_template, {
        count: pendingSkills.value.length,
      })
    : scanSelectionMessages().select_pending_empty_text
}

function clearSelection() {
  selectedSkillIds.value = []
  syncState.value = 'idle'
  syncMessage.value = scanSelectionMessages().clear_selection_text
}

function resetCreateSkillDraft() {
  createSkillDraft.skill_name = ''
  createSkillDraft.skill_type = defaultOptionValue(createSkillFieldMeta('skill_type'))
  createSkillDraft.provider = defaultOptionValue(createSkillFieldMeta('provider'))
  createSkillDraft.source_path = ''
  createSkillDraft.trust_status = defaultOptionValue(createSkillFieldMeta('trust_status'))
}

function resetImportSkillDraft() {
  importSkillDraft.directory_path = ''
  importSkillDraft.skill_type = defaultOptionValue(directoryImportFieldMeta('skill_type'))
  importSkillDraft.provider = defaultOptionValue(directoryImportFieldMeta('provider'))
  importSkillDraft.trust_status = defaultOptionValue(directoryImportFieldMeta('trust_status'))
  importSkillDraft.recursive = Boolean(directoryImportMeta.value.recursive_default)
}

function buildImportPayload() {
  return {
    directory_path: importSkillDraft.directory_path.trim(),
    skill_type: importSkillDraft.skill_type,
    provider: importSkillDraft.provider,
    trust_status: importSkillDraft.trust_status,
    recursive: importSkillDraft.recursive,
  }
}

function importResultPanelConfirmAction() {
  return previewImportResultPanel.value?.actions.find((item) => item.action_key === 'confirm_import_directory') ?? null
}

function canConfirmImport() {
  const action = importResultPanelConfirmAction()
  if (action) {
    return !action.disabled
  }
  return Boolean(importPreview.value && importPreview.value.created + importPreview.value.updated > 0)
}

async function updateTrustStatus(skill: SkillItem, trustStatus: string) {
  const meta = trustFieldMeta(skill)
  const nextLabel = fieldLabel(meta, trustStatus)

  if (skill.trust_status === trustStatus) {
    syncState.value = 'idle'
    syncMessage.value = `${skill.skill_name} 当前已经是${nextLabel}状态。`
    return
  }

  beginAction(`trust-${skill.id}`, `正在提交 ${skill.skill_name} 的信任状态...`)

  try {
    const updated = await api.updateSkillTrustStatus(skill.id, trustStatus)
    replaceSkillItem(updated)
    finishAction(`${updated.skill_name} 已自动更新为${fieldLabel(trustFieldMeta(updated), updated.trust_status)}。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '技能信任状态更新失败')
    await refresh()
  }
}

async function updateSourcePath(skill: SkillItem) {
  const nextPath = sourcePathDraft(skill).trim()
  const currentPath = (skill.source_path || '').trim()
  activeSourcePathId.value = null

  if (nextPath === currentPath) {
    sourcePathDrafts[skill.id] = skill.source_path || ''
    return
  }

  beginAction(`source-path-${skill.id}`, `正在同步 ${skill.skill_name} 的扫描路径...`)

  try {
    const updated = await api.updateSkillSourcePath(skill.id, nextPath)
    replaceSkillItem(updated)
    sourcePathDrafts[skill.id] = updated.source_path || ''
    finishAction(`${updated.skill_name} 的扫描路径已自动更新。`)
  } catch (err) {
    sourcePathDrafts[skill.id] = skill.source_path || ''
    failAction(err instanceof Error ? err.message : '技能扫描路径更新失败')
    await refresh()
  }
}

async function createSkill() {
  if (!createSkillDraft.skill_name.trim() || !createSkillDraft.source_path.trim()) {
    syncState.value = 'idle'
    syncMessage.value = '先填写技能名称和扫描路径。'
    return
  }

  beginAction('skill-create', `正在新增 ${createSkillDraft.skill_name.trim()}...`)

  try {
    const created = await api.createSkill({
      skill_name: createSkillDraft.skill_name.trim(),
      skill_type: createSkillDraft.skill_type,
      provider: createSkillDraft.provider,
      source_path: createSkillDraft.source_path.trim(),
      trust_status: createSkillDraft.trust_status,
    })
    currentSkillPage.value = 1
    await refresh()
    selectedSkillIds.value = [created.id]
    resetCreateSkillDraft()
    finishAction(`${created.skill_name} 已纳管，可直接发起扫描。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '新增技能失败')
  }
}

async function importSkillDirectory() {
  if (!importSkillDraft.directory_path.trim()) {
    syncState.value = 'idle'
    syncMessage.value = '先填写后端机器上的技能目录。'
    return
  }

  beginAction('skill-import', `正在导入目录 ${importSkillDraft.directory_path.trim()}...`)

  try {
    const result = await api.importSkillDirectory({
      directory_path: importSkillDraft.directory_path.trim(),
      skill_type: importSkillDraft.skill_type,
      provider: importSkillDraft.provider,
      trust_status: importSkillDraft.trust_status,
      recursive: importSkillDraft.recursive,
    })
    applyImportedSkills(result)
    resetImportSkillDraft()
    finishAction(`导入完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '导入技能目录失败')
  }
}

async function previewSkillDirectoryImport() {
  const payload = buildImportPayload()
  if (!payload.directory_path) {
    syncState.value = 'idle'
    syncMessage.value = '先填写后端机器上的 skill 目录'
    return
  }

  beginAction('skill-import-preview', `正在预览目录 ${payload.directory_path}...`)

  try {
    const result = await api.previewSkillDirectoryImport(payload)
    importPreview.value = result
    finishAction(`预览完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}`)
  } catch (err) {
    importPreview.value = null
    failAction(err instanceof Error ? err.message : '目录预览失败')
  }
}

async function confirmImportSkillDirectory() {
  if (!importPreview.value) {
    await previewSkillDirectoryImport()
    return
  }

  if (!canConfirmImport()) {
    syncState.value = 'idle'
    syncMessage.value = '当前预览没有可导入的 skill'
    return
  }

  const payload = buildImportPayload()
  if (!payload.directory_path) {
    syncState.value = 'idle'
    syncMessage.value = '先填写后端机器上的 skill 目录'
    return
  }

  beginAction('skill-import', `正在导入目录 ${payload.directory_path}...`)

  try {
    const result = await api.importSkillDirectory(payload)
    await applyImportedSkills(result)
    importPreview.value = null
    resetImportSkillDraft()
    finishAction(`导入完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '导入技能目录失败')
  }
}

async function applyImportedSkills(result: SkillImportResponse) {
  currentSkillPage.value = 1
  await refresh()
  selectedSkillIds.value = result.items.map((item) => item.id)
}

async function scanSelectedSkills() {
  if (!selectedSkillIds.value.length) {
    syncState.value = 'idle'
    syncMessage.value = scanSelectionMessages().missing_selection_text
    return
  }

  const selectedCount = selectedSkillIds.value.length
  currentScanTaskPage.value = 1
  beginAction(
    'scan',
    formatTemplate(scanSelectionMessages().scan_creating_template, {
      count: selectedCount,
    })
  )

  try {
    const task = await api.scanSkills(selectedSkillIds.value)
    await refreshTaskItems()
    const execution = await api.runAttackTask(task.id)
    await refreshTaskItems()
    selectedSkillIds.value = []

    if (execution.task.status === 'done') {
      const eventSuffix = execution.event
        ? formatTemplate(scanSelectionMessages().event_suffix_template, {
            event_id: execution.event.id,
          })
        : ''
      const reportSuffix = execution.report
        ? formatTemplate(scanSelectionMessages().report_suffix_template, {
            report_id: execution.report.id,
          })
        : ''
      finishAction(
        formatTemplate(scanSelectionMessages().scan_completed_template, {
          count: selectedCount,
          event_suffix: eventSuffix,
          report_suffix: reportSuffix,
        })
      )
      return
    }

    activeKey.value = null
    syncState.value = 'idle'
    syncMessage.value = formatTemplate(scanSelectionMessages().scan_queued_template, {
      count: selectedCount,
    })
    lastActionAt.value = formatTime()
    trackedTaskId.value = execution.task.id
  } catch (err) {
    failAction(err instanceof Error ? err.message : scanSelectionMessages().scan_create_failed_text)
  }
}
</script>

<template>
  <section class="page-grid">
    <section class="content-grid two-column skill-workbench-grid">
      <PageSection eyebrow="技能" title="技能信任治理" tag="审批" tone="safe">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ selectionToolbarAction.title }}</h4>
              <div class="section-toolbar-meta">
                <template v-for="summary in selectionToolbarAction.summary_items" :key="summary.key">
                  <StatusPill
                    v-if="summary.display === 'pill' && summary.source === 'selected'"
                    :label="selectedSummaryLabel()"
                    :tone="selectedSummaryTone()"
                  />
                  <StatusPill
                    v-else-if="summary.display === 'pill' && summary.source === 'pending'"
                    :label="pendingSummaryLabel()"
                    :tone="summary.tone ?? 'info'"
                  />
                  <span v-else-if="summary.source === 'selected'">{{ selectedSummaryLabel() }}</span>
                  <span v-else>{{ pendingSummaryLabel() }}</span>
                </template>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <button
                v-for="button in selectionToolbarAction.buttons"
                :key="button.action_key"
                :class="controlButtonClass(button)"
                :disabled="isControlButtonDisabled(button)"
                type="button"
                @click="runControlAction(button.action_key)"
              >
                {{ controlButtonLabel(button) }}
              </button>
            </div>
          </div>
        </template>

        <div v-if="loading" class="empty-state">正在加载技能列表...</div>
        <div v-else-if="error" class="empty-state">
          <p>加载失败：{{ error }}</p>
          <button class="ghost-button" type="button" @click="refresh">重试</button>
        </div>
        <template v-else>
          <div class="settings-stack settings-stack-compact skill-action-stack">
            <article
              v-for="action in formActions"
              :key="action.key"
              class="security-disclosure-card skill-action-disclosure"
            >
              <button class="security-disclosure-toggle" type="button" @click="toggleAction(action.key)">
                <div class="security-disclosure-copy">
                  <strong>{{ action.title }}</strong>
                  <p>{{ actionSummaryText(action) }}</p>
                </div>
                <div class="security-disclosure-meta">
                  <span class="security-disclosure-action">{{ isActionExpanded(action.key) ? '收起' : '展开' }}</span>
                </div>
              </button>
              <div v-if="isActionExpanded(action.key)" class="security-disclosure-body skill-action-disclosure-body">
                <p v-if="action.helper_text" class="settings-form-helper">{{ action.helper_text }}</p>
                <div class="skill-intake-grid">
                  <template v-for="field in action.fields" :key="`${action.key}:${field.key}`">
                    <input
                      v-if="field.field_meta.control === 'text'"
                      :value="actionFieldValue(action, field.key)"
                      :class="['text-input', { 'skill-intake-path': field.key.includes('path') }]"
                      :disabled="loading || isMutating"
                      :placeholder="field.field_meta.placeholder"
                      type="text"
                      @input="updateActionFieldValue(action, field.key, ($event.target as HTMLInputElement).value)"
                      @keydown.enter.prevent="runControlAction(action.submit_action?.action_key || '')"
                    />
                    <select
                      v-else
                      :value="actionFieldValue(action, field.key)"
                      class="select-input"
                      :disabled="loading || isMutating"
                      @change="updateActionFieldValue(action, field.key, ($event.target as HTMLSelectElement).value)"
                    >
                      <option
                        v-for="option in field.field_meta.options"
                        :key="option.value"
                        :value="option.value"
                      >
                        {{ option.label }}
                      </option>
                    </select>
                  </template>
                  <button
                    v-for="button in action.secondary_actions"
                    :key="button.action_key"
                    :class="controlButtonClass(button)"
                    :disabled="isControlButtonDisabled(button)"
                    type="button"
                    @click="runControlAction(button.action_key)"
                  >
                    {{ controlButtonLabel(button) }}
                  </button>
                  <button
                    v-if="action.submit_action"
                    :class="[controlButtonClass(action.submit_action), { 'skill-intake-preview-button': action.submit_action.action_key === 'preview_import_directory' }]"
                    :disabled="isControlButtonDisabled(action.submit_action)"
                    type="button"
                    @click="runControlAction(action.submit_action.action_key)"
                  >
                    {{ controlButtonLabel(action.submit_action) }}
                  </button>
                </div>
              </div>
            </article>

          </div>

          <div v-if="selectedSkills.length" class="token-list">
            <span
              v-for="item in selectedSkills"
              :key="item.id"
              class="token-chip"
            >
              <span>{{ item.skill_name }}</span>
              <button
                class="token-chip-remove"
                :disabled="isMutating"
                type="button"
                @click="toggleSkillSelection(item.id)"
              >
                x
              </button>
            </span>
          </div>

          <p class="section-toolbar-note">扫描路径按运行后端的机器解析，支持绝对路径和相对项目根目录。</p>

          <div class="table-shell skill-table-shell">
            <table>
              <thead>
                <tr>
                  <th>联动</th>
                  <th>技能名称</th>
                  <th>类型</th>
                  <th>来源</th>
                  <th>扫描路径</th>
                  <th>信任状态</th>
                  <th>创建时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="item in skillItems"
                  :key="item.id"
                  :class="{ 'table-row-selected': isSelected(item.id) }"
                  @click="toggleSkillSelection(item.id)"
                >
                  <td>
                    <input
                      class="row-selector"
                      :checked="isSelected(item.id)"
                      type="checkbox"
                      @click.stop
                      @change="toggleSkillSelection(item.id)"
                    />
                  </td>
                  <td>{{ item.skill_name }}</td>
                  <td>{{ item.skill_type }}</td>
                  <td>
                    <StatusPill :label="providerLabel(item.provider)" :tone="providerTone(item.provider)" />
                  </td>
                  <td>
                    <div class="skill-path-cell" @click.stop>
                      <input
                        v-model="sourcePathDrafts[item.id]"
                        class="text-input table-inline-input"
                        :disabled="isMutating"
                        :placeholder="sourcePathFieldMeta(item).placeholder"
                        type="text"
                        @focus="activeSourcePathId = item.id"
                        @blur="updateSourcePath(item)"
                        @keydown.enter.prevent="updateSourcePath(item)"
                        @keydown.esc.prevent="resetSourcePathDraft(item)"
                      />
                      <div class="skill-path-meta">
                        <StatusPill :label="sourcePathStateLabel(item)" :tone="sourcePathStateTone(item)" />
                        <span class="code-inline">{{ sourcePathPreview(item) }}</span>
                      </div>
                    </div>
                  </td>
                  <td>
                    <StatusPill
                      :label="fieldLabel(trustFieldMeta(item), item.trust_status)"
                      :tone="fieldTone(trustFieldMeta(item), item.trust_status)"
                    />
                  </td>
                  <td>{{ item.created_at }}</td>
                  <td>
                    <div class="table-actions">
                      <button
                        v-for="option in trustFieldMeta(item).options"
                        :key="option.value"
                        class="ghost-button small"
                        :disabled="isMutating || item.trust_status === option.value"
                        type="button"
                        @click.stop="updateTrustStatus(item, option.value)"
                      >
                        {{ option.label }}
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="skillTotal > SKILL_PAGE_SIZE" class="sample-pagination skill-pagination">
            <button class="ghost-button" :disabled="currentSkillPage <= 1" type="button" @click="previousSkillPage">
              上一页
            </button>
            <button class="ghost-button" :disabled="currentSkillPage >= skillTotalPages" type="button" @click="nextSkillPage">
              下一页
            </button>
          </div>
        </template>
      </PageSection>

      <section class="skill-result-column">
        <PageSection
          v-for="block in displayedSkillResultBlocks"
          :id="block.section.id || undefined"
          :key="block.key"
          class="skill-result-section"
          :eyebrow="block.section.eyebrow"
          :title="block.section.title"
          :tag="block.section.tag || undefined"
          :tone="block.section.tone"
          :collapsible="true"
          :default-collapsed="true"
        >
        <div v-if="loading" class="empty-state">正在加载结果区...</div>
        <div v-else-if="error" class="empty-state">
          <p>结果区加载失败：{{ error }}</p>
          <button class="ghost-button" type="button" @click="refresh">重试</button>
        </div>
        <div
          v-else-if="block.block_type === 'result_list' && resultBlockList(block)?.items.length"
          class="control-result-list"
        >
          <article
            v-for="item in resultBlockList(block)?.items"
            :key="item.key"
            class="control-result-list-row"
          >
            <div class="control-result-list-main">
              <div class="control-result-list-headline">
                <strong>{{ item.title }}</strong>
                <div class="control-result-list-badges">
                  <StatusPill
                    v-for="badge in item.badges"
                    :key="`${item.key}:${badge.key}`"
                    :label="badge.text"
                    :tone="badge.tone"
                  />
                </div>
              </div>
              <p v-if="item.subtitle" class="code-inline">{{ displayText(item.subtitle) }}</p>
              <p v-if="item.summary_text" class="control-result-list-summary">
                {{ displayText(item.summary_text) }}
              </p>
              <div class="control-result-list-meta">
                <span v-if="item.meta_text">{{ displayText(item.meta_text) }}</span>
                <StatusPill
                  v-for="badge in item.meta_badges"
                  :key="`${item.key}:meta:${badge.key}`"
                  :label="badge.text"
                  :tone="badge.tone"
                />
              </div>
            </div>
          </article>
          <div
            v-if="block.key === 'skill_scan_tasks' && scanTaskTotal > scanTaskResultList.page_size"
            class="sample-pagination skill-pagination"
          >
            <button class="ghost-button" :disabled="currentScanTaskPage <= 1" type="button" @click="previousScanTaskPage">
              上一页
            </button>
            <button
              class="ghost-button"
              :disabled="currentScanTaskPage >= scanTaskTotalPages"
              type="button"
              @click="nextScanTaskPage"
            >
              下一页
            </button>
          </div>
        </div>
        <article
          v-else-if="block.block_type === 'result_panel' && resultBlockPanel(block)"
          class="control-result-panel"
        >
          <div class="control-result-panel-head">
            <div class="control-result-panel-copy">
              <h4>{{ resultBlockPanel(block)?.title }}</h4>
              <p class="control-result-panel-summary">{{ displayText(resultBlockPanel(block)?.summary_text) }}</p>
              <p v-if="resultBlockPanel(block)?.detail_text" class="code-inline">
                {{ displayText(resultBlockPanel(block)?.detail_text) }}
              </p>
            </div>
            <div class="control-result-panel-actions">
              <StatusPill
                v-for="summary in resultBlockPanel(block)?.summary_items"
                :key="summary.key"
                :label="summary.text"
                :tone="summary.tone"
              />
              <button
                v-for="button in resultBlockPanel(block)?.actions"
                :key="button.action_key"
                :class="[controlButtonClass(button), 'small']"
                :disabled="isControlButtonDisabled(button)"
                type="button"
                @click="runControlAction(button.action_key)"
              >
                {{ controlButtonLabel(button) }}
              </button>
            </div>
          </div>
          <div v-if="resultBlockPanel(block)?.items.length" class="control-result-panel-list">
            <div
              v-for="item in resultBlockPanel(block)?.items"
              :key="item.key"
              class="control-result-panel-row"
            >
              <div class="control-result-panel-main">
                <strong>{{ item.title }}</strong>
                <span v-if="item.subtitle" class="code-inline">{{ displayText(item.subtitle) }}</span>
              </div>
              <div class="control-result-panel-meta">
                <StatusPill
                  v-for="badge in item.badges"
                  :key="`${item.key}:${badge.key}`"
                  :label="badge.text"
                  :tone="badge.tone"
                />
              </div>
            </div>
          </div>
          <div v-else class="empty-state">{{ resultBlockPanel(block)?.empty_text }}</div>
        </article>
        <div
          v-else-if="block.block_type === 'result_list' && resultBlockList(block)"
          class="empty-state"
        >
          {{ resultBlockList(block)?.empty_text }}
        </div>
        <div
          v-else-if="block.block_type === 'result_panel' && resultBlockPanel(block)"
          class="empty-state"
        >
          {{ resultBlockPanel(block)?.empty_text }}
        </div>
        <div v-else class="empty-state">当前结果块暂无可展示内容。</div>
        </PageSection>
      </section>
    </section>
  </section>
</template>
