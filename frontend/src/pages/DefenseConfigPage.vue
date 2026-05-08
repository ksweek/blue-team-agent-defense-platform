<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import { useRouteSectionFocus } from '../composables/useRouteSectionFocus'
import {
  api,
  type AiReviewPolicy,
  type AiReviewMode,
  type DefenseConfigItem,
  type DefensePolicyProfile,
  type DefensePolicyRule,
  type DefenseResourceGroup,
  type FormFieldMeta,
  type FormFieldTone,
} from '../services/api'
import { formatBeijingTime } from '../services/time'

type Mode = 'enforce' | 'observe' | 'off'
type ReviewMode = AiReviewMode
type Tone = FormFieldTone
type SyncState = 'idle' | 'saving' | 'saved' | 'error'
type ResourceKind = 'path' | 'skill' | 'plugin'
type ExecutionScope = 'all' | 'remote' | 'local'
type ResourceFilterKind = 'all' | ResourceKind

const FALLBACK_ENABLED_FIELD_META: FormFieldMeta = {
  control: 'toggle',
  placeholder: '',
  helper_text: '开关切换后会立即提交到后端，不再存在额外保存步骤。',
  button_text: '',
  empty_text: '',
  options: [
    { label: '启用', value: 'true', tone: 'safe' },
    { label: '停用', value: 'false', tone: 'info' },
  ],
}

const FALLBACK_MODE_FIELD_META: FormFieldMeta = {
  control: 'segmented',
  placeholder: '',
  helper_text: '模式切换后会立即生效，颜色语义同样由后端下发。',
  button_text: '',
  empty_text: '',
  options: [
    { label: '关闭', value: 'off', tone: 'info' },
    { label: '观察', value: 'observe', tone: 'warn' },
    { label: '执行', value: 'enforce', tone: 'safe' },
  ],
}

const FALLBACK_RESOURCE_GROUPS: DefenseResourceGroup[] = [
  {
    kind: 'path',
    title: '受保护路径',
    description: '需要重点保护的绝对路径、工作区目录或关键配置位置。',
    field_meta: {
      control: 'token-input',
      placeholder: '/srv/app/secrets',
      helper_text: '输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。',
      button_text: '添加',
      empty_text: '当前还没有纳管项，添加后会立即生效。',
      options: [],
    },
  },
  {
    kind: 'skill',
    title: '受保护技能',
    description: '需要额外授权或审计的技能 ID、能力名或策略别名。',
    field_meta: {
      control: 'token-input',
      placeholder: 'release-guard',
      helper_text: '输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。',
      button_text: '添加',
      empty_text: '当前还没有纳管项，添加后会立即生效。',
      options: [],
    },
  },
  {
    kind: 'plugin',
    title: '受保护插件',
    description: '需要强约束的插件、MCP server capability 或扩展能力标识。',
    field_meta: {
      control: 'token-input',
      placeholder: 'audit-guard',
      helper_text: '输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。',
      button_text: '添加',
      empty_text: '当前还没有纳管项，添加后会立即生效。',
      options: [],
    },
  },
]

const FALLBACK_ADVANCED_RULE: DefensePolicyRule = {
  key: 'tool-call-audit',
  title: '强制 Tool Call 审计',
  description: '在工具调用真正执行前保留审计、校验和留痕，避免绕过审批链路。',
  enabled: true,
  mode: 'observe',
  field_meta: {
    enabled: FALLBACK_ENABLED_FIELD_META,
    mode: FALLBACK_MODE_FIELD_META,
  },
}

const FALLBACK_AI_REVIEW_POLICY: AiReviewPolicy = {
  key: 'protected-agent-ai-review',
  title: 'AI 复核策略',
  description: '明确攻击由规则直接阻断，其余流量按模式决定是否进入 AI 复核。',
  mode: 'suspicious_review',
  field_meta: {
    control: 'segmented',
    placeholder: '',
    helper_text: '仅对已开启保护的 AI/Agent 生效。',
    button_text: '',
    empty_text: '',
    options: [
      { label: '规则直断', value: 'rules_only', tone: 'info' },
      { label: '疑似复核', value: 'suspicious_review', tone: 'warn' },
      { label: '剩余全审', value: 'review_all_remaining', tone: 'safe' },
    ],
  },
}

const { data, loading, error, refresh } = useAsyncData(async () => {
  const [defenses, profile] = await Promise.all([api.defenseConfigs(), api.defensePolicy()])
  return { defenses, profile }
})

const activeKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('待操作')
const lastSavedAt = ref('')
const expandedCoverage = ref<Record<number, boolean>>({})
const executionOverviewExpanded = ref(false)

const guardRules = ref<DefensePolicyRule[]>([])
const scanRules = ref<DefensePolicyRule[]>([])
const advancedRule = ref<DefensePolicyRule>({ ...FALLBACK_ADVANCED_RULE })
const aiReviewPolicy = ref<AiReviewPolicy>({ ...FALLBACK_AI_REVIEW_POLICY })
const resourceGroups = ref<DefenseResourceGroup[]>(FALLBACK_RESOURCE_GROUPS)
const protectedPaths = ref<string[]>([])
const protectedSkills = ref<string[]>([])
const protectedPlugins = ref<string[]>([])
const drafts = reactive<Record<ResourceKind, string>>({
  path: '',
  skill: '',
  plugin: '',
})
const executionScope = ref<ExecutionScope>('all')
const activeResourceKind = ref<ResourceFilterKind>('all')

const executionScopeOptions = [
  { label: '\u5168\u90e8', value: 'all' },
  { label: '\u8fdc\u7a0b', value: 'remote' },
  { label: '\u672c\u5730', value: 'local' },
] as const

const resourceKindOptions = [
  { label: '\u5168\u90e8', value: 'all' },
  { label: '\u8def\u5f84', value: 'path' },
  { label: '\u6280\u80fd', value: 'skill' },
  { label: '\u63d2\u4ef6', value: 'plugin' },
] as const

const items = computed<DefenseConfigItem[]>(() => data.value?.defenses.items ?? [])
const isMutating = computed(() => activeKey.value !== null)

useRouteSectionFocus((focus, route) => {
  if (focus !== 'protected-resources') {
    return
  }

  const kind = route.query.kind
  activeResourceKind.value =
    kind === 'path' || kind === 'skill' || kind === 'plugin' ? kind : 'all'
})

function normalizeMode(mode: string): Mode {
  if (mode === 'enforce' || mode === 'off') {
    return mode
  }
  return 'observe'
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

function defenseDisplayLabel(item?: { display_label?: string; defense_name?: string } | null) {
  return item?.display_label || item?.defense_name || '未命名防线'
}

function ruleDisplayLabel(item?: { display_label?: string; title?: string } | null) {
  return item?.display_label || item?.title || '未命名规则'
}

function ruleDescription(item?: { display_description?: string; description?: string } | null) {
  return item?.display_description || item?.description || ''
}

function modeFieldMeta(item?: { field_meta?: { mode: FormFieldMeta } } | null) {
  return item?.field_meta?.mode ?? FALLBACK_MODE_FIELD_META
}

function enabledFieldMeta(item?: { field_meta?: { enabled: FormFieldMeta } } | null) {
  return item?.field_meta?.enabled ?? FALLBACK_ENABLED_FIELD_META
}

function aiReviewFieldMeta(item?: AiReviewPolicy | null) {
  return item?.field_meta ?? FALLBACK_AI_REVIEW_POLICY.field_meta
}

const globalModeFieldMeta = computed(
  () =>
    data.value?.profile.global_field_meta.mode ??
    items.value[0]?.field_meta.mode ??
    guardRules.value[0]?.field_meta.mode ??
    advancedRule.value.field_meta.mode ??
    FALLBACK_MODE_FIELD_META
)

function formatTime(date = new Date()) {
  return formatBeijingTime(date)
}

function applyProfile(profile: DefensePolicyProfile) {
  guardRules.value = profile.guard_rules
  scanRules.value = profile.scan_rules
  advancedRule.value = profile.advanced_rule
  aiReviewPolicy.value = profile.ai_review_policy ?? FALLBACK_AI_REVIEW_POLICY
  resourceGroups.value = profile.resource_groups.length ? profile.resource_groups : FALLBACK_RESOURCE_GROUPS
  protectedPaths.value = [...profile.protected_paths]
  protectedSkills.value = [...profile.protected_skills]
  protectedPlugins.value = [...profile.protected_plugins]
}

function buildPolicyPayload() {
  return {
    guard_rules: guardRules.value.map((item) => ({
      key: item.key,
      title: item.title,
      description: item.description,
      enabled: item.enabled,
      mode: normalizeMode(item.mode),
    })),
    scan_rules: scanRules.value.map((item) => ({
      key: item.key,
      title: item.title,
      description: item.description,
      enabled: item.enabled,
      mode: normalizeMode(item.mode),
    })),
    advanced_rule: {
      key: advancedRule.value.key,
      title: advancedRule.value.title,
      description: advancedRule.value.description,
      enabled: advancedRule.value.enabled,
      mode: normalizeMode(advancedRule.value.mode),
    },
    ai_review_policy: {
      key: aiReviewPolicy.value.key,
      title: aiReviewPolicy.value.title,
      description: aiReviewPolicy.value.description,
      mode: aiReviewPolicy.value.mode,
    },
    protected_paths: [...protectedPaths.value],
    protected_skills: [...protectedSkills.value],
    protected_plugins: [...protectedPlugins.value],
  }
}

function updateLocalDataProfile(profile: DefensePolicyProfile) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    profile,
  }
}

function replaceRemoteDefenseItem(updatedItem: DefenseConfigItem) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    defenses: {
      ...data.value.defenses,
      items: data.value.defenses.items.map((item) => (item.id === updatedItem.id ? updatedItem : item)),
    },
  }
}

function replaceAllRemoteDefenseItems(updatedItems: DefenseConfigItem[]) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    defenses: {
      ...data.value.defenses,
      items: updatedItems,
      total: updatedItems.length,
    },
  }
}

function beginSync(key: string, message = '正在自动保存变更...') {
  activeKey.value = key
  syncState.value = 'saving'
  syncMessage.value = message
}

function finishSync(message: string) {
  syncState.value = 'saved'
  syncMessage.value = message
  lastSavedAt.value = formatTime()
  activeKey.value = null
}

function failSync(message: string) {
  syncState.value = 'error'
  syncMessage.value = message
  activeKey.value = null
}

watch(
  () => data.value,
  (payload) => {
    if (!payload) {
      return
    }
    applyProfile(payload.profile)
  },
  { immediate: true }
)

const primaryEnabled = computed(
  () =>
    items.value.every((item) => item.enabled) &&
    guardRules.value.every((item) => item.enabled) &&
    scanRules.value.every((item) => item.enabled) &&
    advancedRule.value.enabled
)

const primaryMode = computed<Mode>(() => {
  const modes = [
    ...items.value.map((item) => normalizeMode(item.mode)),
    ...guardRules.value.map((item) => normalizeMode(item.mode)),
    ...scanRules.value.map((item) => normalizeMode(item.mode)),
    normalizeMode(advancedRule.value.mode),
  ]

  if (modes.length > 0 && modes.every((mode) => mode === 'enforce')) {
    return 'enforce'
  }

  if (modes.length > 0 && modes.every((mode) => mode === 'off')) {
    return 'off'
  }

  return 'observe'
})

const activeCount = computed(
  () =>
    items.value.filter((item) => item.enabled).length +
    guardRules.value.filter((item) => item.enabled).length +
    scanRules.value.filter((item) => item.enabled).length +
    Number(advancedRule.value.enabled)
)

const totalProtectedCount = computed(
  () => protectedPaths.value.length + protectedSkills.value.length + protectedPlugins.value.length
)

const remoteEnabledCount = computed(() => items.value.filter((item) => item.enabled).length)
const guardEnabledCount = computed(() => guardRules.value.filter((item) => item.enabled).length)
const scanEnabledCount = computed(() => scanRules.value.filter((item) => item.enabled).length)
const executionGuardCount = computed(() => items.value.length + guardRules.value.length)
const executionGuardEnabledCount = computed(() => remoteEnabledCount.value + guardEnabledCount.value)

const filteredResourceGroups = computed(() => {
  if (activeResourceKind.value === 'all') {
    return resourceGroups.value
  }

  return resourceGroups.value.filter((item) => item.kind === activeResourceKind.value)
})

const syncTone = computed<Tone>(() => {
  if (syncState.value === 'saved') return 'safe'
  if (syncState.value === 'error') return 'danger'
  return 'info'
})

const syncLabel = computed(() => {
  if (syncState.value === 'saving') return '保存中'
  if (syncState.value === 'saved') return '已保存'
  if (syncState.value === 'error') return '保存失败'
  return '自动保存'
})

function getProtectedValues(kind: ResourceKind) {
  if (kind === 'path') return protectedPaths.value
  if (kind === 'skill') return protectedSkills.value
  return protectedPlugins.value
}

function setProtectedValues(kind: ResourceKind, values: string[]) {
  if (kind === 'path') {
    protectedPaths.value = values
    return
  }
  if (kind === 'skill') {
    protectedSkills.value = values
    return
  }
  protectedPlugins.value = values
}

function resourceGroup(kind: ResourceKind) {
  return resourceGroups.value.find((item) => item.kind === kind)
}

function parseDraftValues(value: string) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

async function persistProfile(successMessage: string) {
  beginSync('profile')

  try {
    const profile = await api.updateDefensePolicy(buildPolicyPayload())
    updateLocalDataProfile(profile)
    applyProfile(profile)
    finishSync(successMessage)
  } catch (err) {
    failSync(err instanceof Error ? err.message : '自动保存失败')
    await refresh()
  }
}

async function updateRemoteMode(id: number, enabled: boolean, mode: Mode, configJson?: Record<string, unknown>) {
  beginSync(`remote-${id}`)

  try {
    const updated = await api.updateDefenseConfig(id, {
      enabled,
      mode,
      config_json: configJson ?? {},
    })
    replaceRemoteDefenseItem(updated)
    finishSync(`防御配置 #${id} 已自动保存为 ${fieldLabel(modeFieldMeta(updated), updated.mode)} 模式。`)
  } catch (err) {
    failSync(err instanceof Error ? err.message : '更新失败')
  }
}

async function updateLocalRule(group: 'guard' | 'scan', key: string, patch: Partial<DefensePolicyRule>) {
  const target = group === 'guard' ? guardRules : scanRules
  target.value = target.value.map((item) => (item.key === key ? { ...item, ...patch } : item))
  const updated = target.value.find((item) => item.key === key)
  if (updated) {
    await persistProfile(`${updated.title} 已自动保存为 ${fieldLabel(modeFieldMeta(updated), updated.mode)} 模式。`)
  }
}

async function updateAdvancedRule(patch: Partial<DefensePolicyRule>) {
  advancedRule.value = { ...advancedRule.value, ...patch }
  await persistProfile(`${advancedRule.value.title} 已自动保存为 ${fieldLabel(modeFieldMeta(advancedRule.value), advancedRule.value.mode)} 模式。`)
}

async function updateAiReviewMode(mode: ReviewMode) {
  aiReviewPolicy.value = { ...aiReviewPolicy.value, mode }
  await persistProfile(`AI 复核策略已自动切换为 ${fieldLabel(aiReviewFieldMeta(aiReviewPolicy.value), aiReviewPolicy.value.mode)}。`)
}

async function updateAll(enabled: boolean, mode: Mode) {
  beginSync('all')

  guardRules.value = guardRules.value.map((item) => ({ ...item, enabled, mode }))
  scanRules.value = scanRules.value.map((item) => ({ ...item, enabled, mode }))
  advancedRule.value = { ...advancedRule.value, enabled, mode }

  try {
    const updatedConfigs = await api.batchUpdateDefenseConfigs({
      ids: items.value.map((item) => item.id),
      enabled,
      mode,
    })
    const profile = await api.updateDefensePolicy(buildPolicyPayload())
    replaceAllRemoteDefenseItems(updatedConfigs.items)
    updateLocalDataProfile(profile)
    applyProfile(profile)
    finishSync(`全局防御已自动切换为 ${fieldLabel(globalModeFieldMeta.value, mode)} 模式。`)
  } catch (err) {
    failSync(err instanceof Error ? err.message : '更新失败')
    await refresh()
  }
}

async function commitProtectedDraft(kind: ResourceKind) {
  const values = parseDraftValues(drafts[kind])
  if (!values.length) {
    return
  }

  const current = getProtectedValues(kind)
  const next = [...current]
  let addedCount = 0

  for (const value of values) {
    if (!next.includes(value)) {
      next.push(value)
      addedCount += 1
    }
  }

  drafts[kind] = ''

  if (!addedCount) {
    syncState.value = 'idle'
    syncMessage.value = `${resourceGroup(kind)?.title ?? '该分组'} 中已存在相同项。`
    return
  }

  setProtectedValues(kind, next)
  await persistProfile(`已自动保存 ${addedCount} 项${resourceGroup(kind)?.title ?? ''}。`)
}

async function removeProtectedValue(kind: ResourceKind, value: string) {
  const current = getProtectedValues(kind)
  setProtectedValues(
    kind,
    current.filter((item) => item !== value)
  )
  await persistProfile(`已自动移除 ${value}。`)
}

function handleProtectedDraftKeydown(kind: ResourceKind, event: KeyboardEvent) {
  if (event.key === 'Enter' || event.key === ',') {
    event.preventDefault()
    void commitProtectedDraft(kind)
  }
}

function isCoverageExpanded(id: number) {
  return Boolean(expandedCoverage.value[id])
}

function toggleCoverage(id: number) {
  expandedCoverage.value = {
    ...expandedCoverage.value,
    [id]: !expandedCoverage.value[id],
  }
}
</script>

<template>
  <section class="page-grid config-page">
    <div v-if="loading" class="empty-state">正在加载配置项...</div>
    <div v-else-if="error" class="empty-state">
      <p>加载失败：{{ error }}</p>
      <button class="ghost-button" type="button" @click="refresh">重试</button>
    </div>
    <template v-else>
      <PageSection eyebrow="总控" title="全局切换" tone="info">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ syncMessage }}</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${activeCount} 项启用`" tone="safe" />
                <StatusPill
                  :label="fieldLabel(globalModeFieldMeta, primaryMode)"
                  :tone="fieldTone(globalModeFieldMeta, primaryMode)"
                />
                <span>{{ items.length + guardRules.length + scanRules.length + 1 }} 项防线已纳入总控</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <label class="toggle-switch">
                <input
                  class="toggle-input"
                  :checked="primaryEnabled"
                  :disabled="isMutating"
                  type="checkbox"
                  @change="updateAll(!primaryEnabled, primaryMode)"
                />
                <span class="toggle-ui"></span>
              </label>
              <div class="mode-group">
                <button
                  v-for="option in globalModeFieldMeta.options"
                  :key="option.value"
                  :class="['mode-button', { active: primaryMode === option.value }]"
                  :disabled="isMutating"
                  type="button"
                  @click="updateAll(primaryEnabled, option.value as Mode)"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
        </template>
        <article v-if="false" class="setting-row setting-row-emphasis">
          <div class="setting-main">
            <label class="toggle-switch">
              <input
                class="toggle-input"
                :checked="primaryEnabled"
                :disabled="isMutating"
                type="checkbox"
                @change="updateAll(!primaryEnabled, primaryMode)"
              />
              <span class="toggle-ui"></span>
            </label>
            <div class="setting-copy">
              <h4>启用所有防御</h4>
              <div class="setting-meta">
                <StatusPill :label="`${activeCount} 项在线`" tone="safe" />
                <span>默认模式：{{ fieldLabel(globalModeFieldMeta, primaryMode) }}</span>
              </div>
            </div>
          </div>
          <div class="mode-group">
            <button
              v-for="option in globalModeFieldMeta.options"
              :key="option.value"
              :class="['mode-button', { active: primaryMode === option.value }]"
              :disabled="isMutating"
              type="button"
              @click="updateAll(primaryEnabled, option.value as Mode)"
            >
              {{ option.label }}
            </button>
          </div>
        </article>
      </PageSection>

      <PageSection id="execution-guard" eyebrow="执行" title="执行守卫" tag="远程配置" tone="safe">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>执行范围</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${executionGuardCount} 条`" tone="info" />
                <span>{{ executionScope === 'all' ? '查看全部执行规则' : executionScope === 'remote' ? '仅查看远程执行规则' : '仅查看本地执行规则' }}</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <div class="filter-row">
                <button
                  v-for="option in executionScopeOptions"
                  :key="option.value"
                  :class="['filter-chip', { active: executionScope === option.value }]"
                  type="button"
                  @click="executionScope = option.value"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>

          <article class="settings-dropdown-card">
            <button
              class="settings-dropdown-toggle"
              type="button"
              @click="executionOverviewExpanded = !executionOverviewExpanded"
            >
              <div class="settings-dropdown-copy">
                <div class="card-head">
                  <div>
                    <h4>执行守卫概览</h4>
                    <p class="settings-form-helper">默认收起，按需展开查看远程、本地和启用数量。</p>
                  </div>
                  <StatusPill
                    :label="executionOverviewExpanded ? '已展开' : '已收起'"
                    :tone="executionGuardEnabledCount ? 'safe' : 'info'"
                  />
                </div>
              </div>
              <span class="settings-dropdown-indicator">{{ executionOverviewExpanded ? '收起' : '展开' }}</span>
            </button>

            <div v-if="executionOverviewExpanded" class="settings-dropdown-body">
              <article class="setting-row setting-row-compact">
                <div class="setting-copy setting-copy-compact">
                  <h4>远程执行规则</h4>
                  <p>来自后端策略项</p>
                </div>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${items.length} 条`" tone="info" />
                  <StatusPill :label="`${remoteEnabledCount} 已启用`" :tone="remoteEnabledCount ? 'safe' : 'info'" />
                </div>
              </article>

              <article class="setting-row setting-row-compact">
                <div class="setting-copy setting-copy-compact">
                  <h4>本地执行规则</h4>
                  <p>前置授权与执行守卫</p>
                </div>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${guardRules.length} 条`" tone="safe" />
                  <StatusPill :label="`${guardEnabledCount} 已启用`" :tone="guardEnabledCount ? 'safe' : 'info'" />
                </div>
              </article>

              <article class="setting-row setting-row-compact">
                <div class="setting-copy setting-copy-compact">
                  <h4>当前视图</h4>
                  <p>{{ executionScope === 'all' ? '全部执行规则' : executionScope === 'remote' ? '仅远程执行规则' : '仅本地执行规则' }}</p>
                </div>
                <div class="section-toolbar-meta">
                  <StatusPill
                    :label="`${executionGuardEnabledCount} 已启用`"
                    :tone="executionGuardEnabledCount ? 'safe' : 'info'"
                  />
                  <StatusPill
                    :label="fieldLabel(globalModeFieldMeta, primaryMode)"
                    :tone="fieldTone(globalModeFieldMeta, primaryMode)"
                  />
                </div>
              </article>
            </div>
          </article>
        </template>
        <div class="settings-stack settings-stack-compact">
          <template v-if="executionScope !== 'local'">
          <article
            v-for="item in items"
            :key="item.id"
            class="setting-row setting-row-compact"
          >
            <div class="setting-main">
              <label class="toggle-switch">
                <input
                  class="toggle-input"
                  :checked="item.enabled"
                  :disabled="isMutating"
                  type="checkbox"
                  @change="updateRemoteMode(item.id, !item.enabled, normalizeMode(item.mode), item.config_json)"
                />
                <span class="toggle-ui"></span>
              </label>
              <div class="setting-copy setting-copy-compact">
                <h4>{{ defenseDisplayLabel(item) }}</h4>
                <div class="setting-meta">
                  <span v-if="item.category_label">{{ item.category_label }}</span>
                  <span>威胁等级：{{ item.threat_level }}</span>
                  <StatusPill :label="fieldLabel(modeFieldMeta(item), item.mode)" :tone="fieldTone(modeFieldMeta(item), item.mode)" />
                </div>
                <p v-if="item.surface_labels?.length" class="card-subtitle">{{ item.surface_labels.join(' / ') }}</p>
                <div v-if="item.coverage_map" class="setting-coverage-toggle-row">
                  <button
                    class="coverage-toggle-button"
                    type="button"
                    :aria-expanded="isCoverageExpanded(item.id)"
                    @click="toggleCoverage(item.id)"
                  >
                    <span>{{ isCoverageExpanded(item.id) ? '收起覆盖映射' : '展开覆盖映射' }}</span>
                    <span class="coverage-toggle-arrow" aria-hidden="true">{{ isCoverageExpanded(item.id) ? '−' : '+' }}</span>
                  </button>
                </div>
                <div
                  v-if="item.coverage_map && isCoverageExpanded(item.id)"
                  class="setting-coverage setting-coverage-compact"
                >
                  <p class="coverage-summary">{{ item.coverage_map.summary_text }}</p>
                  <div v-if="item.coverage_map.matched_sections.length" class="coverage-row">
                    <span class="coverage-label">章节</span>
                    <div class="token-list coverage-token-list">
                      <span
                        v-for="section in item.coverage_map.matched_sections"
                        :key="section.value"
                        class="token-chip coverage-chip"
                      >
                        {{ section.label }} ({{ section.entry_count }})
                      </span>
                    </div>
                  </div>
                  <div v-if="item.coverage_map.matched_packs.length" class="coverage-row">
                    <span class="coverage-label">专项包</span>
                    <div class="token-list coverage-token-list">
                      <span
                        v-for="pack in item.coverage_map.matched_packs"
                        :key="pack.value"
                        class="token-chip coverage-chip"
                      >
                        {{ pack.label }} ({{ pack.entry_count }})
                      </span>
                    </div>
                  </div>
                  <div v-if="item.coverage_map.attack_surfaces.length" class="coverage-row">
                    <span class="coverage-label">攻击面</span>
                    <div class="token-list coverage-token-list">
                      <span
                        v-for="surface in item.coverage_map.attack_surfaces"
                        :key="surface"
                        class="token-chip coverage-chip coverage-chip-subtle"
                      >
                        {{ surface }}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div class="mode-group">
              <button
                v-for="option in modeFieldMeta(item).options"
                :key="option.value"
                :class="['mode-button', { active: item.mode === option.value }]"
                :disabled="isMutating"
                type="button"
                @click="updateRemoteMode(item.id, item.enabled, option.value as Mode, item.config_json)"
              >
                {{ option.label }}
              </button>
            </div>
          </article>
          </template>

          <template v-if="executionScope !== 'remote'">
          <article
            v-for="item in guardRules"
            :key="item.key"
            class="setting-row setting-row-compact"
          >
            <div class="setting-main">
              <label class="toggle-switch">
                <input
                  class="toggle-input"
                  :checked="item.enabled"
                  :disabled="isMutating"
                  type="checkbox"
                  @change="updateLocalRule('guard', item.key, { enabled: !item.enabled })"
                />
                <span class="toggle-ui"></span>
              </label>
              <div class="setting-copy setting-copy-compact">
                <h4>{{ ruleDisplayLabel(item) }}</h4>
                <div class="setting-meta">
                  <span v-if="item.category_label">{{ item.category_label }}</span>
                  <span v-if="item.surface_labels?.length">{{ item.surface_labels.join(' / ') }}</span>
                </div>
              </div>
            </div>
            <div class="mode-group">
              <button
                v-for="option in modeFieldMeta(item).options"
                :key="option.value"
                :class="['mode-button', { active: item.mode === option.value }]"
                :disabled="isMutating"
                type="button"
                @click="updateLocalRule('guard', item.key, { mode: option.value as Mode })"
              >
                {{ option.label }}
              </button>
            </div>
          </article>
          </template>
        </div>
      </PageSection>

      <PageSection id="scan-output" eyebrow="扫描" title="扫描与输出" tag="本地策略" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>扫描策略概览</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${scanRules.length} 条规则`" tone="warn" />
                <StatusPill :label="`${scanEnabledCount} 已启用`" :tone="scanEnabledCount ? 'safe' : 'info'" />
                <span>全局模式：{{ fieldLabel(globalModeFieldMeta, primaryMode) }}</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <StatusPill
                :label="fieldLabel(globalModeFieldMeta, primaryMode)"
                :tone="fieldTone(globalModeFieldMeta, primaryMode)"
              />
            </div>
          </div>
        </template>
        <div class="settings-stack settings-stack-compact">
          <article
            v-for="item in scanRules"
            :key="item.key"
            class="setting-row setting-row-compact"
          >
            <div class="setting-main">
              <label class="toggle-switch">
                <input
                  class="toggle-input"
                  :checked="item.enabled"
                  :disabled="isMutating"
                  type="checkbox"
                  @change="updateLocalRule('scan', item.key, { enabled: !item.enabled })"
                />
                <span class="toggle-ui"></span>
              </label>
              <div class="setting-copy setting-copy-compact">
                <h4>{{ ruleDisplayLabel(item) }}</h4>
                <div class="setting-meta">
                  <span v-if="item.category_label">{{ item.category_label }}</span>
                  <span v-if="item.surface_labels?.length">{{ item.surface_labels.join(' / ') }}</span>
                </div>
              </div>
            </div>
            <div class="mode-group">
              <button
                v-for="option in modeFieldMeta(item).options"
                :key="option.value"
                :class="['mode-button', { active: item.mode === option.value }]"
                :disabled="isMutating"
                type="button"
                @click="updateLocalRule('scan', item.key, { mode: option.value as Mode })"
              >
                {{ option.label }}
              </button>
            </div>
          </article>
        </div>
      </PageSection>

      <PageSection id="protected-resources" eyebrow="资源" title="受保护资源" tag="自动保存" tone="info">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>受保护资源概览</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${totalProtectedCount} 项纳管`" tone="info" />
                <StatusPill :label="`${protectedPaths.length} 路径`" tone="info" />
                <StatusPill :label="`${protectedSkills.length} 技能`" tone="safe" />
                <StatusPill :label="`${protectedPlugins.length} 插件`" tone="warn" />
              </div>
            </div>
            <div class="section-toolbar-actions">
              <div class="filter-row">
                <button
                  v-for="option in resourceKindOptions"
                  :key="option.value"
                  :class="['filter-chip', { active: activeResourceKind === option.value }]"
                  type="button"
                  @click="activeResourceKind = option.value"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
        </template>
        <div class="field-grid field-grid-compact">
          <article
            v-for="section in filteredResourceGroups"
            :key="section.kind"
            class="field-card field-card-compact"
          >
            <div class="field-head">
              <div>
                <h4>{{ section.title }}</h4>
              </div>
              <small class="field-count">已纳管 {{ getProtectedValues(section.kind).length }} 项</small>
            </div>
            <div class="input-inline">
              <input
                v-model="drafts[section.kind]"
                class="text-input"
                :disabled="isMutating"
                :placeholder="section.field_meta.placeholder"
                type="text"
                @keydown="handleProtectedDraftKeydown(section.kind, $event)"
              />
              <button class="ghost-button small" :disabled="isMutating" type="button" @click="commitProtectedDraft(section.kind)">
                {{ section.field_meta.button_text || '添加' }}
              </button>
            </div>
            <div v-if="getProtectedValues(section.kind).length" class="token-list">
              <span
                v-for="item in getProtectedValues(section.kind)"
                :key="item"
                class="token-chip"
              >
                <span>{{ item }}</span>
                <button
                  class="token-chip-remove"
                  :disabled="isMutating"
                  type="button"
                  @click="removeProtectedValue(section.kind, item)"
                >
                  x
                </button>
              </span>
            </div>
            <div v-else class="token-empty">{{ section.field_meta.empty_text || '当前还没有纳管项，添加后会立即生效。' }}</div>
          </article>
        </div>
      </PageSection>

      <PageSection eyebrow="高级" title="高级规则" tag="自动审计" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ ruleDisplayLabel(advancedRule) }}</h4>
              <div class="section-toolbar-meta">
                <StatusPill
                  :label="fieldLabel(modeFieldMeta(advancedRule), advancedRule.mode)"
                  :tone="fieldTone(modeFieldMeta(advancedRule), advancedRule.mode)"
                />
                <span>{{ advancedRule.enabled ? '已启用' : '已停用' }}</span>
                <span v-if="advancedRule.category_label">{{ advancedRule.category_label }}</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <label class="toggle-switch">
                <input
                  class="toggle-input"
                  :checked="advancedRule.enabled"
                  :disabled="isMutating"
                  type="checkbox"
                  @change="updateAdvancedRule({ enabled: !advancedRule.enabled })"
                />
                <span class="toggle-ui"></span>
              </label>
              <div class="mode-group">
                <button
                  v-for="option in modeFieldMeta(advancedRule).options"
                  :key="option.value"
                  :class="['mode-button', { active: advancedRule.mode === option.value }]"
                  :disabled="isMutating"
                  type="button"
                  @click="updateAdvancedRule({ mode: option.value as Mode })"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
        </template>
        <article v-if="false" class="setting-row">
          <div class="setting-main">
            <label class="toggle-switch">
              <input
                class="toggle-input"
                :checked="advancedRule.enabled"
                :disabled="isMutating"
                type="checkbox"
                @change="updateAdvancedRule({ enabled: !advancedRule.enabled })"
              />
              <span class="toggle-ui"></span>
            </label>
            <div class="setting-copy">
              <h4>{{ advancedRule.title }}</h4>
            </div>
          </div>
          <div class="mode-group">
            <button
              v-for="option in modeFieldMeta(advancedRule).options"
              :key="option.value"
              :class="['mode-button', { active: advancedRule.mode === option.value }]"
              :disabled="isMutating"
              type="button"
              @click="updateAdvancedRule({ mode: option.value as Mode })"
            >
              {{ option.label }}
            </button>
          </div>
        </article>
      </PageSection>
      <PageSection id="ai-review" eyebrow="复核" title="AI 复核" tag="三段模式" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ ruleDisplayLabel(aiReviewPolicy) }}</h4>
              <div class="section-toolbar-meta">
                <StatusPill
                  :label="fieldLabel(aiReviewFieldMeta(aiReviewPolicy), aiReviewPolicy.mode)"
                  :tone="fieldTone(aiReviewFieldMeta(aiReviewPolicy), aiReviewPolicy.mode)"
                />
                <span>{{ items.length + guardRules.length }} 条执行规则可按当前策略进入复核</span>
                <span v-if="aiReviewPolicy.category_label">{{ aiReviewPolicy.category_label }}</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <div class="mode-group">
                <button
                  v-for="option in aiReviewFieldMeta(aiReviewPolicy).options"
                  :key="option.value"
                  :class="['mode-button', { active: aiReviewPolicy.mode === option.value }]"
                  :disabled="isMutating"
                  type="button"
                  @click="updateAiReviewMode(option.value as ReviewMode)"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
        </template>
        <article v-if="false" class="setting-row setting-row-emphasis">
          <div class="setting-main">
              <div class="setting-copy">
                <h4>{{ aiReviewPolicy.title }}</h4>
                <div class="setting-meta">
                  <StatusPill
                    :label="fieldLabel(aiReviewFieldMeta(aiReviewPolicy), aiReviewPolicy.mode)"
                    :tone="fieldTone(aiReviewFieldMeta(aiReviewPolicy), aiReviewPolicy.mode)"
                  />
                </div>
              </div>
            </div>
          <div class="mode-group">
            <button
              v-for="option in aiReviewFieldMeta(aiReviewPolicy).options"
              :key="option.value"
              :class="['mode-button', { active: aiReviewPolicy.mode === option.value }]"
              :disabled="isMutating"
              type="button"
              @click="updateAiReviewMode(option.value as ReviewMode)"
            >
              {{ option.label }}
            </button>
          </div>
        </article>
      </PageSection>
    </template>
  </section>
</template>
