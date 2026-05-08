<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter, type RouteLocationRaw } from 'vue-router'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import {
  api,
  type AssetItem,
  type AssetWhitelistFieldMeta,
  type AssetWhitelistItem,
  type FormFieldMeta,
  type FormFieldTone,
} from '../services/api'
import { redactSensitiveText } from '../services/redaction'
import { formatBeijingTime } from '../services/time'

type Tone = FormFieldTone
type SyncState = 'idle' | 'saving' | 'saved' | 'error'
type WhitelistType = 'path' | 'skill' | 'plugin'
type AssetTypeFilter = 'all' | 'path' | 'skill' | 'plugin'
type AssetStatusFilter = 'all' | 'protected' | 'monitoring' | 'disabled'
type LinkedConfigEntry = {
  key: string
  title: string
  subtitle: string
  tag: string
  tone: Tone
  route: RouteLocationRaw
}

const FALLBACK_STATUS_FIELD_META: FormFieldMeta = {
  control: 'segmented',
  placeholder: '',
  helper_text: '状态按钮点击后会立即写回后端，不再需要额外保存。',
  button_text: '',
  empty_text: '',
  options: [
    { label: '保护中', value: 'protected', tone: 'safe' },
    { label: '观察中', value: 'monitoring', tone: 'warn' },
    { label: '已停用', value: 'disabled', tone: 'info' },
  ],
}

const FALLBACK_RISK_FIELD_META: FormFieldMeta = {
  control: 'segmented',
  placeholder: '',
  helper_text: '风险等级用于快速调整治理优先级和当前资产的处置强度。',
  button_text: '',
  empty_text: '',
  options: [
    { label: '高风险', value: '高', tone: 'danger' },
    { label: '中风险', value: '中', tone: 'warn' },
    { label: '低风险', value: '低', tone: 'safe' },
  ],
}

const FALLBACK_WHITELIST_FIELD_META: AssetWhitelistFieldMeta = {
  whitelist_type: {
    control: 'select',
    placeholder: '',
    helper_text: '白名单类型由后端定义，前端只负责按元数据渲染控件。',
    button_text: '',
    empty_text: '',
    options: [
      { label: '路径', value: 'path', tone: 'info' },
      { label: '技能', value: 'skill', tone: 'safe' },
      { label: '插件', value: 'plugin', tone: 'warn' },
    ],
  },
  rule_value: {
    control: 'text',
    placeholder: '/workspace/** 或 trusted-*',
    helper_text: '填写规则值后按 Enter 或点击按钮即可提交。',
    button_text: '',
    empty_text: '',
    options: [],
  },
  description: {
    control: 'text',
    placeholder: '规则说明，可选',
    helper_text: '留空时后端会生成默认说明。',
    button_text: '添加规则',
    empty_text: '当前资产还没有白名单规则。',
    options: [],
  },
}

const { data, loading, error, refresh } = useAsyncData(async () => {
  const assets = await api.assets()
  return { assets }
})

const router = useRouter()
const selectedAssetId = ref<number | null>(null)
const whitelistItems = ref<AssetWhitelistItem[]>([])
const whitelistFieldMeta = ref<AssetWhitelistFieldMeta>(FALLBACK_WHITELIST_FIELD_META)
const whitelistsLoading = ref(false)
const whitelistError = ref<string | null>(null)
const activeKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('待操作')
const lastActionAt = ref('')
const draftWhitelistType = ref<WhitelistType>('path')
const draftWhitelistValue = ref('')
const draftWhitelistDescription = ref('')
const assetTypeFilter = ref<AssetTypeFilter>('all')
const assetStatusFilter = ref<AssetStatusFilter>('all')
const whitelistTypeFilter = ref<'all' | WhitelistType>('all')

const assetTypeOptions = [
  { label: '\u5168\u90e8', value: 'all' },
  { label: '\u8def\u5f84', value: 'path' },
  { label: '\u6280\u80fd', value: 'skill' },
  { label: '\u63d2\u4ef6', value: 'plugin' },
] as const

const assetStatusOptions = [
  { label: '\u5168\u90e8', value: 'all' },
  { label: '\u4fdd\u62a4\u4e2d', value: 'protected' },
  { label: '\u89c2\u5bdf\u4e2d', value: 'monitoring' },
  { label: '\u5df2\u505c\u7528', value: 'disabled' },
] as const

const whitelistTypeOptions = [
  { label: '\u5168\u90e8', value: 'all' },
  { label: '\u8def\u5f84', value: 'path' },
  { label: '\u6280\u80fd', value: 'skill' },
  { label: '\u63d2\u4ef6', value: 'plugin' },
] as const

const assetItems = computed<AssetItem[]>(() => data.value?.assets.items ?? [])
const selectedAsset = computed(() => assetItems.value.find((item) => item.id === selectedAssetId.value) ?? null)
const protectedCount = computed(() => assetItems.value.filter((item) => item.status === 'protected').length)
const highRiskCount = computed(() => assetItems.value.filter((item) => isHighRiskLevel(item.risk_level)).length)
const whitelistCount = computed(() => whitelistItems.value.length)
const isMutating = computed(() => activeKey.value !== null)

const filteredAssetItems = computed(() =>
  assetItems.value.filter((item) => {
    const matchesType = assetTypeFilter.value === 'all' || item.asset_type === assetTypeFilter.value
    const matchesStatus = assetStatusFilter.value === 'all' || item.status === assetStatusFilter.value
    return matchesType && matchesStatus
  })
)

const whitelistBreakdown = computed(() => {
  const pathCount = whitelistItems.value.filter((item) => item.whitelist_type === 'path').length
  const skillCount = whitelistItems.value.filter((item) => item.whitelist_type === 'skill').length
  const pluginCount = whitelistItems.value.filter((item) => item.whitelist_type === 'plugin').length
  return `${pathCount} 路径 / ${skillCount} 技能 / ${pluginCount} 插件`
})

const linkedConfigEntries = computed<LinkedConfigEntry[]>(() => {
  const resourceKind = linkedResourceKind(selectedAsset.value)

  return [
    {
      key: 'pre-protect-ai',
      title: '预保护 AI 接入',
      subtitle: '默认路由 / 防护开关',
      tag: 'AI 目标',
      tone: 'info',
      route: { name: 'ai-endpoints', query: { focus: 'route-protection' } },
    },
    {
      key: 'ai-review',
      title: 'AI 研判接入',
      subtitle: '规则直断 / AI 复核',
      tag: 'AI 复核',
      tone: 'warn',
      route: { name: 'defense-config', query: { focus: 'ai-review' } },
    },
    {
      key: 'skill-scan',
      title: 'Skill 扫描任务',
      subtitle: '批量扫描 / 审批联动',
      tag: '扫描任务',
      tone: 'safe',
      route: { name: 'skill-management', query: { focus: 'scan-tasks' } },
    },
    {
      key: 'protected-resource',
      title: linkedResourceTitle(selectedAsset.value),
      subtitle: '受保护资源 / 纳管清单',
      tag: resourceKindLabel(resourceKind),
      tone: resourceKindTone(resourceKind),
      route: {
        name: 'defense-config',
        query: { focus: 'protected-resources', kind: resourceKind },
      },
    },
    {
      key: 'scan-output',
      title: '数据脱敏保护',
      subtitle: '扫描与输出',
      tag: '脱敏',
      tone: 'warn',
      route: { name: 'defense-config', query: { focus: 'scan-output' } },
    },
  ]
})

const filteredWhitelistItems = computed(() => {
  if (whitelistTypeFilter.value === 'all') {
    return whitelistItems.value
  }

  return whitelistItems.value.filter((item) => item.whitelist_type === whitelistTypeFilter.value)
})

watch(
  assetItems,
  (items) => {
    if (!items.length) {
      selectedAssetId.value = null
      whitelistItems.value = []
      return
    }

    if (!selectedAssetId.value || !items.some((item) => item.id === selectedAssetId.value)) {
      selectedAssetId.value = items[0].id
    }
  },
  { immediate: true }
)

watch(filteredAssetItems, (items) => {
  if (!items.length) {
    return
  }

  if (!selectedAssetId.value || !items.some((item) => item.id === selectedAssetId.value)) {
    selectedAssetId.value = items[0].id
  }
})

watch(selectedAssetId, (assetId) => {
  if (!assetId) {
    whitelistItems.value = []
    whitelistFieldMeta.value = FALLBACK_WHITELIST_FIELD_META
    whitelistError.value = null
    whitelistTypeFilter.value = 'all'
    return
  }

  whitelistTypeFilter.value = 'all'
  void loadWhitelists(assetId)
})

function formatTime(date = new Date()) {
  return formatBeijingTime(date)
}

function beginAction(key: string, message = '正在同步资产治理动作...') {
  activeKey.value = key
  syncState.value = 'saving'
  syncMessage.value = message
}

function finishAction(message: string) {
  activeKey.value = null
  syncState.value = 'saved'
  syncMessage.value = message
  lastActionAt.value = formatTime()
}

function failAction(message: string) {
  activeKey.value = null
  syncState.value = 'error'
  syncMessage.value = message
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

function displayText(value?: string | null) {
  return redactSensitiveText(value)
}

function normalizeRiskLevel(level: string) {
  const lowered = level.toLowerCase()
  if (lowered === 'high' || level.includes('高')) return 'high'
  if (lowered === 'low' || level.includes('低')) return 'low'
  return 'medium'
}

function isHighRiskLevel(level: string) {
  return normalizeRiskLevel(level) === 'high'
}

function riskOption(meta: FormFieldMeta, value: string) {
  return (
    findOption(meta, value) ??
    meta.options.find((item) => normalizeRiskLevel(item.value) === normalizeRiskLevel(value))
  )
}

function riskFieldLabel(asset: AssetItem | null, value: string) {
  return riskOption(riskFieldMeta(asset), value)?.label ?? value
}

function riskFieldTone(asset: AssetItem | null, value: string): Tone {
  return riskOption(riskFieldMeta(asset), value)?.tone ?? 'info'
}

function isRiskOptionActive(currentValue: string, optionValue: string) {
  return normalizeRiskLevel(currentValue) === normalizeRiskLevel(optionValue)
}

function assetTypeLabel(type: string) {
  if (type === 'path') return '路径资产'
  if (type === 'skill') return '技能资产'
  if (type === 'plugin') return '插件资产'
  return type
}

function resourceKindLabel(kind: WhitelistType) {
  if (kind === 'path') return '路径'
  if (kind === 'skill') return '技能'
  return '插件'
}

function resourceKindTone(kind: WhitelistType): Tone {
  if (kind === 'skill') return 'safe'
  if (kind === 'plugin') return 'warn'
  return 'info'
}

function linkedResourceKind(asset?: AssetItem | null): WhitelistType {
  if (asset?.asset_type === 'skill' || asset?.asset_type === 'plugin') {
    return asset.asset_type
  }
  return 'path'
}

function linkedResourceTitle(asset?: AssetItem | null) {
  const kind = linkedResourceKind(asset)
  if (kind === 'skill') return '保护技能'
  if (kind === 'plugin') return '保护插件'
  return '保护目录'
}

function statusFieldMeta(asset?: AssetItem | null) {
  return asset?.field_meta?.status ?? FALLBACK_STATUS_FIELD_META
}

function riskFieldMeta(asset?: AssetItem | null) {
  return asset?.field_meta?.risk_level ?? FALLBACK_RISK_FIELD_META
}

function whitelistTypeFieldMeta() {
  return whitelistFieldMeta.value.whitelist_type ?? FALLBACK_WHITELIST_FIELD_META.whitelist_type
}

function whitelistValueFieldMeta() {
  return whitelistFieldMeta.value.rule_value ?? FALLBACK_WHITELIST_FIELD_META.rule_value
}

function whitelistDescriptionFieldMeta() {
  return whitelistFieldMeta.value.description ?? FALLBACK_WHITELIST_FIELD_META.description
}

function defaultWhitelistType() {
  const firstOption = whitelistTypeFieldMeta().options[0]?.value
  return (firstOption ?? 'path') as WhitelistType
}

function replaceAssetItem(updated: AssetItem) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    assets: {
      ...data.value.assets,
      items: data.value.assets.items.map((item) => (item.id === updated.id ? updated : item)),
    },
  }
}

async function loadWhitelists(assetId: number) {
  whitelistsLoading.value = true
  whitelistError.value = null

  try {
    const response = await api.assetWhitelists(assetId)
    if (selectedAssetId.value !== assetId) {
      return
    }

    whitelistItems.value = response.items
    whitelistFieldMeta.value = response.field_meta

    if (!whitelistTypeFieldMeta().options.some((item) => item.value === draftWhitelistType.value)) {
      draftWhitelistType.value = defaultWhitelistType()
    }
  } catch (err) {
    if (selectedAssetId.value !== assetId) {
      return
    }

    whitelistItems.value = []
    whitelistFieldMeta.value = FALLBACK_WHITELIST_FIELD_META
    whitelistError.value = err instanceof Error ? err.message : '白名单规则加载失败'
  } finally {
    if (selectedAssetId.value === assetId) {
      whitelistsLoading.value = false
    }
  }
}

function selectAsset(assetId: number) {
  selectedAssetId.value = assetId
  syncState.value = 'idle'
  syncMessage.value = '已切换资产'
}

function openLinkedConfig(route: RouteLocationRaw) {
  void router.push(route)
}

async function updateSelectedAsset(patch: Partial<Pick<AssetItem, 'risk_level' | 'status'>>) {
  if (!selectedAsset.value) {
    return
  }

  const current = selectedAsset.value
  const next = { ...current, ...patch }

  if (
    normalizeRiskLevel(next.risk_level) === normalizeRiskLevel(current.risk_level) &&
    next.status === current.status
  ) {
    syncState.value = 'idle'
    syncMessage.value = `${current.asset_name} 当前状态没有变化。`
    return
  }

  beginAction(`asset-${current.id}`, `正在同步 ${current.asset_name} 的资产状态...`)

  try {
    const updated = await api.updateAsset(current.id, {
      asset_name: next.asset_name,
      asset_type: next.asset_type,
      asset_path: next.asset_path,
      risk_level: next.risk_level,
      status: next.status,
    })
    replaceAssetItem(updated)
    finishAction(`资产 ${updated.asset_name} 已自动同步。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '资产更新失败')
    await refresh()
  }
}

async function addWhitelistRule() {
  if (!selectedAsset.value) {
    return
  }

  const ruleValue = draftWhitelistValue.value.trim()
  if (!ruleValue) {
    syncState.value = 'idle'
    syncMessage.value = '先填写规则值，再添加白名单。'
    return
  }

  if (
    whitelistItems.value.some(
      (item) => item.whitelist_type === draftWhitelistType.value && item.rule_value === ruleValue
    )
  ) {
    syncState.value = 'idle'
    syncMessage.value = '当前资产已存在相同的白名单规则。'
    return
  }

  beginAction('whitelist-create', `正在为 ${selectedAsset.value.asset_name} 添加白名单规则...`)

  try {
    const created = await api.createAssetWhitelist(selectedAsset.value.id, {
      whitelist_type: draftWhitelistType.value,
      rule_value: ruleValue,
      description:
        draftWhitelistDescription.value.trim() ||
        `允许 ${fieldLabel(whitelistTypeFieldMeta(), draftWhitelistType.value)} 访问`,
    })
    whitelistItems.value = [created, ...whitelistItems.value]
    draftWhitelistValue.value = ''
    draftWhitelistDescription.value = ''
    draftWhitelistType.value = defaultWhitelistType()
    finishAction(`已为 ${selectedAsset.value.asset_name} 添加 ${fieldLabel(whitelistTypeFieldMeta(), created.whitelist_type)}。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '白名单规则添加失败')
  }
}

async function removeWhitelistRule(rule: AssetWhitelistItem) {
  beginAction(`whitelist-${rule.id}`, `正在移除规则 ${rule.rule_value}...`)

  try {
    await api.deleteAssetWhitelist(rule.id)
    whitelistItems.value = whitelistItems.value.filter((item) => item.id !== rule.id)
    finishAction(`规则 ${rule.rule_value} 已自动移除。`)
  } catch (err) {
    failAction(err instanceof Error ? err.message : '白名单规则移除失败')
  }
}
</script>

<template>
  <section class="page-grid">
    <section class="content-grid two-column">
      <PageSection eyebrow="资产" title="资产焦点清单" tag="选择后即编辑" tone="safe">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ selectedAsset ? selectedAsset.asset_name : '资产焦点清单' }}</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${filteredAssetItems.length} / ${assetItems.length}`" tone="info" />
                <StatusPill :label="`${protectedCount} 保护中`" :tone="protectedCount ? 'safe' : 'info'" />
                <span>{{ highRiskCount }} 个高风险</span>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <button
                class="ghost-button small"
                type="button"
                @click="
                  assetTypeFilter = 'all';
                  assetStatusFilter = 'all'
                "
              >
                重置筛选
              </button>
            </div>
          </div>

          <div class="section-toolbar section-toolbar-secondary">
            <div class="section-toolbar-fill">
              <div class="filter-row">
                <button
                  v-for="option in assetTypeOptions"
                  :key="option.value"
                  :class="['filter-chip', { active: assetTypeFilter === option.value }]"
                  type="button"
                  @click="assetTypeFilter = option.value"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
            <div class="section-toolbar-actions">
              <div class="filter-row">
                <button
                  v-for="option in assetStatusOptions"
                  :key="option.value"
                  :class="['filter-chip', { active: assetStatusFilter === option.value }]"
                  type="button"
                  @click="assetStatusFilter = option.value"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
        </template>
        <div v-if="loading" class="empty-state">正在加载资产信息...</div>
        <div v-else-if="error" class="empty-state">
          <p>加载失败：{{ error }}</p>
          <button class="ghost-button" type="button" @click="refresh">重试</button>
        </div>
        <div v-else-if="filteredAssetItems.length" class="asset-list asset-list-compact">
          <button
            v-for="item in filteredAssetItems"
            :key="item.id"
            :class="['asset-list-button', 'asset-list-button-compact', { active: item.id === selectedAssetId }]"
            type="button"
            @click="selectAsset(item.id)"
          >
            <div class="card-head">
              <div>
                <h4>{{ item.asset_name }}</h4>
                <p class="card-subtitle">{{ assetTypeLabel(item.asset_type) }}</p>
              </div>
              <StatusPill
                :label="fieldLabel(statusFieldMeta(item), item.status)"
                :tone="fieldTone(statusFieldMeta(item), item.status)"
              />
            </div>
            <p class="code-inline">{{ displayText(item.asset_path) }}</p>
            <div class="asset-list-meta">
              <StatusPill
                :label="riskFieldLabel(item, item.risk_level)"
                :tone="riskFieldTone(item, item.risk_level)"
              />
              <span>{{ item.asset_type }}</span>
            </div>
          </button>
        </div>
        <div v-else class="empty-state">当前筛选下没有匹配资产。</div>
      </PageSection>

      <PageSection eyebrow="控制" title="选中资产配置" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ selectedAsset ? selectedAsset.asset_name : '等待选择资产' }}</h4>
              <div v-if="selectedAsset" class="section-toolbar-meta">
                <StatusPill
                  :label="fieldLabel(statusFieldMeta(selectedAsset), selectedAsset.status)"
                  :tone="fieldTone(statusFieldMeta(selectedAsset), selectedAsset.status)"
                />
                <StatusPill
                  :label="riskFieldLabel(selectedAsset, selectedAsset.risk_level)"
                  :tone="riskFieldTone(selectedAsset, selectedAsset.risk_level)"
                />
                <span>{{ whitelistCount }} 条白名单</span>
              </div>
            </div>
            <div v-if="selectedAsset" class="section-toolbar-actions">
              <StatusPill :label="assetTypeLabel(selectedAsset.asset_type)" tone="info" />
            </div>
          </div>
        </template>
        <div v-if="selectedAsset" class="asset-detail-grid asset-detail-grid-compact">
          <div class="asset-summary-strip">
            <p class="asset-summary-path">{{ displayText(selectedAsset.asset_path) }}</p>
            <div class="section-toolbar-meta">
              <StatusPill
                :label="fieldLabel(statusFieldMeta(selectedAsset), selectedAsset.status)"
                :tone="fieldTone(statusFieldMeta(selectedAsset), selectedAsset.status)"
              />
              <StatusPill
                :label="riskFieldLabel(selectedAsset, selectedAsset.risk_level)"
                :tone="riskFieldTone(selectedAsset, selectedAsset.risk_level)"
              />
              <span>{{ assetTypeLabel(selectedAsset.asset_type) }}</span>
            </div>
          </div>

          <div class="compact-control-grid">
          <article class="field-card field-card-compact">
            <div class="field-head">
              <div>
                <h4>保护状态</h4>
              </div>
              <small class="field-count">当前 {{ fieldLabel(statusFieldMeta(selectedAsset), selectedAsset.status) }}</small>
            </div>
            <div class="mode-group">
              <button
                v-for="option in statusFieldMeta(selectedAsset).options"
                :key="option.value"
                :class="['mode-button', { active: selectedAsset.status === option.value }]"
                :disabled="isMutating"
                type="button"
                @click="updateSelectedAsset({ status: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </article>

          <article class="field-card field-card-compact">
            <div class="field-head">
              <div>
                <h4>风险等级</h4>
              </div>
              <small class="field-count">当前 {{ riskFieldLabel(selectedAsset, selectedAsset.risk_level) }}</small>
            </div>
            <div class="mode-group">
              <button
                v-for="option in riskFieldMeta(selectedAsset).options"
                :key="option.value"
                :class="['mode-button', { active: isRiskOptionActive(selectedAsset.risk_level, option.value) }]"
                :disabled="isMutating"
                type="button"
                @click="updateSelectedAsset({ risk_level: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </article>
          </div>

          <article class="field-card field-card-compact">
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>联动配置入口</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${linkedConfigEntries.length} 项`" tone="info" />
                  <span>{{ assetTypeLabel(selectedAsset.asset_type) }}</span>
                </div>
              </div>
            </div>
            <div class="asset-linked-config-list">
              <button
                v-for="entry in linkedConfigEntries"
                :key="entry.key"
                class="asset-linked-config-button"
                type="button"
                @click="openLinkedConfig(entry.route)"
              >
                <div class="asset-linked-config-copy">
                  <h4>{{ entry.title }}</h4>
                  <p>{{ entry.subtitle }}</p>
                </div>
                <div class="asset-linked-config-meta">
                  <StatusPill :label="entry.tag" :tone="entry.tone" />
                  <span>进入</span>
                </div>
              </button>
            </div>
          </article>

          <article class="field-card field-card-compact">
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>白名单规则</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${filteredWhitelistItems.length} / ${whitelistCount}`" tone="info" />
                  <span>{{ whitelistBreakdown }}</span>
                </div>
              </div>
              <div class="section-toolbar-actions">
                <div class="filter-row">
                  <button
                    v-for="option in whitelistTypeOptions"
                    :key="option.value"
                    :class="['filter-chip', { active: whitelistTypeFilter === option.value }]"
                    type="button"
                    @click="whitelistTypeFilter = option.value"
                  >
                    {{ option.label }}
                  </button>
                </div>
              </div>
            </div>

            <div class="whitelist-form">
              <select v-model="draftWhitelistType" class="select-input" :disabled="isMutating">
                <option
                  v-for="option in whitelistTypeFieldMeta().options"
                  :key="option.value"
                  :value="option.value"
                >
                  {{ option.label }}
                </option>
              </select>
              <input
                v-model="draftWhitelistValue"
                class="text-input"
                :disabled="isMutating"
                :placeholder="whitelistValueFieldMeta().placeholder"
                type="text"
                @keydown.enter.prevent="addWhitelistRule"
              />
              <input
                v-model="draftWhitelistDescription"
                class="text-input"
                :disabled="isMutating"
                :placeholder="whitelistDescriptionFieldMeta().placeholder"
                type="text"
                @keydown.enter.prevent="addWhitelistRule"
              />
              <button class="ghost-button" :disabled="isMutating" type="button" @click="addWhitelistRule">
                {{ whitelistDescriptionFieldMeta().button_text || '添加规则' }}
              </button>
            </div>

            <div v-if="whitelistsLoading" class="token-empty">正在加载当前资产的白名单规则...</div>
            <div v-else-if="whitelistError" class="empty-state">
              <p>白名单加载失败：{{ whitelistError }}</p>
              <button class="ghost-button" type="button" @click="selectedAsset && loadWhitelists(selectedAsset.id)">重试</button>
            </div>
            <div v-else-if="filteredWhitelistItems.length" class="whitelist-list whitelist-list-compact">
              <article
                v-for="item in filteredWhitelistItems"
                :key="item.id"
                class="info-card whitelist-card whitelist-card-row"
              >
                <div class="whitelist-card-head">
                  <div class="whitelist-card-copy">
                    <StatusPill
                      :label="fieldLabel(whitelistTypeFieldMeta(), item.whitelist_type)"
                      :tone="fieldTone(whitelistTypeFieldMeta(), item.whitelist_type)"
                    />
                    <p class="code-inline">{{ displayText(item.rule_value) }}</p>
                  </div>
                  <button
                    class="ghost-button small"
                    :disabled="isMutating"
                    type="button"
                    @click="removeWhitelistRule(item)"
                  >
                    移除
                  </button>
                </div>
              </article>
            </div>
            <div v-else class="token-empty">
              {{ whitelistDescriptionFieldMeta().empty_text || '当前资产还没有白名单规则，新增后会立即生效。' }}
            </div>
          </article>
        </div>
        <div v-else class="empty-state">先从左侧选择一个资产，再开始即时调整。</div>
      </PageSection>
    </section>
  </section>
</template>
