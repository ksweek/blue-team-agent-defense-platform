<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAsyncData } from '../composables/useAsyncData'
import {
  api,
  type SystemActionKey,
  type SystemActionTone,
  type SystemSettingFieldMeta,
  type SystemSettingItem,
} from '../services/api'
import { redactSensitiveText, redactSettingToken } from '../services/redaction'
import { formatBeijingTime } from '../services/time'

type Tone = SystemActionTone
type SyncState = 'idle' | 'saving' | 'saved' | 'error'

type AuditLogItem = {
  id: number
  user_id: number
  module: string
  action: string
  detail: string
  created_at: string
}

const FALLBACK_FIELD_META: SystemSettingFieldMeta = {
  control: 'text',
  placeholder: '输入设置值',
  helper_text: '',
  options: [],
}

const ACTION_LABEL_MAP: Record<string, string> = {
  update: '更新设置',
  'export-defense-config': '导出防护配置',
  'platform-backup': '执行平台备份',
  'refresh-permission-cache': '刷新权限缓存',
  'send-test-email': '发送测试邮件',
  'email-digest': '邮件汇总',
}

const EMAIL_TOGGLE_KEY = 'notify_email'
const EMAIL_SETTING_KEYS = [
  'notify_email_recipients',
  'notify_email_template',
  'notify_email_min_level',
  'notify_email_digest_minutes',
  'notify_email_subject_prefix',
  'qq_email_account',
  'qq_email_auth_code',
] as const
const REVIEW_AI_SETTING_KEYS = [
  'review_ai_api_url',
  'review_ai_api_key',
  'review_ai_model',
] as const

const { data, loading, error, refresh } = useAsyncData(async () => {
  const [settings, auditLogs, systemActions] = await Promise.all([
    api.systemSettings(),
    api.auditLogs({ module: 'system-settings', page_size: 50 }),
    api.systemActionDefinitions(),
  ])

  return { settings, auditLogs, systemActions }
})

const activeActionKey = ref<SystemActionKey | null>(null)
const activeSettingKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('待操作')
const lastMutationAt = ref('')
const lastActionOutput = ref('')
const lastUpdatedSettingLabel = ref('')
const selectedLogId = ref<number | null>(null)
const settingsKeyword = ref('')
const settingDrafts = reactive<Record<string, string>>({})
const tokenDrafts = reactive<Record<string, string>>({})
const emailSettingsExpanded = ref(true)
const reviewAiSettingsExpanded = ref(true)

const settings = computed<SystemSettingItem[]>(() => data.value?.settings.items ?? [])
const auditLogs = computed<AuditLogItem[]>(() => data.value?.auditLogs.items ?? [])
const systemActions = computed(() => data.value?.systemActions.items ?? [])
const latestSystemAudit = computed(() => auditLogs.value[0] ?? null)
const selectedLog = computed(() => auditLogs.value.find((item) => item.id === selectedLogId.value) ?? null)
const recentAuditLogs = computed(() => auditLogs.value.filter((item) => item.id !== selectedLogId.value).slice(0, 8))
const isMutating = computed(() => activeActionKey.value !== null || activeSettingKey.value !== null)
const settingsKeywordValue = computed(() => settingsKeyword.value.trim().toLowerCase())

const emailToggleSetting = computed(
  () => settings.value.find((item) => item.setting_key === EMAIL_TOGGLE_KEY) ?? null
)
const emailSettings = computed(() =>
  settings.value.filter((item) => EMAIL_SETTING_KEYS.includes(item.setting_key as (typeof EMAIL_SETTING_KEYS)[number]))
)
const reviewAiSettings = computed(() =>
  settings.value.filter((item) => REVIEW_AI_SETTING_KEYS.includes(item.setting_key as (typeof REVIEW_AI_SETTING_KEYS)[number]))
)
const standardSettings = computed(() =>
  settings.value.filter(
    (item) =>
      item.setting_key === EMAIL_TOGGLE_KEY ||
      (
        !EMAIL_SETTING_KEYS.includes(item.setting_key as (typeof EMAIL_SETTING_KEYS)[number]) &&
        !REVIEW_AI_SETTING_KEYS.includes(item.setting_key as (typeof REVIEW_AI_SETTING_KEYS)[number])
      )
  )
)

const filteredStandardSettings = computed(() => {
  const keyword = settingsKeywordValue.value
  if (!keyword) {
    return standardSettings.value
  }

  return standardSettings.value.filter((item) => {
    const label = settingLabel(item).toLowerCase()
    return label.includes(keyword) || item.setting_key.toLowerCase().includes(keyword)
  })
})

const filteredEmailSettings = computed(() => {
  const keyword = settingsKeywordValue.value
  if (!keyword) {
    return emailSettings.value
  }

  return emailSettings.value.filter((item) => {
    const label = settingLabel(item).toLowerCase()
    return label.includes(keyword) || item.setting_key.toLowerCase().includes(keyword)
  })
})

const filteredReviewAiSettings = computed(() => {
  const keyword = settingsKeywordValue.value
  if (!keyword) {
    return reviewAiSettings.value
  }

  return reviewAiSettings.value.filter((item) => {
    const label = settingLabel(item).toLowerCase()
    return label.includes(keyword) || item.setting_key.toLowerCase().includes(keyword)
  })
})

const emailEnabled = computed(() => {
  const draftValue = settingDrafts[EMAIL_TOGGLE_KEY]
  if (draftValue) {
    return draftValue === 'enabled'
  }
  return emailToggleSetting.value?.setting_value === 'enabled'
})

const showEmailSettingsPanel = computed(
  () => emailEnabled.value && (!settingsKeywordValue.value || filteredEmailSettings.value.length > 0)
)
const showReviewAiSettingsPanel = computed(
  () => !settingsKeywordValue.value || filteredReviewAiSettings.value.length > 0
)

const visibleStandardSettings = computed(() => {
  const items = [...filteredStandardSettings.value]
  if (
    showEmailSettingsPanel.value &&
    emailToggleSetting.value &&
    !items.some((item) => item.setting_key === EMAIL_TOGGLE_KEY)
  ) {
    items.unshift(emailToggleSetting.value)
  }
  return items
})

const visibleSettingCount = computed(
  () =>
    visibleStandardSettings.value.length +
    (showReviewAiSettingsPanel.value ? 1 : 0) +
    (showEmailSettingsPanel.value ? 1 : 0)
)

const syncTone = computed<Tone>(() => {
  if (syncState.value === 'saved') {
    return 'safe'
  }
  if (syncState.value === 'error') {
    return 'danger'
  }
  return 'info'
})

const syncLabel = computed(() => {
  if (syncState.value === 'saving') {
    return '处理中'
  }
  if (syncState.value === 'saved') {
    return '已完成'
  }
  if (syncState.value === 'error') {
    return '失败'
  }
  return '待操作'
})

const statusItems = computed(
  () =>
    [
      {
        label: '状态',
        value: syncLabel.value,
        meta: lastMutationAt.value ? `最近操作 ${lastMutationAt.value}` : '北京时间',
        tone: syncTone.value,
      },
      {
        label: '设置',
        value: `${settings.value.length} 项`,
        meta: lastUpdatedSettingLabel.value ? `最近更新 ${lastUpdatedSettingLabel.value}` : '自动保存',
        tone: lastUpdatedSettingLabel.value ? ('safe' as Tone) : ('info' as Tone),
      },
      {
        label: '审计',
        value: `${auditLogs.value.length} 条`,
        meta: latestSystemAudit.value ? latestSystemAudit.value.created_at : '仅显示系统设置记录',
        tone: 'warn' as Tone,
      },
    ] as Array<{ label: string; value: string; meta: string; tone: Tone }>
)

watch(
  settings,
  (items) => {
    for (const item of items) {
      if (activeSettingKey.value !== item.setting_key) {
        settingDrafts[item.setting_key] = item.setting_value
      }
      if (!(item.setting_key in tokenDrafts)) {
        tokenDrafts[item.setting_key] = ''
      }
    }
  },
  { immediate: true }
)

watch(
  emailEnabled,
  (enabled) => {
    emailSettingsExpanded.value = enabled
  },
  { immediate: true }
)

watch(
  auditLogs,
  (items) => {
    if (!items.length) {
      selectedLogId.value = null
      return
    }

    if (!selectedLogId.value || !items.some((item) => item.id === selectedLogId.value)) {
      selectedLogId.value = items[0].id
    }
  },
  { immediate: true }
)

function settingLabel(item: SystemSettingItem) {
  return item.description
}

function fieldMeta(item: SystemSettingItem) {
  return item.field_meta ?? FALLBACK_FIELD_META
}

function fieldOptions(item: SystemSettingItem) {
  return fieldMeta(item).options ?? []
}

function fieldHelper(item: SystemSettingItem) {
  return fieldMeta(item).helper_text || ''
}

function optionLabel(item: SystemSettingItem | null, value?: string) {
  if (!item) {
    return value || '-'
  }
  const currentValue = value ?? settingDrafts[item.setting_key] ?? item.setting_value
  return fieldOptions(item).find((option) => option.value === currentValue)?.label ?? currentValue ?? '-'
}

function isTokenInput(item: SystemSettingItem) {
  return fieldMeta(item).control === 'token-input'
}

function isPasswordInput(item: SystemSettingItem) {
  return fieldMeta(item).control === 'password'
}

function normalizeTokens(value: string) {
  return value
    .split(/[,\n;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
    .filter((item, index, source) => source.indexOf(item) === index)
}

function tokenValues(settingKey: string) {
  return normalizeTokens(settingDrafts[settingKey] ?? '')
}

function displayToken(settingKey: string, token: string) {
  return redactSettingToken(settingKey, token)
}

function displayAuditDetail(value?: string | null) {
  return redactSensitiveText(value)
}

function displayActionOutput(value?: string | null) {
  return redactSensitiveText(value)
}

function setTokenValues(settingKey: string, tokens: string[]) {
  settingDrafts[settingKey] = tokens.join(',')
}

function getSetting(settingKey: string) {
  return settings.value.find((item) => item.setting_key === settingKey) ?? null
}

function settingCurrentValue(settingKey: string) {
  const item = getSetting(settingKey)
  if (!item) {
    return ''
  }
  return settingDrafts[settingKey] ?? item.setting_value
}

function toggleEmailSettingsExpanded() {
  if (!emailEnabled.value) {
    return
  }
  emailSettingsExpanded.value = !emailSettingsExpanded.value
}

function beginAction(actionKey: SystemActionKey, message: string) {
  activeActionKey.value = actionKey
  syncState.value = 'saving'
  syncMessage.value = message
}

function beginSettingSave(settingKey: string, message: string) {
  activeSettingKey.value = settingKey
  syncState.value = 'saving'
  syncMessage.value = message
}

function finishMutation(message: string, options?: { output?: string; settingLabel?: string }) {
  activeActionKey.value = null
  activeSettingKey.value = null
  syncState.value = 'saved'
  syncMessage.value = message
  lastMutationAt.value = formatBeijingTime()
  lastActionOutput.value = options?.output ?? ''

  if (options?.settingLabel) {
    lastUpdatedSettingLabel.value = options.settingLabel
  }
}

function failMutation(message: string) {
  activeActionKey.value = null
  activeSettingKey.value = null
  syncState.value = 'error'
  syncMessage.value = message
}

function prependAuditLog(log: AuditLogItem) {
  if (!data.value || log.module !== 'system-settings') {
    return
  }

  data.value = {
    ...data.value,
    auditLogs: {
      total: data.value.auditLogs.total + 1,
      items: [log, ...data.value.auditLogs.items.filter((item) => item.id !== log.id)].slice(0, 50),
    },
  }
}

function updateLocalSetting(updated: SystemSettingItem) {
  if (!data.value) {
    return
  }

  data.value = {
    ...data.value,
    settings: {
      ...data.value.settings,
      items: data.value.settings.items.map((item) =>
        item.setting_key === updated.setting_key ? updated : item
      ),
    },
  }
}

function actionLabel(actionKey: string) {
  return systemActions.value.find((item) => item.action_key === actionKey)?.action_label ?? ACTION_LABEL_MAP[actionKey] ?? actionKey
}

function actionStatusLabel(actionKey: SystemActionKey) {
  return activeActionKey.value === actionKey ? '执行中' : '可执行'
}

function actionStatusTone(actionKey: SystemActionKey, tone: Tone): Tone {
  return activeActionKey.value === actionKey ? 'info' : tone
}

function settingStatusLabel(settingKey: string) {
  if (activeSettingKey.value === settingKey) {
    return '保存中'
  }

  const current = settings.value.find((item) => item.setting_key === settingKey)
  if (current && lastUpdatedSettingLabel.value === settingLabel(current)) {
    return '已保存'
  }

  return '自动保存'
}

function settingStatusTone(settingKey: string): Tone {
  if (activeSettingKey.value === settingKey) {
    return 'info'
  }

  const current = settings.value.find((item) => item.setting_key === settingKey)
  if (current && lastUpdatedSettingLabel.value === settingLabel(current)) {
    return 'safe'
  }

  return 'info'
}

function moduleLabel(module: string) {
  if (module === 'system-settings') {
    return '系统设置'
  }
  return module
}

function canEdit(settingKey: string) {
  return !isMutating.value || activeSettingKey.value === settingKey
}

const emailSummaryText = computed(() => {
  const templateItem = getSetting('notify_email_template')
  const levelItem = getSetting('notify_email_min_level')
  const recipients = tokenValues('notify_email_recipients').length
  const digestMinutes = settingCurrentValue('notify_email_digest_minutes') || '30'

  return [
    `模板 ${optionLabel(templateItem)}`,
    `阈值 ${optionLabel(levelItem)}`,
    `${digestMinutes} 分钟`,
    recipients ? `${recipients} 个收件人` : '未设收件人',
  ].join(' / ')
})

const reviewAiSummaryText = computed(() => {
  const apiUrl = settingCurrentValue('review_ai_api_url')
  const apiKey = settingCurrentValue('review_ai_api_key')
  const model = settingCurrentValue('review_ai_model') || 'gpt-4.1-mini'
  return [
    apiUrl ? '接口已配置' : '未配置接口',
    apiKey ? '密钥已配置' : '未配置密钥',
    `模型 ${model}`,
  ].join(' / ')
})

function selectAuditLog(logId: number) {
  selectedLogId.value = logId
}

async function saveSetting(settingKey: string) {
  const current = settings.value.find((item) => item.setting_key === settingKey)
  if (!current || activeActionKey.value) {
    return
  }

  const nextValue = settingDrafts[settingKey] ?? ''
  if (nextValue === current.setting_value) {
    return
  }

  const label = settingLabel(current)
  beginSettingSave(settingKey, `正在保存 ${label}`)

  try {
    const result = await api.updateSystemSetting(settingKey, nextValue)
    const updatedLabel = settingLabel(result.setting)

    settingDrafts[settingKey] = result.setting.setting_value
    tokenDrafts[settingKey] = ''
    updateLocalSetting(result.setting)
    prependAuditLog(result.audit_log)
    selectedLogId.value = result.audit_log.id
    finishMutation(`${updatedLabel} 已保存`, { settingLabel: updatedLabel })
  } catch (err) {
    settingDrafts[settingKey] = current.setting_value
    failMutation(err instanceof Error ? err.message : `${label} 保存失败`)
    await refresh()
  }
}

async function appendTokens(settingKey: string) {
  const current = settings.value.find((item) => item.setting_key === settingKey)
  if (!current) {
    return
  }

  const inputTokens = normalizeTokens(tokenDrafts[settingKey] ?? '')
  if (!inputTokens.length) {
    return
  }

  const nextTokens = [...tokenValues(settingKey)]
  let changed = false

  for (const item of inputTokens) {
    if (!nextTokens.includes(item)) {
      nextTokens.push(item)
      changed = true
    }
  }

  tokenDrafts[settingKey] = ''
  if (!changed) {
    return
  }

  setTokenValues(settingKey, nextTokens)
  await saveSetting(settingKey)
}

async function removeToken(settingKey: string, token: string) {
  const nextTokens = tokenValues(settingKey).filter((item) => item !== token)
  setTokenValues(settingKey, nextTokens)
  await saveSetting(settingKey)
}

async function runAction(actionKey: SystemActionKey) {
  const action = systemActions.value.find((item) => item.action_key === actionKey)
  if (!action || activeSettingKey.value) {
    return
  }

  beginAction(actionKey, `正在执行 ${action.action_label}`)

  try {
    const result = await api.runSystemAction(actionKey)
    prependAuditLog(result.audit_log)
    selectedLogId.value = result.audit_log.id
    finishMutation(`${result.action_label} 已完成`, { output: result.output })
  } catch (err) {
    failMutation(err instanceof Error ? err.message : `${action.action_label} 执行失败`)
    await refresh()
  }
}
</script>

<template>
  <section class="page-grid">
    <div v-if="loading" class="empty-state">正在加载系统设置...</div>
    <div v-else-if="error" class="empty-state">
      <p>加载失败：{{ error }}</p>
      <button class="ghost-button" type="button" @click="refresh">重试</button>
    </div>

    <section v-else class="content-grid two-column">
      <div class="page-grid">
        <PageSection eyebrow="动作" title="动作执行区" tag="即时执行" tone="info">
          <template #toolbar>
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>{{ activeActionKey ? actionLabel(activeActionKey) : '系统动作' }}</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${systemActions.length} 项`" tone="info" />
                  <span>{{ latestSystemAudit ? `最近 ${latestSystemAudit.created_at}` : '暂无记录' }}</span>
                </div>
              </div>
              <div class="section-toolbar-actions">
                <button class="ghost-button small" :disabled="isMutating" type="button" @click="refresh">刷新</button>
              </div>
            </div>
          </template>

          <div v-if="systemActions.length" class="action-list action-list-compact">
            <article
              v-for="item in systemActions"
              :key="item.action_key"
              class="action-card action-card-compact action-card-dense"
            >
              <div class="action-card-copy">
                <div class="card-head">
                  <div>
                    <h4>{{ item.action_label }}</h4>
                  </div>
                  <StatusPill
                    :label="actionStatusLabel(item.action_key)"
                    :tone="actionStatusTone(item.action_key, item.tone)"
                  />
                </div>
              </div>
              <button
                class="ghost-button action-card-button"
                :disabled="isMutating"
                type="button"
                @click="runAction(item.action_key)"
              >
                {{ item.button_text }}
              </button>
            </article>
          </div>
          <div v-else class="empty-state">当前没有可执行动作。</div>
        </PageSection>

        <PageSection eyebrow="设置" title="设置编辑区" tag="自动保存" tone="safe">
          <template #toolbar>
            <div class="section-toolbar">
              <div class="section-toolbar-copy">
                <h4>{{ lastUpdatedSettingLabel || '系统参数' }}</h4>
                <div class="section-toolbar-meta">
                  <StatusPill :label="`${visibleSettingCount} / ${settings.length}`" tone="safe" />
                  <span>{{ lastUpdatedSettingLabel ? `最近更新 ${lastUpdatedSettingLabel}` : '修改即保存' }}</span>
                </div>
              </div>
              <div class="section-toolbar-actions">
                <input
                  v-model="settingsKeyword"
                  class="text-input section-toolbar-input"
                  :disabled="isMutating"
                  placeholder="搜索设置"
                  type="text"
                />
              </div>
            </div>
          </template>

          <div v-if="filteredStandardSettings.length || showEmailSettingsPanel" class="settings-form-list settings-form-list-compact">
            <article
              v-for="item in visibleStandardSettings"
              :key="item.setting_key"
              class="settings-form-row settings-form-row-compact"
            >
              <div class="settings-form-copy">
                <div class="card-head">
                  <div>
                    <h4>{{ settingLabel(item) }}</h4>
                    <p v-if="fieldHelper(item)" class="settings-form-helper">{{ fieldHelper(item) }}</p>
                  </div>
                  <StatusPill
                    :label="settingStatusLabel(item.setting_key)"
                    :tone="settingStatusTone(item.setting_key)"
                  />
                </div>
              </div>

              <div class="settings-form-control">
                <select
                  v-if="fieldMeta(item).control === 'select'"
                  v-model="settingDrafts[item.setting_key]"
                  class="select-input settings-form-select"
                  :disabled="!canEdit(item.setting_key)"
                  @change="saveSetting(item.setting_key)"
                >
                  <option
                    v-for="option in fieldOptions(item)"
                    :key="option.value"
                    :value="option.value"
                  >
                    {{ option.label }}
                  </option>
                </select>

                <div
                  v-else-if="isTokenInput(item)"
                  class="settings-token-editor"
                >
                  <div class="input-inline">
                    <input
                      v-model="tokenDrafts[item.setting_key]"
                      class="text-input settings-form-input"
                      :disabled="!canEdit(item.setting_key)"
                      :placeholder="fieldMeta(item).placeholder"
                      type="text"
                      @blur="appendTokens(item.setting_key)"
                      @keydown.enter.prevent="appendTokens(item.setting_key)"
                    />
                    <button
                      class="ghost-button small"
                      :disabled="!canEdit(item.setting_key)"
                      type="button"
                      @click="appendTokens(item.setting_key)"
                    >
                      {{ fieldMeta(item).button_text || '添加' }}
                    </button>
                  </div>

                  <div v-if="tokenValues(item.setting_key).length" class="token-list">
                    <span
                      v-for="token in tokenValues(item.setting_key)"
                      :key="token"
                      class="token-chip"
                    >
                      <span>{{ displayToken(item.setting_key, token) }}</span>
                      <button
                        class="token-chip-remove"
                        :disabled="!canEdit(item.setting_key)"
                        type="button"
                        @click="removeToken(item.setting_key, token)"
                      >
                        x
                      </button>
                    </span>
                  </div>
                  <div v-else class="token-empty">
                    {{ fieldMeta(item).empty_text || '当前未设置' }}
                  </div>
                </div>

                <input
                  v-else
                  v-model="settingDrafts[item.setting_key]"
                  class="text-input settings-form-input"
                  :disabled="!canEdit(item.setting_key)"
                  :placeholder="fieldMeta(item).placeholder"
                  :type="isPasswordInput(item) ? 'password' : 'text'"
                  @blur="saveSetting(item.setting_key)"
                  @keydown.enter.prevent="saveSetting(item.setting_key)"
                />
              </div>
            </article>

            <article
              v-if="showReviewAiSettingsPanel"
              class="settings-dropdown-card"
            >
              <button
                class="settings-dropdown-toggle"
                type="button"
                @click="reviewAiSettingsExpanded = !reviewAiSettingsExpanded"
              >
                <div class="settings-dropdown-copy">
                  <div class="card-head">
                    <div>
                      <h4>辅助研判配置</h4>
                      <p class="settings-form-helper">{{ reviewAiSummaryText }}</p>
                    </div>
                    <StatusPill
                      :label="reviewAiSettingsExpanded ? '已展开' : '已收起'"
                      :tone="settingCurrentValue('review_ai_api_url') && settingCurrentValue('review_ai_api_key') ? 'safe' : 'warn'"
                    />
                  </div>
                </div>
                <span class="settings-dropdown-indicator">{{ reviewAiSettingsExpanded ? '收起' : '展开' }}</span>
              </button>

              <div v-if="reviewAiSettingsExpanded" class="settings-dropdown-body">
                <article
                  v-for="item in filteredReviewAiSettings"
                  :key="item.setting_key"
                  class="settings-form-row settings-form-row-compact settings-form-row-nested"
                >
                  <div class="settings-form-copy">
                    <div class="card-head">
                      <div>
                        <h4>{{ settingLabel(item) }}</h4>
                        <p v-if="fieldHelper(item)" class="settings-form-helper">{{ fieldHelper(item) }}</p>
                      </div>
                      <StatusPill
                        :label="settingStatusLabel(item.setting_key)"
                        :tone="settingStatusTone(item.setting_key)"
                      />
                    </div>
                  </div>

                  <div class="settings-form-control">
                    <select
                      v-if="fieldMeta(item).control === 'select'"
                      v-model="settingDrafts[item.setting_key]"
                      class="select-input settings-form-select"
                      :disabled="!canEdit(item.setting_key)"
                      @change="saveSetting(item.setting_key)"
                    >
                      <option
                        v-for="option in fieldOptions(item)"
                        :key="option.value"
                        :value="option.value"
                      >
                        {{ option.label }}
                      </option>
                    </select>

                    <input
                      v-else
                      v-model="settingDrafts[item.setting_key]"
                      class="text-input settings-form-input"
                      :disabled="!canEdit(item.setting_key)"
                      :placeholder="fieldMeta(item).placeholder"
                      :type="isPasswordInput(item) ? 'password' : 'text'"
                      @blur="saveSetting(item.setting_key)"
                      @keydown.enter.prevent="saveSetting(item.setting_key)"
                    />
                  </div>
                </article>
              </div>
            </article>

            <article
              v-if="showEmailSettingsPanel"
              class="settings-dropdown-card"
            >
              <button
                class="settings-dropdown-toggle"
                :disabled="!emailEnabled"
                type="button"
                @click="toggleEmailSettingsExpanded"
              >
                <div class="settings-dropdown-copy">
                  <div class="card-head">
                    <div>
                      <h4>邮件提醒配置</h4>
                      <p class="settings-form-helper">{{ emailSummaryText }}</p>
                    </div>
                    <StatusPill
                      :label="emailSettingsExpanded ? '已展开' : '已收起'"
                      :tone="emailEnabled ? 'safe' : 'info'"
                    />
                  </div>
                </div>
                <span class="settings-dropdown-indicator">{{ emailSettingsExpanded ? '收起' : '展开' }}</span>
              </button>

              <div v-if="emailSettingsExpanded" class="settings-dropdown-body">
                <article
                  v-for="item in filteredEmailSettings"
                  :key="item.setting_key"
                  class="settings-form-row settings-form-row-compact settings-form-row-nested"
                >
                  <div class="settings-form-copy">
                    <div class="card-head">
                      <div>
                        <h4>{{ settingLabel(item) }}</h4>
                        <p v-if="fieldHelper(item)" class="settings-form-helper">{{ fieldHelper(item) }}</p>
                      </div>
                      <StatusPill
                        :label="settingStatusLabel(item.setting_key)"
                        :tone="settingStatusTone(item.setting_key)"
                      />
                    </div>
                  </div>

                  <div class="settings-form-control">
                    <select
                      v-if="fieldMeta(item).control === 'select'"
                      v-model="settingDrafts[item.setting_key]"
                      class="select-input settings-form-select"
                      :disabled="!canEdit(item.setting_key)"
                      @change="saveSetting(item.setting_key)"
                    >
                      <option
                        v-for="option in fieldOptions(item)"
                        :key="option.value"
                        :value="option.value"
                      >
                        {{ option.label }}
                      </option>
                    </select>

                    <div
                      v-else-if="isTokenInput(item)"
                      class="settings-token-editor"
                    >
                      <div class="input-inline">
                        <input
                          v-model="tokenDrafts[item.setting_key]"
                          class="text-input settings-form-input"
                          :disabled="!canEdit(item.setting_key)"
                          :placeholder="fieldMeta(item).placeholder"
                          type="text"
                          @blur="appendTokens(item.setting_key)"
                          @keydown.enter.prevent="appendTokens(item.setting_key)"
                        />
                        <button
                          class="ghost-button small"
                          :disabled="!canEdit(item.setting_key)"
                          type="button"
                          @click="appendTokens(item.setting_key)"
                        >
                          {{ fieldMeta(item).button_text || '添加' }}
                        </button>
                      </div>

                      <div v-if="tokenValues(item.setting_key).length" class="token-list">
                        <span
                          v-for="token in tokenValues(item.setting_key)"
                          :key="token"
                          class="token-chip"
                        >
                          <span>{{ displayToken(item.setting_key, token) }}</span>
                          <button
                            class="token-chip-remove"
                            :disabled="!canEdit(item.setting_key)"
                            type="button"
                            @click="removeToken(item.setting_key, token)"
                          >
                            x
                          </button>
                        </span>
                      </div>
                      <div v-else class="token-empty">
                        {{ fieldMeta(item).empty_text || '当前未设置' }}
                      </div>
                    </div>

                    <input
                      v-else
                      v-model="settingDrafts[item.setting_key]"
                      class="text-input settings-form-input"
                      :disabled="!canEdit(item.setting_key)"
                      :placeholder="fieldMeta(item).placeholder"
                      :type="isPasswordInput(item) ? 'password' : 'text'"
                      @blur="saveSetting(item.setting_key)"
                      @keydown.enter.prevent="saveSetting(item.setting_key)"
                    />
                  </div>
                </article>
              </div>
            </article>
          </div>
          <div v-else class="empty-state">当前没有匹配的设置项。</div>
        </PageSection>
      </div>

      <PageSection eyebrow="审计" title="审计回显区" tag="系统设置" tone="warn">
        <template #toolbar>
          <div class="section-toolbar">
            <div class="section-toolbar-copy">
              <h4>{{ selectedLog ? actionLabel(selectedLog.action) : '审计回显' }}</h4>
              <div class="section-toolbar-meta">
                <StatusPill :label="`${auditLogs.length} 条`" tone="warn" />
                <span>{{ selectedLog ? selectedLog.created_at : '暂无记录' }}</span>
              </div>
            </div>
          </div>
        </template>

        <article v-if="selectedLog" class="info-card audit-focus-card audit-focus-card-dense">
          <div class="card-head">
            <div>
              <h4>{{ actionLabel(selectedLog.action) }}</h4>
              <p class="card-subtitle">{{ selectedLog.created_at }}</p>
            </div>
            <div class="audit-focus-tags">
              <StatusPill :label="moduleLabel(selectedLog.module)" tone="warn" />
              <StatusPill label="当前" tone="info" />
            </div>
          </div>
          <p class="audit-focus-detail">{{ displayAuditDetail(selectedLog.detail) }}</p>
          <p v-if="lastActionOutput" class="settings-form-helper">输出：{{ displayActionOutput(lastActionOutput) }}</p>
        </article>
        <div v-else class="empty-state">当前没有可查看的审计日志。</div>

        <div v-if="recentAuditLogs.length" class="audit-log-list audit-log-list-compact audit-log-list-dense">
          <button
            v-for="item in recentAuditLogs"
            :key="item.id"
            :class="[
              'audit-log-button',
              'audit-log-button-compact',
              'audit-log-button-dense',
              { active: item.id === selectedLogId },
            ]"
            type="button"
            @click="selectAuditLog(item.id)"
          >
            <div class="card-head">
              <div>
                <h4>{{ actionLabel(item.action) }}</h4>
                <p class="card-subtitle">{{ item.created_at }}</p>
              </div>
              <StatusPill :label="moduleLabel(item.module)" tone="warn" />
            </div>
            <p>{{ displayAuditDetail(item.detail) }}</p>
          </button>
        </div>
      </PageSection>
    </section>
  </section>
</template>
