<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import AiScopeBanner from '../components/AiScopeBanner.vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import TopStatusRail from '../components/TopStatusRail.vue'
import { useAsyncData } from '../composables/useAsyncData'
import { useRoute } from 'vue-router'
import {
  api,
  type AiEndpointMcpPolicyProfile,
  type McpApprovalMode,
  type McpCapabilityPolicyItem,
  type McpCapabilitySuggestion,
  type McpPolicyTemplateItem,
  type McpRiskLevel,
  type McpScopeOption,
  type McpServerPolicyItem,
  type McpServerSuggestion,
  type McpTrustMode,
} from '../services/api'
import { formatBeijingTime } from '../services/time'

type Tone = 'safe' | 'warn' | 'danger' | 'info'
type SyncState = 'idle' | 'saving' | 'saved' | 'error'

type EditableMcpServer = {
  server_name: string
  server_label: string
  enabled: boolean
  trust_mode: McpTrustMode
  require_ticket: boolean
  require_approval: boolean
  allowed_scopes: string[]
  scopeDraft: string
}

type EditableMcpCapability = {
  server_name: string
  capability_name: string
  capability_label: string
  enabled: boolean
  risk_level: McpRiskLevel
  approval_mode: McpApprovalMode
  allowed_scopes: string[]
  scopeDraft: string
}

const route = useRoute()

const endpointId = computed(() => {
  const parsed = Number(route.params.endpointId)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null
})

const detailRoute = computed(() => {
  if (!endpointId.value) {
    return { name: 'ai-endpoints' }
  }
  return {
    name: 'ai-endpoints-detail',
    params: {
      endpointId: String(endpointId.value),
    },
  }
})

const { data, loading, error, refresh } = useAsyncData(async () => {
  if (!endpointId.value) {
    throw new Error('缺少 AI 目标 ID')
  }
  return api.aiEndpointMcpPolicy(endpointId.value)
}, false)

const servers = ref<EditableMcpServer[]>([])
const capabilities = ref<EditableMcpCapability[]>([])
const activeActionKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('等待操作')
const lastSavedAt = ref('')

const profile = computed<AiEndpointMcpPolicyProfile | null>(() => data.value ?? null)
const templates = computed<McpPolicyTemplateItem[]>(() => profile.value?.templates ?? [])
const scopeOptions = computed<McpScopeOption[]>(() => profile.value?.catalog.scope_options ?? [])
const serverSuggestions = computed<McpServerSuggestion[]>(() => profile.value?.catalog.server_suggestions ?? [])
const capabilitySuggestions = computed<McpCapabilitySuggestion[]>(() => profile.value?.catalog.capability_suggestions ?? [])
const matchedTemplate = computed(
  () => templates.value.find((item) => item.key === profile.value?.policy_summary.matched_template_key) ?? null
)

const trustModeOptions: Array<{ value: McpTrustMode; label: string }> = [
  { value: 'trusted', label: '可信' },
  { value: 'restricted', label: '受限' },
  { value: 'blocked', label: '阻断' },
]

const approvalModeOptions: Array<{ value: McpApprovalMode; label: string }> = [
  { value: 'inherit', label: '继承 Server' },
  { value: 'required', label: '必须审批' },
  { value: 'deny', label: '直接拒绝' },
]

const riskLevelOptions: Array<{ value: McpRiskLevel; label: string }> = [
  { value: 'low', label: '低风险' },
  { value: 'medium', label: '中风险' },
  { value: 'high', label: '高风险' },
]

const railItems = computed(() => {
  const summary = profile.value?.policy_summary
  return [
    {
      label: '当前模式',
      value: summary?.effective_mode === 'strict_allowlist' ? '严格白名单' : '兼容模式',
      tone: summary?.effective_mode === 'strict_allowlist' ? ('warn' as Tone) : ('info' as Tone),
      meta: summary?.compatibility_note || '按目标单独维护 MCP 策略',
    },
    {
      label: '专属规则',
      value: `${servers.value.length} / ${capabilities.value.length}`,
      tone: servers.value.length || capabilities.value.length ? ('safe' as Tone) : ('info' as Tone),
      meta: 'Server / Capability',
    },
    {
      label: '继承全局',
      value: summary?.inherits_global_defaults ? '是' : '否',
      tone: summary?.inherits_global_defaults ? ('info' as Tone) : ('warn' as Tone),
      meta: `全局 ${summary?.global_server_count ?? 0} / ${summary?.global_capability_count ?? 0}`,
    },
    {
      label: '预定义策略',
      value: matchedTemplate.value?.label || '自定义',
      tone: matchedTemplate.value ? ('safe' as Tone) : ('info' as Tone),
      meta: matchedTemplate.value?.description || '可先套模板，再细调',
    },
  ]
})

const syncTone = computed<Tone>(() => {
  if (syncState.value === 'saved') {
    return 'safe'
  }
  if (syncState.value === 'error') {
    return 'danger'
  }
  if (syncState.value === 'saving') {
    return 'warn'
  }
  return 'info'
})

function createEmptyServer(seed?: Partial<EditableMcpServer>): EditableMcpServer {
  return {
    server_name: seed?.server_name || '',
    server_label: seed?.server_label || '',
    enabled: seed?.enabled ?? true,
    trust_mode: seed?.trust_mode || 'trusted',
    require_ticket: seed?.require_ticket ?? true,
    require_approval: seed?.require_approval ?? false,
    allowed_scopes: dedupeStrings(seed?.allowed_scopes || []),
    scopeDraft: '',
  }
}

function createEmptyCapability(seed?: Partial<EditableMcpCapability>): EditableMcpCapability {
  return {
    server_name: seed?.server_name || '*',
    capability_name: seed?.capability_name || '',
    capability_label: seed?.capability_label || '',
    enabled: seed?.enabled ?? true,
    risk_level: seed?.risk_level || 'medium',
    approval_mode: seed?.approval_mode || 'inherit',
    allowed_scopes: dedupeStrings(seed?.allowed_scopes || []),
    scopeDraft: '',
  }
}

function hydrateEditors(nextProfile: AiEndpointMcpPolicyProfile) {
  servers.value = nextProfile.servers.map((item) =>
    createEmptyServer({
      server_name: item.server_name,
      server_label: item.server_label,
      enabled: item.enabled,
      trust_mode: item.trust_mode,
      require_ticket: item.require_ticket,
      require_approval: item.require_approval,
      allowed_scopes: item.allowed_scopes,
    })
  )
  capabilities.value = nextProfile.capabilities.map((item) =>
    createEmptyCapability({
      server_name: item.server_name,
      capability_name: item.capability_name,
      capability_label: item.capability_label,
      enabled: item.enabled,
      risk_level: item.risk_level,
      approval_mode: item.approval_mode,
      allowed_scopes: item.allowed_scopes,
    })
  )
}

watch(
  endpointId,
  () => {
    void refresh()
  },
  { immediate: true }
)

watch(
  data,
  (value) => {
    if (!value) {
      return
    }
    hydrateEditors(value)
  },
  { immediate: true }
)

function beginAction(key: string, message: string) {
  activeActionKey.value = key
  syncState.value = 'saving'
  syncMessage.value = message
}

function finishAction(message: string) {
  activeActionKey.value = null
  syncState.value = 'saved'
  syncMessage.value = message
  lastSavedAt.value = formatBeijingTime(new Date())
}

function failAction(errorValue: unknown) {
  activeActionKey.value = null
  syncState.value = 'error'
  syncMessage.value = errorValue instanceof Error ? errorValue.message : '操作失败'
}

function dedupeStrings(values: string[]) {
  const items: string[] = []
  const seen = new Set<string>()
  for (const value of values) {
    const normalized = String(value || '').trim()
    if (!normalized) {
      continue
    }
    const lowered = normalized.toLowerCase()
    if (seen.has(lowered)) {
      continue
    }
    seen.add(lowered)
    items.push(normalized)
  }
  return items
}

function addServer(seed?: Partial<EditableMcpServer>) {
  servers.value = [...servers.value, createEmptyServer(seed)]
}

function addCapability(seed?: Partial<EditableMcpCapability>) {
  capabilities.value = [...capabilities.value, createEmptyCapability(seed)]
}

function upsertServerFromSuggestion(item: McpServerSuggestion) {
  const existing = servers.value.find((server) => server.server_name.toLowerCase() === item.server_name.toLowerCase())
  if (existing) {
    existing.server_label = existing.server_label || item.server_label
    existing.allowed_scopes = dedupeStrings([...existing.allowed_scopes, ...item.suggested_scopes])
    return
  }
  addServer({
    server_name: item.server_name,
    server_label: item.server_label,
    trust_mode: item.server_name === 'shell' ? 'restricted' : 'trusted',
    require_ticket: true,
    require_approval: item.server_name === 'shell',
    allowed_scopes: item.suggested_scopes,
  })
}

function upsertCapabilityFromSuggestion(item: McpCapabilitySuggestion) {
  const existing = capabilities.value.find(
    (capability) =>
      capability.server_name.toLowerCase() === item.server_name.toLowerCase() &&
      capability.capability_name.toLowerCase() === item.capability_name.toLowerCase()
  )
  if (existing) {
    existing.capability_label = existing.capability_label || item.capability_label
    existing.allowed_scopes = dedupeStrings([...existing.allowed_scopes, ...item.suggested_scopes])
    existing.risk_level = item.risk_level
    existing.approval_mode = item.approval_mode
    return
  }
  addCapability({
    server_name: item.server_name,
    capability_name: item.capability_name,
    capability_label: item.capability_label,
    risk_level: item.risk_level,
    approval_mode: item.approval_mode,
    allowed_scopes: item.suggested_scopes,
  })
}

function removeServer(index: number) {
  servers.value = servers.value.filter((_, currentIndex) => currentIndex !== index)
}

function removeCapability(index: number) {
  capabilities.value = capabilities.value.filter((_, currentIndex) => currentIndex !== index)
}

function addScope(
  target: { allowed_scopes: string[]; scopeDraft: string },
  explicitValue?: string,
) {
  const value = String(explicitValue ?? target.scopeDraft ?? '').trim()
  if (!value) {
    return
  }
  target.allowed_scopes = dedupeStrings([...target.allowed_scopes, value])
  target.scopeDraft = ''
}

function removeScope(target: { allowed_scopes: string[] }, value: string) {
  target.allowed_scopes = target.allowed_scopes.filter((item) => item !== value)
}

function scopeTone(riskLevel: McpRiskLevel): Tone {
  if (riskLevel === 'high') {
    return 'danger'
  }
  if (riskLevel === 'medium') {
    return 'warn'
  }
  return 'info'
}

function templateTone(item: McpPolicyTemplateItem): Tone {
  return item.recommended ? 'safe' : 'info'
}

function normalizePayloadServer(item: EditableMcpServer): McpServerPolicyItem {
  return {
    server_name: item.server_name.trim(),
    server_label: item.server_label.trim(),
    enabled: item.enabled,
    trust_mode: item.trust_mode,
    require_ticket: item.require_ticket,
    require_approval: item.require_approval,
    allowed_scopes: dedupeStrings(item.allowed_scopes),
  }
}

function normalizePayloadCapability(item: EditableMcpCapability): McpCapabilityPolicyItem {
  return {
    server_name: item.server_name.trim() || '*',
    capability_name: item.capability_name.trim(),
    capability_label: item.capability_label.trim(),
    enabled: item.enabled,
    risk_level: item.risk_level,
    approval_mode: item.approval_mode,
    allowed_scopes: dedupeStrings(item.allowed_scopes),
  }
}

async function refreshProfile() {
  beginAction('refresh-mcp-policy', '正在刷新 MCP 策略...')
  try {
    await refresh()
    if (error.value) {
      throw new Error(error.value)
    }
    finishAction('MCP 策略已刷新')
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function savePolicy() {
  if (!endpointId.value) {
    syncState.value = 'error'
    syncMessage.value = '缺少 AI 目标 ID'
    return
  }

  beginAction('save-mcp-policy', '正在保存当前 AI 目标的 MCP 策略...')
  try {
    const nextProfile = await api.updateAiEndpointMcpPolicy(endpointId.value, {
      servers: servers.value
        .map(normalizePayloadServer)
        .filter((item) => item.server_name),
      capabilities: capabilities.value
        .map(normalizePayloadCapability)
        .filter((item) => item.capability_name),
    })
    data.value = nextProfile
    hydrateEditors(nextProfile)
    finishAction('MCP 策略已保存')
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function applyTemplate(item: McpPolicyTemplateItem) {
  if (!endpointId.value) {
    syncState.value = 'error'
    syncMessage.value = '缺少 AI 目标 ID'
    return
  }

  const confirmed = window.confirm(`确认将当前目标的 MCP 策略切换为“${item.label}”吗？现有专属规则会被覆盖。`)
  if (!confirmed) {
    return
  }

  beginAction(`apply-template-${item.key}`, `正在套用 ${item.label}...`)
  try {
    const nextProfile = await api.applyAiEndpointMcpPolicyTemplate(endpointId.value, item.key)
    data.value = nextProfile
    hydrateEditors(nextProfile)
    finishAction(`已套用 ${item.label}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}
</script>

<template>
  <div class="page-grid scoped-ai-page mcp-policy-page">
    <TopStatusRail
      title="MCP 策略"
      summary=""
      :items="railItems"
      :status-label="syncState === 'saving' ? '处理中' : syncState === 'saved' ? '已更新' : syncState === 'error' ? '失败' : '就绪'"
      :status-tone="syncTone"
      :meta="`${syncMessage}${lastSavedAt ? ` / ${lastSavedAt}` : ''}`"
    >
      <template #actions>
        <RouterLink class="ghost-button small" :to="detailRoute">返回目标</RouterLink>
        <button class="ghost-button small" type="button" :disabled="loading || activeActionKey !== null" @click="refreshProfile">
          刷新
        </button>
        <button class="primary-button small" type="button" :disabled="activeActionKey !== null" @click="savePolicy">
          保存策略
        </button>
      </template>
    </TopStatusRail>

    <AiScopeBanner v-if="endpointId" :endpoint-id="endpointId" />

    <template v-if="profile && !error">
    <PageSection eyebrow="模板" title="预定义策略" :tag="`${templates.length} 套`" tone="info">
      <div class="mcp-template-grid">
        <article
          v-for="item in templates"
          :key="item.key"
          :class="['mcp-template-card', { active: matchedTemplate?.key === item.key }]"
        >
          <div class="mcp-template-head">
            <div>
              <strong>{{ item.label }}</strong>
              <p>{{ item.description }}</p>
            </div>
            <StatusPill :label="item.recommended ? '推荐' : '可选'" :tone="templateTone(item)" />
          </div>
          <div class="mcp-template-meta">
            <span>Server {{ item.server_count }}</span>
            <span>Capability {{ item.capability_count }}</span>
          </div>
          <div class="table-actions wrap">
            <button class="primary-button small" type="button" :disabled="activeActionKey !== null" @click="applyTemplate(item)">
              套用模板
            </button>
          </div>
        </article>
      </div>
    </PageSection>

    <PageSection eyebrow="Server" title="允许的 MCP Server" :tag="`${servers.length} 条`" tone="warn">
      <div class="mcp-policy-toolbar">
        <div class="sample-preview-tags">
          <button class="token-chip as-button" type="button" @click="addServer()">新增空白 Server</button>
          <button
            v-for="item in serverSuggestions"
            :key="item.server_name"
            class="token-chip as-button"
            type="button"
            @click="upsertServerFromSuggestion(item)"
          >
            {{ item.server_label }}
          </button>
        </div>
        <p class="section-toolbar-note">
          当前页只保存这个 AI 目标自己的 MCP Server 白名单。留空时会继承全局默认，若全局也为空则保持兼容模式。
        </p>
      </div>

      <div v-if="!servers.length" class="empty-state">
        <p>当前还没有专属 MCP Server 规则，可直接套模板或手动新增。</p>
      </div>

      <div v-else class="mcp-editor-list">
        <article v-for="(item, index) in servers" :key="`server-${index}`" class="mcp-editor-card">
          <div class="mcp-editor-grid">
            <input v-model="item.server_name" class="text-input" type="text" placeholder="server_name，例如 filesystem" />
            <input v-model="item.server_label" class="text-input" type="text" placeholder="显示名称" />
            <select v-model="item.trust_mode" class="select-input">
              <option v-for="option in trustModeOptions" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
          </div>

          <div class="mcp-check-row">
            <label class="mcp-check">
              <input v-model="item.enabled" type="checkbox" />
              <span>启用</span>
            </label>
            <label class="mcp-check">
              <input v-model="item.require_ticket" type="checkbox" />
              <span>要求 Ticket</span>
            </label>
            <label class="mcp-check">
              <input v-model="item.require_approval" type="checkbox" />
              <span>要求审批</span>
            </label>
          </div>

          <div class="mcp-scope-editor">
            <div class="token-list">
              <span v-for="scope in item.allowed_scopes" :key="scope" class="token-chip">
                {{ scope }}
                <button type="button" @click="removeScope(item, scope)">×</button>
              </span>
            </div>
            <div class="mcp-scope-input-row">
              <input
                v-model="item.scopeDraft"
                class="text-input"
                type="text"
                placeholder="输入 scope，例如 read / workspace.scan"
                @keydown.enter.prevent="addScope(item)"
              />
              <button class="ghost-button small" type="button" @click="addScope(item)">添加 Scope</button>
            </div>
            <div class="sample-preview-tags">
              <button
                v-for="scope in scopeOptions"
                :key="`${item.server_name || index}-${scope.value}`"
                class="token-chip as-button"
                type="button"
                @click="addScope(item, scope.value)"
              >
                {{ scope.value }}
              </button>
            </div>
          </div>

          <div class="mcp-editor-foot">
            <StatusPill :label="item.enabled ? '已启用' : '已停用'" :tone="item.enabled ? 'safe' : 'danger'" />
            <button class="ghost-button small danger" type="button" @click="removeServer(index)">删除</button>
          </div>
        </article>
      </div>
    </PageSection>

    <PageSection eyebrow="Capability" title="允许的 Capability" :tag="`${capabilities.length} 条`" tone="warn">
      <div class="mcp-policy-toolbar">
        <div class="sample-preview-tags">
          <button class="token-chip as-button" type="button" @click="addCapability()">新增空白 Capability</button>
          <button
            v-for="item in capabilitySuggestions"
            :key="`${item.server_name}-${item.capability_name}`"
            class="token-chip as-button"
            type="button"
            @click="upsertCapabilityFromSuggestion(item)"
          >
            {{ item.capability_label }}
          </button>
        </div>
        <p class="section-toolbar-note">
          Capability 名称支持通配符，例如 <code>read_*</code>、<code>write_*</code>。对 OpenClaw 这类接入，建议先用模板再按实际工具名细化。
        </p>
      </div>

      <div v-if="!capabilities.length" class="empty-state">
        <p>当前还没有专属 Capability 规则，可直接从常用建议加入。</p>
      </div>

      <div v-else class="mcp-editor-list">
        <article v-for="(item, index) in capabilities" :key="`capability-${index}`" class="mcp-editor-card">
          <div class="mcp-editor-grid capability">
            <input v-model="item.server_name" class="text-input" type="text" placeholder="所属 Server，留 * 表示通配" />
            <input v-model="item.capability_name" class="text-input" type="text" placeholder="capability_name，例如 shell.exec / read_*" />
            <input v-model="item.capability_label" class="text-input" type="text" placeholder="显示名称" />
            <select v-model="item.risk_level" class="select-input">
              <option v-for="option in riskLevelOptions" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
            <select v-model="item.approval_mode" class="select-input">
              <option v-for="option in approvalModeOptions" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
          </div>

          <div class="mcp-check-row">
            <label class="mcp-check">
              <input v-model="item.enabled" type="checkbox" />
              <span>启用</span>
            </label>
            <StatusPill :label="riskLevelOptions.find((option) => option.value === item.risk_level)?.label || item.risk_level" :tone="scopeTone(item.risk_level)" />
          </div>

          <div class="mcp-scope-editor">
            <div class="token-list">
              <span v-for="scope in item.allowed_scopes" :key="scope" class="token-chip">
                {{ scope }}
                <button type="button" @click="removeScope(item, scope)">×</button>
              </span>
            </div>
            <div class="mcp-scope-input-row">
              <input
                v-model="item.scopeDraft"
                class="text-input"
                type="text"
                placeholder="输入 Capability 允许的 scope"
                @keydown.enter.prevent="addScope(item)"
              />
              <button class="ghost-button small" type="button" @click="addScope(item)">添加 Scope</button>
            </div>
            <div class="sample-preview-tags">
              <button
                v-for="scope in scopeOptions"
                :key="`${item.capability_name || index}-${scope.value}`"
                class="token-chip as-button"
                type="button"
                @click="addScope(item, scope.value)"
              >
                {{ scope.value }}
              </button>
            </div>
          </div>

          <div class="mcp-editor-foot">
            <StatusPill
              :label="approvalModeOptions.find((option) => option.value === item.approval_mode)?.label || item.approval_mode"
              :tone="item.approval_mode === 'deny' ? 'danger' : item.approval_mode === 'required' ? 'warn' : 'info'"
            />
            <button class="ghost-button small danger" type="button" @click="removeCapability(index)">删除</button>
          </div>
        </article>
      </div>
    </PageSection>
    </template>

    <section v-if="loading" class="panel">
      <div class="empty-state">
        <p>正在加载当前 AI 目标的 MCP 策略...</p>
      </div>
    </section>

    <section v-else-if="error" class="panel">
      <div class="empty-state">
        <p>{{ error }}</p>
      </div>
    </section>
  </div>
</template>
