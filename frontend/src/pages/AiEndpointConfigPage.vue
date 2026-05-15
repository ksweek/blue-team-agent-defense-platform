<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import TopStatusRail from '../components/TopStatusRail.vue'
import { useAsyncData } from '../composables/useAsyncData'
import AiEndpointFormPanel from '../features/ai-endpoints/components/AiEndpointFormPanel.vue'
import {
  CONNECTION_MODE_LABELS,
  PROTECTION_MODE_LABELS,
  TARGET_TYPE_LABELS,
  type ProtectionMode,
  type Tone,
} from '../features/ai-endpoints/constants'
import {
  endpointMetaText,
  endpointStatusLabel,
  endpointSummaryText,
  endpointTone,
} from '../features/ai-endpoints/helpers'
import {
  blankEndpointForm,
  buildPayloadFromDrawer,
  fillDrawerForm,
  type EndpointForm,
} from '../features/ai-endpoints/useAiEndpointsPage'
import {
  api,
  type AiEndpointItem,
  type AiReviewMode,
  type AssetItem,
  type DefensePolicyProfile,
  type ManagedRuntimeItem,
  type RuntimeEnrollmentTokenItem,
  type RuntimeRegistrySummary,
  type SkillItem,
} from '../services/api'
import { redactSensitiveText, redactSensitiveValue } from '../services/redaction'
import { formatBeijingTime } from '../services/time'

type SyncState = 'idle' | 'saving' | 'saved' | 'error'

const EMPTY_RUNTIME_SUMMARY: RuntimeRegistrySummary = {
  tokens_total: 0,
  tokens_active: 0,
  runtimes_total: 0,
  runtimes_pending: 0,
  runtimes_activation_requested: 0,
  runtimes_activation_issued: 0,
  runtimes_approved: 0,
  runtimes_active: 0,
  tokens_unbound: 0,
  runtimes_unbound: 0,
  runtimes_online: 0,
}

const route = useRoute()
const router = useRouter()

const endpointId = computed(() => {
  const parsed = Number(route.params.endpointId)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null
})
const createMode = computed(() => route.name === 'ai-endpoints-create' || endpointId.value === null)

const { data, loading, error, refresh } = useAsyncData(
  async () => {
    const resolvedEndpointId = endpointId.value
    const [endpoints, runtimeRegistry, assets, skills, policy] = await Promise.all([
      api.aiEndpoints(),
      api.runtimeRegistry(),
      api.assets(),
      resolvedEndpointId ? api.skills({ page_size: 100, scan_task_page_size: 8, ai_endpoint_id: resolvedEndpointId }) : Promise.resolve(null),
      resolvedEndpointId ? api.defensePolicy(resolvedEndpointId) : Promise.resolve(null),
    ])
    return { endpoints, runtimeRegistry, assets, skills, policy }
  },
  false
)

const form = reactive<EndpointForm>(blankEndpointForm('default', 0))
const activeActionKey = ref<string | null>(null)
const syncState = ref<SyncState>('idle')
const syncMessage = ref('等待操作')
const lastActionAt = ref('')
const testOutput = ref('')
const testUsage = ref<Record<string, unknown> | null>(null)
const runtimeTokenLabel = ref('')
const runtimeTokenType = ref('agent')
const runtimeTokenUsageLimit = ref(1)
const runtimeTokenExpiresAt = ref('')
const latestActivationCode = ref('')
const latestLegacyEnrollmentToken = ref('')
const latestEnrollmentToken = latestActivationCode
const latestEnrollmentSteps = ref<string[]>([])
const latestTokenLabelSeed = ref('')
const protectedPathDraft = ref('')
const protectedSkillDraft = ref('')
const protectedPluginDraft = ref('')
const selectedSkillIds = ref<number[]>([])
const skillCreateForm = reactive({
  skill_name: '',
  skill_type: 'local',
  provider: 'manual',
  source_path: '',
  trust_status: 'pending',
})
const skillImportForm = reactive({
  directory_path: '',
  skill_type: 'local',
  provider: 'imported',
  trust_status: 'pending',
  recursive: true,
})

const endpointItems = computed<AiEndpointItem[]>(() => data.value?.endpoints.items ?? [])
const runtimeSummary = computed<RuntimeRegistrySummary>(() => data.value?.runtimeRegistry.summary ?? EMPTY_RUNTIME_SUMMARY)
const runtimeTokens = computed<RuntimeEnrollmentTokenItem[]>(() => data.value?.runtimeRegistry.tokens ?? [])
const runtimeItems = computed<ManagedRuntimeItem[]>(() => data.value?.runtimeRegistry.runtimes ?? [])
const policyProfile = computed<DefensePolicyProfile | null>(() => data.value?.policy ?? null)
const skillItems = computed<SkillItem[]>(() => data.value?.skills?.items ?? [])
const skillResultItems = computed(() => data.value?.skills?.result_meta?.lists?.[0]?.items ?? [])
const assetItems = computed<AssetItem[]>(() => data.value?.assets.items ?? [])
const selectedEndpoint = computed(
  () => (createMode.value ? null : endpointItems.value.find((item) => item.id === endpointId.value) ?? null)
)
const attackTestingRoute = computed(() => {
  if (!selectedEndpoint.value) {
    return { name: 'attack-testing' }
  }
  return {
    name: 'attack-testing',
    query: {
      ai_endpoint_id: String(selectedEndpoint.value.id),
    },
  }
})
const mcpPolicyRoute = computed(() => {
  if (!selectedEndpoint.value) {
    return { name: 'ai-endpoints' }
  }
  return {
    name: 'ai-endpoints-mcp-policy',
    params: {
      endpointId: String(selectedEndpoint.value.id),
    },
  }
})
const selectedEndpointTokens = computed(() => {
  const resolvedId = selectedEndpoint.value?.id
  if (!resolvedId) {
    return []
  }
  return runtimeTokens.value.filter((item) => item.ai_endpoint?.id === resolvedId)
})
const selectedEndpointRuntimes = computed(() => {
  const resolvedId = selectedEndpoint.value?.id
  if (!resolvedId) {
    return []
  }
  return runtimeItems.value.filter((item) => item.ai_endpoint?.id === resolvedId)
})
const unboundTokens = computed(() => runtimeTokens.value.filter((item) => item.ai_endpoint?.id == null))
const unboundRuntimes = computed(() => runtimeItems.value.filter((item) => item.ai_endpoint?.id == null))
const selectedEndpointIntegration = computed(() => selectedEndpoint.value?.integration_view ?? null)
const isBusy = computed(() => activeActionKey.value !== null)
const aiReviewMode = computed<AiReviewMode>(() => policyProfile.value?.ai_review_policy.mode ?? 'rules_only')
const protectedPaths = computed(() => policyProfile.value?.protected_paths ?? [])
const protectedSkills = computed(() => policyProfile.value?.protected_skills ?? [])
const protectedPlugins = computed(() => policyProfile.value?.protected_plugins ?? [])
const sensitivePathAssets = computed(() =>
  assetItems.value.filter((item) => item.asset_type === 'path' && item.status !== 'disabled')
)
const pendingSkillCount = computed(() => skillItems.value.filter((item) => item.trust_status === 'pending').length)
const selectedSkillCount = computed(() => selectedSkillIds.value.length)
const skillScanTargetIds = computed(() => selectedSkillIds.value.length ? selectedSkillIds.value : skillItems.value.map((item) => item.id))

const reviewModeOptions: Array<{ value: AiReviewMode; label: string }> = [
  { value: 'rules_only', label: '规则直断' },
  { value: 'suspicious_review', label: '疑似研判' },
  { value: 'review_all_remaining', label: '剩余全审' },
]

function targetTypeLabel(item?: AiEndpointItem | null, fallbackType: EndpointForm['target_type'] = form.target_type) {
  if (item?.target_label) {
    return item.target_label
  }
  return TARGET_TYPE_LABELS[fallbackType as 'openclaw_control' | 'standard_api'] ?? 'OpenClaw 受保护目标'
}

function connectionModeLabel(mode?: string) {
  return CONNECTION_MODE_LABELS[String(mode || '')] ?? 'Runtime 桥接'
}

const isOpenClawEndpoint = computed(() => selectedEndpoint.value?.target_type === 'openclaw_control')

const railItems = computed(() => {
  if (!selectedEndpoint.value) {
    return [
      {
        label: '接入协议',
        value: targetTypeLabel(),
        tone: 'info' as Tone,
        meta: '先填写上游信息',
      },
      {
        label: '默认路由',
        value: form.is_default ? '准备设置' : '未启用',
        tone: form.is_default ? ('safe' as Tone) : ('info' as Tone),
        meta: '创建成功后立即生效',
      },
      {
        label: 'Runtime',
        value: '0',
        tone: 'info' as Tone,
        meta: '创建后可再绑定客户端',
      },
      {
        label: '注册码',
        value: '0',
        tone: 'info' as Tone,
        meta: '创建后按需签发',
      },
    ]
  }

  return [
    {
      label: '接入协议',
        value: targetTypeLabel(selectedEndpoint.value),
      tone: 'info' as Tone,
        meta: connectionModeLabel(selectedEndpoint.value.connection_mode),
    },
    {
      label: '默认路由',
      value: selectedEndpoint.value.is_default ? '已启用' : '未启用',
      tone: selectedEndpoint.value.is_default ? ('safe' as Tone) : ('info' as Tone),
      meta: selectedEndpoint.value.endpoint_group,
    },
    {
      label: 'Runtime',
      value: String(selectedEndpoint.value.usage_summary.runtime_count),
      tone: selectedEndpoint.value.usage_summary.runtime_online_count ? ('safe' as Tone) : ('warn' as Tone),
      meta: `在线 ${selectedEndpoint.value.usage_summary.runtime_online_count}`,
    },
    {
      label: '注册码',
      value: String(selectedEndpoint.value.usage_summary.token_count),
      tone: selectedEndpoint.value.usage_summary.token_count ? ('warn' as Tone) : ('info' as Tone),
      meta: selectedEndpoint.value.usage_summary.last_runtime_seen_at || '暂无最近心跳',
    },
  ]
})

const pageTitle = computed(() =>
  createMode.value ? '新增目标' : selectedEndpoint.value?.display_name || '目标配置'
)
const pageSummary = computed(() => {
  if (createMode.value) {
    return '新增接入目标。'
  }
  if (!selectedEndpoint.value) {
    return '正在定位指定目标。'
  }
  return `${endpointSummaryText(selectedEndpoint.value)} / ${endpointMetaText(selectedEndpoint.value)}`
})
const statusLabel = computed(() => {
  if (syncState.value === 'saving') return '处理中'
  if (syncState.value === 'saved') return '已同步'
  if (syncState.value === 'error') return '失败'
  if (selectedEndpoint.value) return endpointStatusLabel(selectedEndpoint.value)
  return '就绪'
})
const statusTone = computed<Tone>(() => {
  if (syncState.value === 'saving') return 'warn'
  if (syncState.value === 'saved') return 'safe'
  if (syncState.value === 'error') return 'danger'
  return selectedEndpoint.value ? endpointTone(selectedEndpoint.value) : 'info'
})

watch(
  () => [route.name, route.params.endpointId] as const,
  () => {
    clearTestResult()
    latestActivationCode.value = ''
    latestLegacyEnrollmentToken.value = ''
    latestEnrollmentSteps.value = []
    void refreshPage().catch((errorValue) => {
      failAction(errorValue)
    })
  },
  { immediate: true }
)

watch(
  [createMode, endpointItems],
  ([isCreate, items]) => {
    if (!isCreate) {
      return
    }
    Object.assign(form, blankEndpointForm('default', items.length))
  },
  { immediate: true }
)

watch(
  selectedEndpoint,
  (item) => {
    if (!item) {
      return
    }
    fillDrawerForm(form, item)
    const nextDefaultLabel = `${item.display_name} 客户端注册码`
    if (!runtimeTokenLabel.value.trim() || runtimeTokenLabel.value === latestTokenLabelSeed.value) {
      runtimeTokenLabel.value = nextDefaultLabel
    }
    latestTokenLabelSeed.value = nextDefaultLabel
  },
  { immediate: true }
)

watch(skillItems, (items) => {
  const availableIds = new Set(items.map((item) => item.id))
  selectedSkillIds.value = selectedSkillIds.value.filter((id) => availableIds.has(id))
})

function clearTestResult() {
  testOutput.value = ''
  testUsage.value = null
}

function beginAction(key: string, message: string) {
  activeActionKey.value = key
  syncState.value = 'saving'
  syncMessage.value = redactSensitiveText(message)
}

function finishAction(message: string) {
  activeActionKey.value = null
  syncState.value = 'saved'
  syncMessage.value = redactSensitiveText(message)
  lastActionAt.value = formatBeijingTime(new Date())
}

function failAction(errorValue: unknown) {
  activeActionKey.value = null
  syncState.value = 'error'
  syncMessage.value = formatError(errorValue)
}

function formatError(errorValue: unknown) {
  return errorValue instanceof Error ? errorValue.message : '操作失败'
}

async function refreshPage() {
  await refresh()
  if (error.value) {
    throw new Error(error.value)
  }
}

async function saveEndpoint() {
  const isCreate = createMode.value
  beginAction(isCreate ? 'create-endpoint' : `save-endpoint-${endpointId.value}`, isCreate ? '正在新增目标...' : '正在保存目标...')

  try {
    if (isCreate) {
      const created = await api.createAiEndpoint(
        buildPayloadFromDrawer(form, true) as Parameters<typeof api.createAiEndpoint>[0]
      )
      finishAction(`已新增 ${created.display_name}`)
      void router.replace({
        name: 'ai-endpoints-detail',
        params: {
          endpointId: String(created.id),
        },
      })
      return
    }

    if (!selectedEndpoint.value) {
      throw new Error('当前没有可编辑的目标')
    }

    const payload = buildPayloadFromDrawer(form, Boolean(form.api_key.trim()))
    if (!form.api_key.trim()) {
      delete payload.api_key
    }

    const updated = await api.updateAiEndpoint(
      selectedEndpoint.value.id,
      payload as Parameters<typeof api.updateAiEndpoint>[1]
    )
    await refreshPage()
    fillDrawerForm(form, updated)
    finishAction(`已保存 ${updated.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function testCurrentEndpoint() {
  if (!selectedEndpoint.value) {
    return
  }

  beginAction(`test-endpoint-${selectedEndpoint.value.id}`, `正在测试 ${selectedEndpoint.value.display_name}...`)
  try {
    const result = await api.testAiEndpoint(selectedEndpoint.value.id)
    testOutput.value = redactSensitiveText(result.output_text)
    testUsage.value = redactSensitiveValue(result.usage)
    fillDrawerForm(form, result.endpoint)
    finishAction(`连通测试完成：${selectedEndpoint.value.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function deleteEndpoint() {
  if (!selectedEndpoint.value) {
    return
  }

  const confirmed = window.confirm(`确认删除目标“${selectedEndpoint.value.display_name}”吗？`)
  if (!confirmed) {
    return
  }

  beginAction(`delete-endpoint-${selectedEndpoint.value.id}`, `正在删除 ${selectedEndpoint.value.display_name}...`)
  try {
    const result = await api.deleteAiEndpoint(selectedEndpoint.value.id)
    finishAction(`已删除 ${result.display_name}，释放 ${result.released_tokens} 个注册码和 ${result.released_runtimes} 个 Runtime`)
    void router.push({ name: 'ai-endpoints' })
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function refreshList() {
  beginAction('refresh-endpoint-config', '正在刷新目标与接入状态...')
  try {
    await refreshPage()
    finishAction('页面已刷新')
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function copyText(value: string, successMessage: string) {
  try {
    await navigator.clipboard.writeText(value)
    finishAction(successMessage)
  } catch {
    syncState.value = 'error'
    syncMessage.value = '复制失败，请手动复制'
  }
}

async function createRuntimeToken() {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    syncState.value = 'error'
    syncMessage.value = '请先保存当前目标，再生成注册码'
    return
  }
  if (!runtimeTokenLabel.value.trim()) {
    syncState.value = 'error'
    syncMessage.value = '注册码名称不能为空'
    return
  }

  beginAction('create-runtime-token', '正在生成客户端注册码...')
  try {
    const result = await api.createRuntimeEnrollmentToken({
      token_label: runtimeTokenLabel.value.trim(),
      runtime_type: runtimeTokenType.value.trim() || 'agent',
      ai_endpoint_id: endpoint.id,
      usage_limit: Math.max(1, Number(runtimeTokenUsageLimit.value || 1)),
      expires_at: runtimeTokenExpiresAt.value || null,
      delivery_mode: 'activation_code',
    })
    if (!result.activation_code) {
      throw new Error('后端未返回短期接入激活码')
    }
    latestActivationCode.value = result.activation_code
    latestLegacyEnrollmentToken.value = result.enrollment_token || ''
    latestEnrollmentSteps.value = result.onboarding_steps
    await refreshPage()
    finishAction(`已生成 ${result.token.token_label}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function bindTokenToSelected(item: RuntimeEnrollmentTokenItem) {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    syncState.value = 'error'
    syncMessage.value = '请先选择一个目标'
    return
  }

  beginAction(`bind-token-${item.id}`, `正在绑定注册码 ${item.token_label}...`)
  try {
    await api.bindRuntimeEnrollmentToken(item.id, { ai_endpoint_id: endpoint.id })
    await refreshPage()
    finishAction(`已将 ${item.token_label} 绑定到 ${endpoint.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function unbindToken(item: RuntimeEnrollmentTokenItem) {
  beginAction(`unbind-token-${item.id}`, `正在解绑注册码 ${item.token_label}...`)
  try {
    await api.bindRuntimeEnrollmentToken(item.id, { ai_endpoint_id: null })
    await refreshPage()
    finishAction(`已解绑 ${item.token_label}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function bindRuntimeToSelected(item: ManagedRuntimeItem) {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    syncState.value = 'error'
    syncMessage.value = '请先选择一个目标'
    return
  }

  beginAction(`bind-runtime-${item.id}`, `正在绑定 Runtime ${item.display_name}...`)
  try {
    await api.bindManagedRuntime(item.id, { ai_endpoint_id: endpoint.id })
    await refreshPage()
    finishAction(`已将 ${item.display_name} 绑定到 ${endpoint.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function unbindRuntime(item: ManagedRuntimeItem) {
  beginAction(`unbind-runtime-${item.id}`, `正在解绑 Runtime ${item.display_name}...`)
  try {
    await api.bindManagedRuntime(item.id, { ai_endpoint_id: null })
    await refreshPage()
    finishAction(`已解绑 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function approveRuntime(item: ManagedRuntimeItem) {
  beginAction(`approve-runtime-${item.id}`, `正在批准 ${item.display_name}...`)
  try {
    await api.approveManagedRuntime(item.id, {
      ai_endpoint_id: selectedEndpoint.value?.id ?? item.ai_endpoint?.id ?? null,
    })
    await refreshPage()
    finishAction(`已批准 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function approveAndBindRuntime(item: ManagedRuntimeItem) {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    syncState.value = 'error'
    syncMessage.value = '请先选择一个目标'
    return
  }

  beginAction(`approve-bind-runtime-${item.id}`, `正在批准并绑定 ${item.display_name}...`)
  try {
    await api.approveManagedRuntime(item.id, { ai_endpoint_id: endpoint.id })
    await refreshPage()
    finishAction(`已批准并绑定 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function rejectRuntime(item: ManagedRuntimeItem) {
  const reason = window.prompt(`请输入拒绝 ${item.display_name} 的原因`, item.rejection_reason || '未通过接入审批')
  if (reason === null) {
    return
  }

  beginAction(`reject-runtime-${item.id}`, `正在拒绝 ${item.display_name}...`)
  try {
    await api.rejectManagedRuntime(item.id, reason)
    await refreshPage()
    finishAction(`已拒绝 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function revokeRuntime(item: ManagedRuntimeItem) {
  const confirmed = window.confirm(`确认撤销 Runtime“${item.display_name}”吗？`)
  if (!confirmed) {
    return
  }

  beginAction(`revoke-runtime-${item.id}`, `正在撤销 ${item.display_name}...`)
  try {
    await api.revokeManagedRuntime(item.id)
    await refreshPage()
    finishAction(`已撤销 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function issueActivationCode(item: ManagedRuntimeItem) {
  const expiresInput = window.prompt('请输入激活码有效期（分钟）', '10')
  if (expiresInput === null) {
    return
  }

  const expiresInMinutes = Math.max(1, Number.parseInt(expiresInput, 10) || 10)
  beginAction(`activation-code-${item.id}`, `正在为 ${item.display_name} 生成激活码...`)
  try {
    const result = await api.issueRuntimeActivationCode(item.id, {
      ai_endpoint_id: selectedEndpoint.value?.id ?? item.ai_endpoint?.id ?? null,
      expires_in_minutes: expiresInMinutes,
    })
    await refreshPage()
    window.prompt(`请复制激活码并发送给客户端（有效期 ${expiresInMinutes} 分钟）`, result.activation_code)
    finishAction(`已为 ${item.display_name} 生成激活码`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function setEndpointDefault(item: AiEndpointItem) {
  beginAction(`default-endpoint-${item.id}`, `正在切换默认路由到 ${item.display_name}...`)
  try {
    await api.updateAiEndpoint(item.id, { is_default: true, enabled: true })
    await refreshPage()
    finishAction(`默认路由已切换到 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function toggleEndpointEnabled(item: AiEndpointItem) {
  beginAction(
    `toggle-enabled-${item.id}`,
    item.enabled ? `正在停用 ${item.display_name}...` : `正在启用 ${item.display_name}...`
  )
  try {
    await api.updateAiEndpoint(item.id, { enabled: !item.enabled })
    await refreshPage()
    finishAction(item.enabled ? `已停用 ${item.display_name}` : `已启用 ${item.display_name}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function setEndpointProtectionMode(item: AiEndpointItem, mode: ProtectionMode) {
  beginAction(`protection-mode-${item.id}-${mode}`, `正在更新 ${item.display_name} 的防护模式...`)
  try {
    await api.updateAiEndpoint(item.id, {
      protection_enabled: mode !== 'off',
      protection_mode: mode,
    })
    await refreshPage()
    finishAction(`已切换 ${item.display_name} 的防护模式`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

function buildAlwaysOnPolicyPayload(
  profile: DefensePolicyProfile,
  patch: Partial<{
    aiReviewMode: AiReviewMode
    protectedPaths: string[]
    protectedSkills: string[]
    protectedPlugins: string[]
  }> = {}
) {
  return {
    guard_rules: profile.guard_rules.map((item) => ({
      key: item.key,
      title: item.title,
      description: item.description,
      enabled: true,
      mode: 'enforce' as const,
    })),
    scan_rules: profile.scan_rules.map((item) => ({
      key: item.key,
      title: item.title,
      description: item.description,
      enabled: true,
      mode: 'enforce' as const,
    })),
    advanced_rule: {
      key: profile.advanced_rule.key,
      title: profile.advanced_rule.title,
      description: profile.advanced_rule.description,
      enabled: true,
      mode: 'enforce' as const,
    },
    ai_review_policy: {
      key: profile.ai_review_policy.key,
      title: profile.ai_review_policy.title,
      description: profile.ai_review_policy.description,
      mode: patch.aiReviewMode ?? profile.ai_review_policy.mode,
      reviewer_ai_endpoint_id: null,
    },
    protected_paths: patch.protectedPaths ?? [...profile.protected_paths],
    protected_skills: patch.protectedSkills ?? [...profile.protected_skills],
    protected_plugins: patch.protectedPlugins ?? [...profile.protected_plugins],
  }
}

function updateLocalPolicy(profile: DefensePolicyProfile) {
  if (!data.value) {
    return
  }
  data.value = {
    ...data.value,
    policy: profile,
  }
}

async function persistEndpointPolicy(
  patch: Parameters<typeof buildAlwaysOnPolicyPayload>[1],
  successMessage: string
) {
  const endpoint = selectedEndpoint.value
  const profile = policyProfile.value
  if (!endpoint || !profile) {
    syncState.value = 'error'
    syncMessage.value = '请先保存当前目标'
    return
  }

  beginAction(`policy-${endpoint.id}`, '正在保存目标治理配置...')
  try {
    const updated = await api.updateDefensePolicy(buildAlwaysOnPolicyPayload(profile, patch), endpoint.id)
    updateLocalPolicy(updated)
    finishAction(successMessage)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function updateAiReviewMode(mode: AiReviewMode) {
  await persistEndpointPolicy(
    {
      aiReviewMode: mode,
    },
    '研判策略已保存'
  )
}

function parseDraftValues(value: string) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function mergeUniqueValues(current: string[], values: string[]) {
  const seen = new Set<string>()
  const next: string[] = []
  for (const value of [...current, ...values]) {
    const normalized = value.trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    next.push(normalized)
  }
  return next
}

async function addProtectedPaths(rawValue?: string) {
  const values = parseDraftValues(rawValue ?? protectedPathDraft.value)
  if (!values.length) {
    return
  }
  const next = mergeUniqueValues(protectedPaths.value, values)
  protectedPathDraft.value = ''
  await persistEndpointPolicy({ protectedPaths: next }, '敏感目录保护已保存')
}

async function removeProtectedPath(value: string) {
  await persistEndpointPolicy(
    { protectedPaths: protectedPaths.value.filter((item) => item !== value) },
    '敏感目录保护已保存'
  )
}

async function addProtectedSkills(rawValue?: string) {
  const values = parseDraftValues(rawValue ?? protectedSkillDraft.value)
  if (!values.length) {
    return
  }
  const next = mergeUniqueValues(protectedSkills.value, values)
  protectedSkillDraft.value = ''
  await persistEndpointPolicy({ protectedSkills: next }, '受保护 Skill 已保存')
}

async function protectAllEndpointSkills() {
  const names = skillItems.value.map((item) => item.skill_name)
  if (!names.length) {
    syncState.value = 'error'
    syncMessage.value = '当前目标没有可保护的 Skill'
    return
  }
  await persistEndpointPolicy(
    { protectedSkills: mergeUniqueValues(protectedSkills.value, names) },
    '当前目标的 Skill 已加入保护'
  )
}

async function removeProtectedSkill(value: string) {
  await persistEndpointPolicy(
    { protectedSkills: protectedSkills.value.filter((item) => item !== value) },
    '受保护 Skill 已保存'
  )
}

async function addProtectedPlugins(rawValue?: string) {
  const values = parseDraftValues(rawValue ?? protectedPluginDraft.value)
  if (!values.length) {
    return
  }
  const next = mergeUniqueValues(protectedPlugins.value, values)
  protectedPluginDraft.value = ''
  await persistEndpointPolicy({ protectedPlugins: next }, '受保护插件已保存')
}

async function removeProtectedPlugin(value: string) {
  await persistEndpointPolicy(
    { protectedPlugins: protectedPlugins.value.filter((item) => item !== value) },
    '受保护插件已保存'
  )
}

function isSkillSelected(skillId: number) {
  return selectedSkillIds.value.includes(skillId)
}

function toggleSkillSelection(skillId: number, event: Event) {
  const target = event.target
  if (!(target instanceof HTMLInputElement)) {
    return
  }
  const next = new Set(selectedSkillIds.value)
  if (target.checked) {
    next.add(skillId)
  } else {
    next.delete(skillId)
  }
  selectedSkillIds.value = Array.from(next)
}

function selectPendingSkills() {
  selectedSkillIds.value = skillItems.value.filter((item) => item.trust_status === 'pending').map((item) => item.id)
}

function clearSkillSelection() {
  selectedSkillIds.value = []
}

async function createEndpointSkill() {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    return
  }
  if (!skillCreateForm.skill_name.trim() || !skillCreateForm.source_path.trim()) {
    syncState.value = 'error'
    syncMessage.value = 'Skill 名称和路径不能为空'
    return
  }

  beginAction('create-endpoint-skill', '正在新增当前目标的 Skill...')
  try {
    await api.createSkill({
      skill_name: skillCreateForm.skill_name.trim(),
      skill_type: skillCreateForm.skill_type,
      provider: skillCreateForm.provider,
      source_path: skillCreateForm.source_path.trim(),
      trust_status: skillCreateForm.trust_status,
      ai_endpoint_id: endpoint.id,
    })
    skillCreateForm.skill_name = ''
    skillCreateForm.source_path = ''
    await refreshPage()
    finishAction('Skill 已加入当前目标')
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function importEndpointSkillDirectory() {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    return
  }
  if (!skillImportForm.directory_path.trim()) {
    syncState.value = 'error'
    syncMessage.value = 'Skill 目录不能为空'
    return
  }

  beginAction('import-endpoint-skills', '正在导入当前目标的 Skill 目录...')
  try {
    const result = await api.importSkillDirectory({
      directory_path: skillImportForm.directory_path.trim(),
      skill_type: skillImportForm.skill_type,
      provider: skillImportForm.provider,
      trust_status: skillImportForm.trust_status,
      recursive: skillImportForm.recursive,
      ai_endpoint_id: endpoint.id,
    })
    skillImportForm.directory_path = ''
    await refreshPage()
    finishAction(`Skill 目录已导入：新增 ${result.created}，更新 ${result.updated}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

async function scanEndpointSkills() {
  const endpoint = selectedEndpoint.value
  if (!endpoint) {
    return
  }
  const ids = skillScanTargetIds.value
  if (!ids.length) {
    syncState.value = 'error'
    syncMessage.value = '当前目标没有可扫描的 Skill'
    return
  }

  beginAction('scan-endpoint-skills', `正在扫描 ${ids.length} 个 Skill...`)
  try {
    const task = await api.scanSkills(ids, endpoint.id)
    await refreshPage()
    finishAction(`Skill 扫描任务已创建：#${task.id}`)
  } catch (errorValue) {
    failAction(errorValue)
  }
}

function runtimeStatusLabel(item: ManagedRuntimeItem) {
  if (item.status === 'activation_requested') return '待签发激活码'
  if (item.status === 'activation_issued') return '待兑换激活码'
  if (item.status === 'pending') return '待审批'
  if (item.status === 'approved') return '待领凭据'
  if (item.status === 'active') return '已接入'
  if (item.status === 'rejected') return '已拒绝'
  if (item.status === 'revoked') return '已撤销'
  return item.status
}

function runtimeStatusTone(item: ManagedRuntimeItem): Tone {
  if (item.status === 'activation_requested') return 'warn'
  if (item.status === 'activation_issued') return 'info'
  if (item.status === 'pending') return 'warn'
  if (item.status === 'approved') return 'info'
  if (item.status === 'active') return item.is_online ? 'safe' : 'warn'
  return 'danger'
}

function tokenStatusLabel(item: RuntimeEnrollmentTokenItem) {
  if (item.status === 'active') return '可注册'
  if (item.status === 'expired') return '已过期'
  if (item.status === 'revoked') return '已停用'
  return item.status
}

function tokenStatusTone(item: RuntimeEnrollmentTokenItem): Tone {
  if (item.status === 'active') return 'safe'
  if (item.status === 'expired') return 'warn'
  return 'danger'
}

function tokenDeliveryLabel(item: RuntimeEnrollmentTokenItem) {
  return item.delivery_mode === 'activation_code' ? '短期激活码' : '长注册码'
}

function tokenSecretHint(item: RuntimeEnrollmentTokenItem) {
  if (item.delivery_mode === 'activation_code' && item.bootstrap_code_hint) {
    return item.bootstrap_code_hint
  }
  return item.token_hint
}

function bindingStateLabel(item: { binding_state?: string | null }) {
  return item.binding_state === 'bound' ? '已绑定' : '未绑定'
}

function bindingStateTone(item: { binding_state?: string | null }): Tone {
  return item.binding_state === 'bound' ? 'safe' : 'info'
}
</script>

<template>
  <div class="page-grid">
    <TopStatusRail
      :title="pageTitle"
      :summary="pageSummary"
      :items="railItems"
      :status-label="statusLabel"
      :status-tone="statusTone"
      :meta="`${syncMessage}${lastActionAt ? ` / ${lastActionAt}` : ''}`"
    >
      <template #actions>
        <RouterLink class="ghost-button small" :to="{ name: 'ai-endpoints' }">返回列表</RouterLink>
        <RouterLink v-if="selectedEndpoint" class="ghost-button small" :to="mcpPolicyRoute">MCP 策略</RouterLink>
        <RouterLink class="ghost-button small" :to="attackTestingRoute">攻击测试</RouterLink>
        <button class="ghost-button small" type="button" :disabled="loading || isBusy" @click="refreshList">刷新</button>
      </template>
    </TopStatusRail>

    <section class="ai-route-strip endpoint-config-banner">
      <div class="ai-route-copy">
        <p class="panel-kicker">{{ selectedEndpoint ? '当前目标' : '创建模式' }}</p>
        <strong>{{ selectedEndpoint ? `当前目标：${selectedEndpoint.display_name}` : '先创建目标，再绑定客户端与注册码' }}</strong>
      </div>

      <div class="ai-route-metrics">
        <article class="ai-route-metric">
          <span>{{ selectedEndpoint ? '已绑定 Runtime' : '目标状态' }}</span>
          <strong>{{ selectedEndpoint ? selectedEndpointRuntimes.length : '待创建' }}</strong>
        </article>
        <article class="ai-route-metric">
          <span>{{ selectedEndpoint ? '已绑定注册码' : '默认路由' }}</span>
          <strong>{{ selectedEndpoint ? selectedEndpointTokens.length : form.is_default ? '准备启用' : '未启用' }}</strong>
        </article>
        <article class="ai-route-metric">
          <span>{{ selectedEndpoint ? '防护模式' : '接入协议' }}</span>
          <strong>{{ selectedEndpoint ? PROTECTION_MODE_LABELS[selectedEndpoint.protection_mode] : targetTypeLabel() }}</strong>
        </article>
      </div>

      <div class="endpoint-route-side">
        <div v-if="selectedEndpoint" class="table-actions wrap ai-route-actions">
          <button class="primary-button small" type="button" :disabled="isBusy" @click="testCurrentEndpoint">
            立即测试连通
          </button>
          <RouterLink class="ghost-button small" :to="mcpPolicyRoute">MCP 策略</RouterLink>
          <RouterLink class="ghost-button small" :to="attackTestingRoute">攻击测试</RouterLink>
        </div>
        <div v-else class="endpoint-inline-alert tone-info endpoint-route-note">
          <div class="endpoint-inline-alert-copy">
            <strong>保存后解锁单目标治理</strong>
          </div>
        </div>
      </div>
    </section>

    <div class="endpoint-config-layout">
      <div class="endpoint-config-main">
        <section v-if="loading && !createMode && !selectedEndpoint" class="endpoint-config-surface">
          <div class="empty-state">
            <p>正在加载目标配置...</p>
          </div>
        </section>

        <section v-else-if="createMode || selectedEndpoint" class="endpoint-config-surface">
          <div class="endpoint-config-header">
            <div class="endpoint-config-header-copy">
              <p class="panel-kicker">{{ createMode ? '新增目标' : '专属配置' }}</p>
              <h3>{{ createMode ? '接入信息与专属策略' : `${selectedEndpoint?.display_name || '目标'} 配置` }}</h3>
            </div>
            <div class="endpoint-config-header-side">
              <StatusPill v-if="selectedEndpoint" :label="endpointStatusLabel(selectedEndpoint)" :tone="endpointTone(selectedEndpoint)" />
              <StatusPill v-else label="待创建" tone="info" />
            </div>
          </div>

          <AiEndpointFormPanel
            :mode="createMode ? 'create' : 'detail'"
            :busy="isBusy"
            :form="form"
            :selected-endpoint="selectedEndpoint"
            :test-output="testOutput"
            :test-usage="testUsage"
            @save="saveEndpoint"
            @test="testCurrentEndpoint"
            @delete="deleteEndpoint"
          />
        </section>

        <section v-else class="endpoint-config-surface">
          <div class="empty-state">
            <p>未找到指定目标，可能已被删除或当前账号无权访问。</p>
          </div>
        </section>

        <template v-if="selectedEndpoint">
          <PageSection eyebrow="研判" title="辅助研判" tag="独立接口" tone="warn">
            <div class="endpoint-governance-panel">
              <div class="endpoint-governance-row">
                <div class="endpoint-governance-main">
                  <strong>研判模式</strong>
                  <div class="mode-group">
                    <button
                      v-for="option in reviewModeOptions"
                      :key="option.value"
                      :class="['ghost-button', 'small', { active: aiReviewMode === option.value }]"
                      type="button"
                      :disabled="isBusy"
                      @click="updateAiReviewMode(option.value)"
                    >
                      {{ option.label }}
                    </button>
                  </div>
                </div>
                <div class="endpoint-governance-control">
                  <RouterLink class="ghost-button small" to="/system-settings">配置辅助研判接口</RouterLink>
                </div>
              </div>

              <div class="endpoint-governance-metrics">
                <article>
                  <span>规则策略</span>
                  <strong>全开启</strong>
                </article>
                <article>
                  <span>研判端</span>
                  <strong>系统设置接口</strong>
                </article>
                <article>
                  <span>研判模式</span>
                  <strong>{{ reviewModeOptions.find((item) => item.value === aiReviewMode)?.label || aiReviewMode }}</strong>
                </article>
              </div>
            </div>
          </PageSection>

          <PageSection eyebrow="Skill" title="当前目标的 Skill 扫描" :tag="`${skillItems.length} 项 / 待审 ${pendingSkillCount}`" tone="warn" collapsible :defaultCollapsed="false">
            <div class="endpoint-governance-panel">
              <div class="endpoint-skill-actions">
                <input v-model="skillCreateForm.skill_name" class="text-input" type="text" placeholder="Skill 名称" />
                <input v-model="skillCreateForm.source_path" class="text-input" type="text" placeholder="Skill 路径" />
                <select v-model="skillCreateForm.skill_type" class="select-input">
                  <option value="local">本地</option>
                  <option value="plugin">插件</option>
                  <option value="remote">远程</option>
                  <option value="mcp">MCP</option>
                </select>
                <select v-model="skillCreateForm.trust_status" class="select-input">
                  <option value="pending">待审核</option>
                  <option value="trusted">可信</option>
                </select>
                <button class="primary-button small" type="button" :disabled="isBusy" @click="createEndpointSkill">
                  新增 Skill
                </button>
              </div>

              <div class="endpoint-skill-actions">
                <input v-model="skillImportForm.directory_path" class="text-input" type="text" placeholder="Skill 目录" />
                <select v-model="skillImportForm.skill_type" class="select-input">
                  <option value="local">本地</option>
                  <option value="plugin">插件</option>
                  <option value="remote">远程</option>
                  <option value="mcp">MCP</option>
                </select>
                <select v-model="skillImportForm.trust_status" class="select-input">
                  <option value="pending">待审核</option>
                  <option value="trusted">可信</option>
                </select>
                <label class="endpoint-inline-check">
                  <input v-model="skillImportForm.recursive" type="checkbox" />
                  <span>递归</span>
                </label>
                <button class="ghost-button small" type="button" :disabled="isBusy" @click="importEndpointSkillDirectory">
                  导入目录
                </button>
              </div>

              <div class="endpoint-governance-toolbar">
                <div class="sample-preview-tags">
                  <StatusPill :label="`已选 ${selectedSkillCount || skillItems.length}`" tone="info" />
                  <StatusPill :label="`扫描任务 ${skillResultItems.length}`" tone="warn" />
                </div>
                <div class="table-actions wrap">
                  <button class="ghost-button small" type="button" :disabled="!pendingSkillCount" @click="selectPendingSkills">
                    选择待审核
                  </button>
                  <button class="ghost-button small" type="button" :disabled="!selectedSkillCount" @click="clearSkillSelection">
                    清空
                  </button>
                  <button class="ghost-button small" type="button" :disabled="!skillItems.length || isBusy" @click="protectAllEndpointSkills">
                    保护当前目标 Skill
                  </button>
                  <button class="primary-button small" type="button" :disabled="!skillItems.length || isBusy" @click="scanEndpointSkills">
                    执行扫描
                  </button>
                </div>
              </div>

              <div v-if="!skillItems.length" class="empty-state">
                <p>当前目标没有 Skill。</p>
              </div>
              <div v-else class="endpoint-detail-list">
                <article v-for="item in skillItems" :key="item.id" class="endpoint-detail-row compact">
                  <label class="selection-toggle endpoint-row-toggle" @click.stop>
                    <input
                      class="row-selector"
                      :checked="isSkillSelected(item.id)"
                      type="checkbox"
                      @change="toggleSkillSelection(item.id, $event)"
                    />
                  </label>
                  <div class="endpoint-detail-main">
                    <div class="endpoint-detail-head">
                      <strong>{{ item.skill_name }}</strong>
                      <div class="sample-preview-tags">
                        <StatusPill :label="item.skill_type" tone="info" />
                        <StatusPill :label="item.trust_status === 'trusted' ? '可信' : '待审核'" :tone="item.trust_status === 'trusted' ? 'safe' : 'warn'" />
                      </div>
                    </div>
                    <div class="endpoint-detail-meta">
                      <span>{{ item.provider }}</span>
                      <span>{{ item.source_path_state }}</span>
                      <span>{{ item.source_path || item.resolved_source_path || '-' }}</span>
                    </div>
                  </div>
                </article>
              </div>

              <div v-if="skillResultItems.length" class="endpoint-token-result">
                <div class="endpoint-token-result-head">
                  <strong>最近扫描任务</strong>
                </div>
                <div class="endpoint-detail-list">
                  <article v-for="item in skillResultItems.slice(0, 4)" :key="item.key" class="endpoint-detail-row compact">
                    <div class="endpoint-detail-main">
                      <strong>{{ item.title }}</strong>
                      <div class="endpoint-detail-meta">
                        <span>{{ item.status }}</span>
                        <span>{{ item.meta_text }}</span>
                      </div>
                    </div>
                  </article>
                </div>
              </div>
            </div>
          </PageSection>

          <PageSection eyebrow="目录" title="当前目标的敏感目录保护" :tag="`${protectedPaths.length} 目录 / ${protectedSkills.length} Skill`" tone="danger" collapsible :defaultCollapsed="false">
            <div class="endpoint-governance-panel">
              <div class="endpoint-skill-actions">
                <input
                  v-model="protectedPathDraft"
                  class="text-input"
                  type="text"
                  placeholder="敏感目录，多个用逗号分隔"
                  @keydown.enter.prevent="addProtectedPaths()"
                />
                <button class="primary-button small" type="button" :disabled="isBusy" @click="addProtectedPaths()">
                  加入目录保护
                </button>
              </div>

              <div v-if="sensitivePathAssets.length" class="token-list">
                <button
                  v-for="item in sensitivePathAssets"
                  :key="item.id"
                  class="token-chip as-button"
                  type="button"
                  :disabled="isBusy || protectedPaths.includes(item.asset_path)"
                  @click="addProtectedPaths(item.asset_path)"
                >
                  {{ item.asset_name }}: {{ item.asset_path }}
                </button>
              </div>

              <div class="token-list">
                <span v-for="item in protectedPaths" :key="item" class="token-chip strong">
                  {{ item }}
                  <button type="button" :disabled="isBusy" @click="removeProtectedPath(item)">×</button>
                </span>
                <span v-if="!protectedPaths.length" class="token-empty">未配置敏感目录。</span>
              </div>

              <div class="endpoint-skill-actions">
                <input
                  v-model="protectedSkillDraft"
                  class="text-input"
                  type="text"
                  placeholder="受保护 Skill"
                  @keydown.enter.prevent="addProtectedSkills()"
                />
                <button class="ghost-button small" type="button" :disabled="isBusy" @click="addProtectedSkills()">
                  加入 Skill 保护
                </button>
                <input
                  v-model="protectedPluginDraft"
                  class="text-input"
                  type="text"
                  placeholder="受保护插件"
                  @keydown.enter.prevent="addProtectedPlugins()"
                />
                <button class="ghost-button small" type="button" :disabled="isBusy" @click="addProtectedPlugins()">
                  加入插件保护
                </button>
              </div>

              <div class="token-list">
                <span v-for="item in protectedSkills" :key="`skill-${item}`" class="token-chip">
                  Skill: {{ item }}
                  <button type="button" :disabled="isBusy" @click="removeProtectedSkill(item)">×</button>
                </span>
                <span v-for="item in protectedPlugins" :key="`plugin-${item}`" class="token-chip">
                  Plugin: {{ item }}
                  <button type="button" :disabled="isBusy" @click="removeProtectedPlugin(item)">×</button>
                </span>
              </div>
            </div>
          </PageSection>

          <PageSection eyebrow="Runtime" title="已绑定 Runtime" :tag="`${selectedEndpointRuntimes.length} 项`" tone="warn" collapsible :defaultCollapsed="true">
            <div v-if="!selectedEndpointRuntimes.length" class="empty-state">
              <p>这个目标下还没有已绑定 Runtime。</p>
            </div>
            <div v-else class="endpoint-detail-list">
              <article v-for="item in selectedEndpointRuntimes" :key="item.id" class="endpoint-detail-row">
                <div class="endpoint-detail-main">
                  <div class="endpoint-detail-head">
                    <strong>{{ item.display_name }}</strong>
                    <div class="sample-preview-tags">
                      <StatusPill :label="runtimeStatusLabel(item)" :tone="runtimeStatusTone(item)" />
                      <StatusPill :label="item.is_online ? '在线' : '离线'" :tone="item.is_online ? 'safe' : 'info'" />
                    </div>
                  </div>
                  <p>{{ item.status_summary }} / {{ item.hostname || '未上报主机名' }}</p>
                  <div class="endpoint-detail-meta">
                    <span>{{ item.runtime_type }}</span>
                    <span>{{ item.last_seen_at || '暂无心跳' }}</span>
                    <span>{{ item.ip_addresses.join(' / ') || '无 IP' }}</span>
                  </div>
                </div>
                <div class="endpoint-detail-actions">
                  <button
                    v-if="item.status === 'activation_requested' || item.status === 'activation_issued'"
                    class="ghost-button small"
                    type="button"
                    :disabled="isBusy"
                    @click="issueActivationCode(item)"
                  >
                    {{ item.status === 'activation_issued' ? '重发激活码' : '签发激活码' }}
                  </button>
                  <button
                    v-if="item.status === 'pending' || item.status === 'approved'"
                    class="ghost-button small"
                    type="button"
                    :disabled="isBusy"
                    @click="approveRuntime(item)"
                  >
                    批准
                  </button>
                  <button class="ghost-button small" type="button" :disabled="isBusy" @click="unbindRuntime(item)">
                    解绑
                  </button>
                  <button
                    v-if="item.status === 'pending' || item.status === 'approved'"
                    class="ghost-button small"
                    type="button"
                    :disabled="isBusy"
                    @click="rejectRuntime(item)"
                  >
                    拒绝
                  </button>
                  <button
                    v-else
                    class="ghost-button small"
                    type="button"
                    :disabled="isBusy"
                    @click="revokeRuntime(item)"
                  >
                    撤销
                  </button>
                </div>
              </article>
            </div>
          </PageSection>

          <PageSection eyebrow="注册码" title="已绑定注册码" :tag="`${selectedEndpointTokens.length} 项`" tone="info" collapsible :defaultCollapsed="true">
            <div v-if="!selectedEndpointTokens.length" class="empty-state">
              <p>这个目标下还没有已绑定注册码。</p>
            </div>
            <div v-else class="endpoint-detail-list">
              <article v-for="item in selectedEndpointTokens" :key="item.id" class="endpoint-detail-row">
                <div class="endpoint-detail-main">
                  <div class="endpoint-detail-head">
                    <strong>{{ item.token_label }}</strong>
                    <div class="sample-preview-tags">
                      <StatusPill :label="tokenStatusLabel(item)" :tone="tokenStatusTone(item)" />
                      <StatusPill :label="bindingStateLabel(item)" :tone="bindingStateTone(item)" />
                    </div>
                  </div>
                  <p>{{ item.runtime_type }} / {{ tokenSecretHint(item) }}</p>
                  <div class="endpoint-detail-meta">
                    <span>{{ tokenDeliveryLabel(item) }}</span>
                    <span>可用 {{ item.remaining_uses }}</span>
                    <span>已用 {{ item.used_count }}</span>
                    <span>{{ item.expires_at || '不过期' }}</span>
                  </div>
                </div>
                <div class="endpoint-detail-actions">
                  <button class="ghost-button small" type="button" :disabled="isBusy" @click="unbindToken(item)">
                    解绑
                  </button>
                </div>
              </article>
            </div>
          </PageSection>

          <PageSection eyebrow="待处理" title="未绑定对象" :tag="`${unboundRuntimes.length + unboundTokens.length} 项`" tone="warn" collapsible :defaultCollapsed="true">
            <div class="endpoint-subsection">
              <div class="endpoint-subsection-head">
                <h4>未绑定 Runtime</h4>
                <span>{{ unboundRuntimes.length }} 项</span>
              </div>
              <div v-if="!unboundRuntimes.length" class="token-empty">没有未绑定 Runtime。</div>
              <div v-else class="endpoint-detail-list">
                <article v-for="item in unboundRuntimes" :key="item.id" class="endpoint-detail-row">
                  <div class="endpoint-detail-main">
                    <div class="endpoint-detail-head">
                      <strong>{{ item.display_name }}</strong>
                      <div class="sample-preview-tags">
                        <StatusPill :label="runtimeStatusLabel(item)" :tone="runtimeStatusTone(item)" />
                        <StatusPill :label="bindingStateLabel(item)" :tone="bindingStateTone(item)" />
                      </div>
                    </div>
                    <p>{{ item.status_summary }} / {{ item.hostname || '未上报主机名' }}</p>
                    <div class="endpoint-detail-meta">
                      <span>{{ item.runtime_type }}</span>
                      <span>{{ item.last_seen_at || '暂无心跳' }}</span>
                      <span>{{ item.ip_addresses.join(' / ') || '无 IP' }}</span>
                    </div>
                  </div>
                  <div class="endpoint-detail-actions">
                    <button
                      v-if="item.status === 'activation_requested' || item.status === 'activation_issued'"
                      class="ghost-button small"
                      type="button"
                      :disabled="isBusy"
                      @click="issueActivationCode(item)"
                    >
                      {{ item.status === 'activation_issued' ? '重发激活码' : '签发激活码' }}
                    </button>
                    <button class="ghost-button small" type="button" :disabled="isBusy" @click="bindRuntimeToSelected(item)">
                      绑定到当前
                    </button>
                    <button
                      v-if="item.status === 'pending' || item.status === 'approved'"
                      class="ghost-button small"
                      type="button"
                      :disabled="isBusy"
                      @click="approveAndBindRuntime(item)"
                    >
                      绑定并批准
                    </button>
                    <button
                      v-if="item.status === 'pending' || item.status === 'approved'"
                      class="ghost-button small"
                      type="button"
                      :disabled="isBusy"
                      @click="rejectRuntime(item)"
                    >
                      拒绝
                    </button>
                    <button
                      v-else
                      class="ghost-button small"
                      type="button"
                      :disabled="isBusy"
                      @click="revokeRuntime(item)"
                    >
                      撤销
                    </button>
                  </div>
                </article>
              </div>
            </div>

            <div class="endpoint-subsection">
              <div class="endpoint-subsection-head">
                <h4>未绑定注册码</h4>
                <span>{{ unboundTokens.length }} 项</span>
              </div>
              <div v-if="!unboundTokens.length" class="token-empty">没有未绑定注册码。</div>
              <div v-else class="endpoint-detail-list">
                <article v-for="item in unboundTokens" :key="item.id" class="endpoint-detail-row">
                  <div class="endpoint-detail-main">
                    <div class="endpoint-detail-head">
                      <strong>{{ item.token_label }}</strong>
                      <div class="sample-preview-tags">
                        <StatusPill :label="tokenStatusLabel(item)" :tone="tokenStatusTone(item)" />
                        <StatusPill :label="bindingStateLabel(item)" :tone="bindingStateTone(item)" />
                      </div>
                    </div>
                    <p>{{ item.runtime_type }} / {{ tokenSecretHint(item) }}</p>
                    <div class="endpoint-detail-meta">
                      <span>{{ tokenDeliveryLabel(item) }}</span>
                      <span>可用 {{ item.remaining_uses }}</span>
                      <span>已用 {{ item.used_count }}</span>
                      <span>{{ item.expires_at || '不过期' }}</span>
                    </div>
                  </div>
                  <div class="endpoint-detail-actions">
                    <button class="ghost-button small" type="button" :disabled="isBusy" @click="bindTokenToSelected(item)">
                      绑定到当前
                    </button>
                  </div>
                </article>
              </div>
            </div>
          </PageSection>

          <PageSection eyebrow="接入指引" title="OpenClaw 客户端接入" tag="按需展开" tone="info" collapsible :defaultCollapsed="true">
            <div v-if="isOpenClawEndpoint" class="endpoint-guide-stack">
              <div class="settings-snapshot-list">
                <div class="settings-snapshot-row">
                  <div class="settings-snapshot-copy">
                    <h4>推荐脚本</h4>
                  </div>
                  <p class="settings-snapshot-value">connect_openclaw_control.cmd / connect_openclaw_control.sh</p>
                </div>

                <div class="settings-snapshot-row">
                  <div class="settings-snapshot-copy">
                    <h4>连接方式</h4>
                  </div>
                  <p class="settings-snapshot-value">{{ connectionModeLabel(selectedEndpoint?.connection_mode) }}</p>
                </div>
              </div>

              <ol class="ai-access-step-list">
                <li>先在平台创建当前目标，并签发一个短期激活码。</li>
                <li>客户端运行 OpenClaw 接入脚本，填写管理端地址、OpenClaw 地址、gateway token 和激活码。</li>
                <li>脚本会向平台换取长期 Runtime 凭据，并自动保存到本地，后续直接复用。</li>
                <li>当桥接 Runtime 在线后，OpenClaw 的聊天消息和工具调用会先经过平台审查，再转发到上游。</li>
              </ol>
            </div>
            <div v-else-if="selectedEndpointIntegration" class="endpoint-guide-stack">
              <div class="settings-snapshot-list">
                <div class="settings-snapshot-row">
                  <div class="settings-snapshot-copy">
                    <h4>HTTP 代理入口</h4>
                  </div>
                  <p class="settings-snapshot-value">
                    <button class="ghost-button small" type="button" @click="copyText(selectedEndpointIntegration.gateway_base_path, '已复制 HTTP 入口')">
                      {{ selectedEndpointIntegration.gateway_base_path }}
                    </button>
                  </p>
                </div>

                <div class="settings-snapshot-row">
                  <div class="settings-snapshot-copy">
                    <h4>WebSocket 入口</h4>
                  </div>
                  <p class="settings-snapshot-value">
                    <button class="ghost-button small" type="button" @click="copyText(selectedEndpointIntegration.gateway_ws_base_path, '已复制 WebSocket 入口')">
                      {{ selectedEndpointIntegration.gateway_ws_base_path }}
                    </button>
                  </p>
                </div>
              </div>

              <div class="endpoint-guide-grid">
                <section class="endpoint-guide-card">
                  <div class="endpoint-subsection-head">
                    <h4>路由选择</h4>
                  </div>
                  <article
                    v-for="selector in selectedEndpointIntegration.route_selector_items"
                    :key="selector.key"
                    class="endpoint-guide-row"
                  >
                    <div class="endpoint-detail-main">
                      <strong>{{ selector.label }}</strong>
                    </div>
                    <button class="ghost-button small" type="button" @click="copyText(selector.value, `已复制 ${selector.label}`)">
                      {{ selector.value }}
                    </button>
                  </article>
                </section>

                <section class="endpoint-guide-card">
                  <div class="endpoint-subsection-head">
                    <h4>认证方式</h4>
                  </div>
                  <article
                    v-for="auth in selectedEndpointIntegration.auth_modes"
                    :key="auth.key"
                    class="endpoint-guide-row"
                  >
                    <div class="endpoint-detail-main">
                      <strong>{{ auth.label }}</strong>
                    </div>
                    <button class="ghost-button small" type="button" @click="copyText(`${auth.header_name}: ${auth.header_value}`, `已复制 ${auth.label}`)">
                      {{ auth.header_name }}
                    </button>
                  </article>
                </section>
              </div>

              <div v-if="selectedEndpointIntegration.access_modes[0]" class="endpoint-token-result">
                <div class="endpoint-token-result-head">
                  <strong>{{ selectedEndpointIntegration.access_modes[0].label }}</strong>
                  <button
                    class="ghost-button small"
                    type="button"
                    @click="copyText(selectedEndpointIntegration.access_modes[0].sample_lines.join('\n'), '已复制接入示例')"
                  >
                    复制示例
                  </button>
                </div>
                <pre class="ai-access-sample">{{ selectedEndpointIntegration.access_modes[0].sample_lines.join('\n') }}</pre>
              </div>
            </div>
          </PageSection>
        </template>
      </div>

      <aside class="endpoint-config-side">
        <PageSection
          eyebrow="概况"
          title="当前目标"
          :tag="selectedEndpoint ? endpointStatusLabel(selectedEndpoint) : '待创建'"
          :tone="selectedEndpoint ? endpointTone(selectedEndpoint) : 'info'"
        >
          <div v-if="selectedEndpoint" class="endpoint-summary-stack">
            <div class="ai-endpoint-summary-card endpoint-context-hero">
              <div class="ai-endpoint-summary-head">
                <div class="ai-endpoint-summary-copy">
                  <p class="panel-kicker">当前目标</p>
                  <h4>{{ selectedEndpoint.display_name }}</h4>
                </div>
                <StatusPill :label="endpointStatusLabel(selectedEndpoint)" :tone="endpointTone(selectedEndpoint)" />
              </div>
              <div class="endpoint-table-meta">
                <span>{{ selectedEndpoint.endpoint_group }}</span>
                <span>{{ targetTypeLabel(selectedEndpoint) }}</span>
                <span>{{ selectedEndpoint.usage_summary.runtime_count }} Runtime</span>
              </div>
            </div>

            <div class="settings-snapshot-list">
              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>接入协议</h4>
                </div>
                <p class="settings-snapshot-value">{{ targetTypeLabel(selectedEndpoint) }}</p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>防护模式</h4>
                </div>
                <p class="settings-snapshot-value">{{ PROTECTION_MODE_LABELS[selectedEndpoint.protection_mode] }}</p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>上游地址</h4>
                </div>
                <p class="settings-snapshot-value">
                  {{ selectedEndpoint.is_default ? '默认路由' : '普通路由' }}
                </p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>最近心跳</h4>
                  <p>{{ selectedEndpoint.usage_summary.last_runtime_seen_at || '暂无在线客户端' }}</p>
                </div>
                <p class="settings-snapshot-value">在线 {{ selectedEndpoint.usage_summary.runtime_online_count }}</p>
              </div>
            </div>
          </div>
          <div v-else class="empty-state">
            <p>创建完成后，这里会显示当前目标的接入状态、路由角色和客户端数量。</p>
          </div>
        </PageSection>

        <PageSection eyebrow="客户端" title="注册码与绑定" :tag="selectedEndpoint ? `${runtimeSummary.tokens_active} 活跃` : '保存后可用'" tone="warn">
          <div v-if="selectedEndpoint" class="endpoint-summary-stack">
            <div class="ai-runtime-token-form compact">
              <input
                v-model="runtimeTokenLabel"
                class="text-input"
                type="text"
                placeholder="注册码名称"
              />
              <input
                v-model="runtimeTokenType"
                class="text-input"
                type="text"
                placeholder="runtime 类型，例如 agent"
              />
              <input
                v-model.number="runtimeTokenUsageLimit"
                class="text-input"
                type="number"
                min="1"
                placeholder="使用次数"
              />
              <input
                v-model="runtimeTokenExpiresAt"
                class="text-input"
                type="datetime-local"
                placeholder="过期时间"
              />
              <button class="primary-button small" type="button" :disabled="isBusy" @click="createRuntimeToken">
                生成注册码
              </button>
            </div>

            <div v-if="latestActivationCode" class="endpoint-token-result">
              <div class="endpoint-token-result-head">
                <strong>最新注册码</strong>
                <button class="ghost-button small" type="button" @click="copyText(latestEnrollmentToken, '已复制注册码')">
                  复制
                </button>
              </div>
              <pre class="ai-access-sample">{{ latestEnrollmentToken }}</pre>
              <ol class="ai-access-step-list">
                <li v-for="step in latestEnrollmentSteps" :key="step">{{ step }}</li>
              </ol>
              <details v-if="latestLegacyEnrollmentToken">
                <summary>旧注册码</summary>
                <pre class="ai-access-sample">{{ latestLegacyEnrollmentToken }}</pre>
              </details>
            </div>
          </div>
          <div v-else class="empty-state">
            <p>保存后可用。</p>
          </div>
        </PageSection>

        <PageSection eyebrow="操作" title="目标操作" tag="当前页" tone="info">
          <div v-if="selectedEndpoint" class="endpoint-action-grid">
            <button
              class="ghost-button small"
              type="button"
              :disabled="selectedEndpoint.is_default || isBusy"
              @click="setEndpointDefault(selectedEndpoint)"
            >
              设为默认
            </button>
            <button class="ghost-button small" type="button" :disabled="isBusy" @click="toggleEndpointEnabled(selectedEndpoint)">
              {{ selectedEndpoint.enabled ? '停用接入' : '启用接入' }}
            </button>
            <button class="ghost-button small" type="button" :disabled="isBusy" @click="setEndpointProtectionMode(selectedEndpoint, 'enforce')">
              开启防护
            </button>
            <RouterLink class="ghost-button small" :to="mcpPolicyRoute">MCP 策略</RouterLink>
            <RouterLink class="ghost-button small" :to="attackTestingRoute">攻击测试</RouterLink>
          </div>
          <div v-else class="empty-state">
            <p>保存后可用。</p>
          </div>
        </PageSection>
      </aside>
    </div>
  </div>
</template>
