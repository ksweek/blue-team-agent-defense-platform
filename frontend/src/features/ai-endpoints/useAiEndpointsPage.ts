import { computed, reactive, ref, watch } from 'vue'
import type {
  AiEndpointConfigSecretItem,
  AiEndpointItem,
  AiEndpointSummary,
  ManagedRuntimeItem,
  RuntimeEnrollmentTokenItem,
  RuntimeRegistrySummary,
} from '../../services/api'
import { api } from '../../services/api'
import { useAsyncData } from '../../composables/useAsyncData'
import { redactSensitiveText, redactSensitiveValue } from '../../services/redaction'
import { formatBeijingTime } from '../../services/time'
import {
  PROTECTION_MODE_LABELS,
  PROVIDER_LABELS,
  type ProtectionMode,
  type ProviderType,
  type Tone,
} from './constants'
import {
  endpointMetaText,
  endpointStatusLabel,
  endpointSummaryText,
  endpointTone,
  normalizeEndpointKey,
  normalizeGroup,
} from './helpers'

type DrawerMode = 'create' | 'detail'
type SyncState = 'idle' | 'saving' | 'saved' | 'error'

export type EndpointSecretDraft = AiEndpointConfigSecretItem & {
  next_value: string
  remove: boolean
}

export type EndpointForm = {
  endpoint_key: string
  display_name: string
  endpoint_group: string
  provider_type: ProviderType
  base_url: string
  api_key: string
  model_name: string
  enabled: boolean
  is_default: boolean
  protection_enabled: boolean
  protection_mode: ProtectionMode
  description: string
  config_public_text: string
  config_secret_items: EndpointSecretDraft[]
  new_secret_path: string
  new_secret_value: string
}

const EMPTY_SUMMARY: AiEndpointSummary = {
  total: 0,
  enabled: 0,
  protected: 0,
  default_id: null,
  default_display_name: null,
  default_group: null,
  group_count: 0,
  cleanup_candidates: 0,
}

const EMPTY_RUNTIME_SUMMARY: RuntimeRegistrySummary = {
  tokens_total: 0,
  tokens_active: 0,
  runtimes_total: 0,
  runtimes_pending: 0,
  runtimes_approved: 0,
  runtimes_active: 0,
  tokens_unbound: 0,
  runtimes_unbound: 0,
  runtimes_online: 0,
}

export function useAiEndpointsPage() {
  const { data, loading, error, refresh } = useAsyncData(async () => {
    const [endpoints, runtimeRegistry] = await Promise.all([
      api.aiEndpoints(),
      api.runtimeRegistry(),
    ])
    return { endpoints, runtimeRegistry }
  })

  const activeGroup = ref('all')
  const selectedIds = ref<number[]>([])
  const selectedEndpointId = ref<number | null>(null)
  const drawerOpen = ref(false)
  const drawerMode = ref<DrawerMode>('detail')
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
  const latestEnrollmentToken = ref('')
  const latestEnrollmentSteps = ref<string[]>([])

  const drawerForm = reactive<EndpointForm>(blankEndpointForm(activeGroup.value, 0))

  const endpointItems = computed<AiEndpointItem[]>(() => data.value?.endpoints.items ?? [])
  const endpointSummary = computed<AiEndpointSummary>(() => data.value?.endpoints.summary ?? EMPTY_SUMMARY)
  const runtimeSummary = computed<RuntimeRegistrySummary>(
    () => data.value?.runtimeRegistry.summary ?? EMPTY_RUNTIME_SUMMARY
  )
  const runtimeTokens = computed<RuntimeEnrollmentTokenItem[]>(() => data.value?.runtimeRegistry.tokens ?? [])
  const runtimeItems = computed<ManagedRuntimeItem[]>(() => data.value?.runtimeRegistry.runtimes ?? [])
  const unboundTokens = computed<RuntimeEnrollmentTokenItem[]>(
    () => data.value?.runtimeRegistry.unbound_tokens ?? []
  )
  const unboundRuntimes = computed<ManagedRuntimeItem[]>(
    () => data.value?.runtimeRegistry.unbound_runtimes ?? []
  )
  const isBusy = computed(() => activeActionKey.value !== null)
  const selectedCount = computed(() => selectedIds.value.length)
  const cleanupCandidates = computed(() => endpointItems.value.filter((item) => item.is_cleanup_candidate))

  const groupOptions = computed(() => {
    const counters = new Map<string, number>()
    endpointItems.value.forEach((item) => {
      const group = normalizeGroup(item.endpoint_group)
      counters.set(group, (counters.get(group) ?? 0) + 1)
    })

    return [
      { key: 'all', label: '全部', count: endpointItems.value.length },
      ...Array.from(counters.entries())
        .sort((left, right) => left[0].localeCompare(right[0], 'zh-CN'))
        .map(([key, count]) => ({
          key,
          label: key === 'default' ? '默认分组' : key,
          count,
        })),
    ]
  })

  const filteredItems = computed(() => {
    if (activeGroup.value === 'all') {
      return endpointItems.value
    }
    return endpointItems.value.filter((item) => normalizeGroup(item.endpoint_group) === activeGroup.value)
  })

  const selectedEndpoint = computed(
    () => endpointItems.value.find((item) => item.id === selectedEndpointId.value) ?? null
  )
  const selectedEndpointIntegration = computed(() => selectedEndpoint.value?.integration_view ?? null)
  const selectedEndpointTokens = computed(() => {
    const endpointId = selectedEndpoint.value?.id
    if (!endpointId) {
      return []
    }
    return runtimeTokens.value.filter((item) => item.ai_endpoint?.id === endpointId)
  })
  const selectedEndpointRuntimes = computed(() => {
    const endpointId = selectedEndpoint.value?.id
    if (!endpointId) {
      return []
    }
    return runtimeItems.value.filter((item) => item.ai_endpoint?.id === endpointId)
  })

  const topRailItems = computed(() => [
    {
      label: 'AI 目标',
      value: String(endpointSummary.value.total),
      tone: 'info' as Tone,
      meta: `${endpointSummary.value.group_count ?? 0} 个分组`,
    },
    {
      label: '默认路由',
      value: endpointSummary.value.default_display_name || '未配置',
      tone: endpointSummary.value.default_id ? ('safe' as Tone) : ('warn' as Tone),
      meta: endpointSummary.value.default_group || '请选择一个目标作为默认回退',
    },
    {
      label: '在线 Runtime',
      value: String(runtimeSummary.value.runtimes_online),
      tone: runtimeSummary.value.runtimes_online ? ('safe' as Tone) : ('info' as Tone),
      meta: `未绑定 ${runtimeSummary.value.runtimes_unbound}`,
    },
    {
      label: '注册码',
      value: String(runtimeSummary.value.tokens_active),
      tone: runtimeSummary.value.tokens_active ? ('warn' as Tone) : ('info' as Tone),
      meta: `未绑定 ${runtimeSummary.value.tokens_unbound}`,
    },
    {
      label: '清理候选',
      value: String(endpointSummary.value.cleanup_candidates ?? 0),
      tone: (endpointSummary.value.cleanup_candidates ?? 0) > 0 ? ('warn' as Tone) : ('safe' as Tone),
      meta: (endpointSummary.value.cleanup_candidates ?? 0) > 0 ? '可一键删除测试端点' : '当前没有测试端点',
    },
  ])

  const drawerTitle = computed(() =>
    drawerMode.value === 'create'
      ? '新增 AI 目标'
      : selectedEndpoint.value?.display_name || 'AI 目标配置'
  )

  const drawerSummary = computed(() => {
    if (drawerMode.value === 'create') {
      return '填写真实上游模型端点，保存后即可绑定 Runtime 和注册码。'
    }

    const endpoint = selectedEndpoint.value
    if (!endpoint) {
      return '当前没有可编辑的 AI 目标。'
    }

    return `${PROVIDER_LABELS[endpoint.provider_type]} / ${normalizeGroup(endpoint.endpoint_group)} / ${endpoint.model_name}`
  })

  watch(
    [endpointItems, filteredItems],
    ([items, filtered]) => {
      const availableIds = new Set(items.map((item) => item.id))
      selectedIds.value = selectedIds.value.filter((id) => availableIds.has(id))

      if (!items.length) {
        selectedEndpointId.value = null
        drawerOpen.value = false
        return
      }

      if (!groupOptions.value.some((item) => item.key === activeGroup.value)) {
        activeGroup.value = 'all'
      }

      const visibleIds = new Set(filtered.map((item) => item.id))
      if (selectedEndpointId.value && visibleIds.has(selectedEndpointId.value)) {
        return
      }

      selectedEndpointId.value = filtered[0]?.id ?? items[0]?.id ?? null
    },
    { immediate: true }
  )

  watch(selectedEndpoint, (item) => {
    if (!item) {
      return
    }

    if (!runtimeTokenLabel.value.trim()) {
      runtimeTokenLabel.value = `${item.display_name} 客户端注册码`
    }

    if (drawerMode.value === 'detail' && drawerOpen.value) {
      fillDrawerForm(drawerForm, item)
    }
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
    syncMessage.value = redactSensitiveText(formatError(errorValue))
  }

  function formatError(errorValue: unknown) {
    return errorValue instanceof Error ? errorValue.message : '操作失败'
  }

  async function refreshEndpoints() {
    await refresh()
    if (error.value) {
      throw new Error(error.value)
    }
  }

  function selectEndpoint(endpointId: number) {
    selectedEndpointId.value = endpointId
  }

  function openCreateDrawer() {
    drawerMode.value = 'create'
    drawerOpen.value = true
    clearTestResult()
    Object.assign(drawerForm, blankEndpointForm(activeGroup.value, endpointItems.value.length))
  }

  function openEndpoint(item: AiEndpointItem) {
    selectedEndpointId.value = item.id
    drawerMode.value = 'detail'
    drawerOpen.value = true
    clearTestResult()
    fillDrawerForm(drawerForm, item)
  }

  function closeDrawer() {
    drawerOpen.value = false
    clearTestResult()
  }

  function clearSelection() {
    selectedIds.value = []
  }

  function toggleSelection(endpointId: number, checked: boolean) {
    const next = new Set(selectedIds.value)
    if (checked) {
      next.add(endpointId)
    } else {
      next.delete(endpointId)
    }
    selectedIds.value = Array.from(next)
  }

  function handleSelectionChange(endpointId: number, event: Event) {
    const target = event.target
    if (!(target instanceof HTMLInputElement)) {
      return
    }
    toggleSelection(endpointId, target.checked)
  }

  function isSelected(endpointId: number) {
    return selectedIds.value.includes(endpointId)
  }

  async function saveDrawer() {
    const createMode = drawerMode.value === 'create'
    beginAction(createMode ? 'create-endpoint' : `save-endpoint-${selectedEndpointId.value}`, createMode ? '正在新增 AI 目标...' : '正在保存 AI 目标...')

    try {
      if (createMode) {
        const created = await api.createAiEndpoint(
          buildPayloadFromDrawer(drawerForm, true) as Parameters<typeof api.createAiEndpoint>[0]
        )
        await refreshEndpoints()
        selectedEndpointId.value = created.id
        fillDrawerForm(drawerForm, created)
        finishAction(`已新增 ${created.display_name}`)
        selectedIds.value = [created.id]
        drawerMode.value = 'detail'
        return
      }

      if (!selectedEndpoint.value) {
        throw new Error('当前没有可编辑的 AI 目标')
      }

      const payload = buildPayloadFromDrawer(drawerForm, Boolean(drawerForm.api_key.trim()))
      if (!drawerForm.api_key.trim()) {
        delete payload.api_key
      }

      const updated = await api.updateAiEndpoint(
        selectedEndpoint.value.id,
        payload as Parameters<typeof api.updateAiEndpoint>[1]
      )
      await refreshEndpoints()
      selectedEndpointId.value = updated.id
      fillDrawerForm(drawerForm, updated)
      finishAction(`已保存 ${updated.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function testEndpoint(item: AiEndpointItem) {
    beginAction(`test-endpoint-${item.id}`, `正在测试 ${item.display_name}...`)
    try {
      const result = await api.testAiEndpoint(item.id)
      testOutput.value = redactSensitiveText(result.output_text)
      testUsage.value = redactSensitiveValue(result.usage)
      selectedEndpointId.value = item.id
      drawerMode.value = 'detail'
      drawerOpen.value = true
      fillDrawerForm(drawerForm, result.endpoint)
      finishAction(`连通测试完成：${item.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function setEndpointDefault(item: AiEndpointItem) {
    beginAction(`default-endpoint-${item.id}`, `正在切换默认路由到 ${item.display_name}...`)
    try {
      const updated = await api.updateAiEndpoint(item.id, { is_default: true, enabled: true })
      await refreshEndpoints()
      selectedEndpointId.value = updated.id
      finishAction(`默认路由已切换到 ${updated.display_name}`)
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
      const updated = await api.updateAiEndpoint(item.id, { enabled: !item.enabled })
      await refreshEndpoints()
      selectedEndpointId.value = updated.id
      finishAction(item.enabled ? `已停用 ${updated.display_name}` : `已启用 ${updated.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function toggleEndpointProtection(item: AiEndpointItem) {
    const nextEnabled = !item.protection_enabled || item.protection_mode === 'off'
    const nextMode: ProtectionMode = nextEnabled ? 'enforce' : 'off'
    beginAction(
      `toggle-protection-${item.id}`,
      nextEnabled ? `正在开启 ${item.display_name} 的执行防护...` : `正在关闭 ${item.display_name} 的执行防护...`
    )
    try {
      const updated = await api.updateAiEndpoint(item.id, {
        protection_enabled: nextEnabled,
        protection_mode: nextMode,
      })
      await refreshEndpoints()
      selectedEndpointId.value = updated.id
      finishAction(nextEnabled ? `已开启 ${updated.display_name} 的执行防护` : `已关闭 ${updated.display_name} 的执行防护`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function setEndpointProtectionMode(item: AiEndpointItem, mode: ProtectionMode) {
    beginAction(`protection-mode-${item.id}-${mode}`, `正在更新 ${item.display_name} 的防护模式...`)
    try {
      const updated = await api.updateAiEndpoint(item.id, {
        protection_enabled: mode !== 'off',
        protection_mode: mode,
      })
      await refreshEndpoints()
      selectedEndpointId.value = updated.id
      finishAction(`已切换 ${updated.display_name} 的防护模式`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function deleteEndpoint(item: AiEndpointItem) {
    const confirmed = window.confirm(`确认删除 AI 目标“${item.display_name}”吗？`)
    if (!confirmed) {
      return
    }

    beginAction(`delete-endpoint-${item.id}`, `正在删除 ${item.display_name}...`)
    try {
      const result = await api.deleteAiEndpoint(item.id)
      await refreshEndpoints()
      selectedIds.value = selectedIds.value.filter((id) => id !== item.id)
      if (selectedEndpointId.value === item.id) {
        selectedEndpointId.value = filteredItems.value[0]?.id ?? endpointItems.value[0]?.id ?? null
      }
      if (!selectedEndpointId.value) {
        drawerOpen.value = false
      }
      finishAction(`已删除 ${result.display_name}，释放 ${result.released_tokens} 个注册码和 ${result.released_runtimes} 个 Runtime`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function cleanupEndpointCandidates() {
    if (!cleanupCandidates.value.length) {
      syncState.value = 'error'
      syncMessage.value = '当前没有可清理的测试端点'
      return
    }

    const confirmed = window.confirm(`确认清理 ${cleanupCandidates.value.length} 个测试端点吗？`)
    if (!confirmed) {
      return
    }

    beginAction('cleanup-endpoints', '正在清理测试端点...')
    try {
      const result = await api.cleanupAiEndpointCandidates()
      await refreshEndpoints()
      selectedIds.value = selectedIds.value.filter((id) => endpointItems.value.some((item) => item.id === id))
      finishAction(`已清理 ${result.deleted_count} 个测试端点，释放 ${result.released_tokens} 个注册码和 ${result.released_runtimes} 个 Runtime`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function runBatchUpdate(
    actionKey: string,
    message: string,
    payload: Parameters<typeof api.batchUpdateAiEndpoints>[0],
    doneMessage: string
  ) {
    if (!selectedIds.value.length) {
      syncState.value = 'error'
      syncMessage.value = '请先选择至少一个 AI 目标'
      return
    }

    beginAction(actionKey, message)
    try {
      await api.batchUpdateAiEndpoints(payload)
      await refreshEndpoints()
      finishAction(doneMessage)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  function refreshList() {
    beginAction('refresh-endpoints', '正在刷新 AI 目标和接入状态...')
    void refreshEndpoints()
      .then(() => {
        finishAction('列表已刷新')
      })
      .catch((errorValue) => {
        failAction(errorValue)
      })
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
      syncMessage.value = '请先选择一个 AI 目标，再生成注册码'
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
      })
      latestEnrollmentToken.value = result.enrollment_token
      latestEnrollmentSteps.value = result.onboarding_steps
      await refreshEndpoints()
      finishAction(`已生成 ${result.token.token_label}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function bindTokenToSelected(item: RuntimeEnrollmentTokenItem) {
    const endpoint = selectedEndpoint.value
    if (!endpoint) {
      syncState.value = 'error'
      syncMessage.value = '请先选择一个 AI 目标'
      return
    }

    beginAction(`bind-token-${item.id}`, `正在绑定注册码 ${item.token_label}...`)
    try {
      await api.bindRuntimeEnrollmentToken(item.id, { ai_endpoint_id: endpoint.id })
      await refreshEndpoints()
      finishAction(`已将 ${item.token_label} 绑定到 ${endpoint.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function unbindToken(item: RuntimeEnrollmentTokenItem) {
    beginAction(`unbind-token-${item.id}`, `正在解绑注册码 ${item.token_label}...`)
    try {
      await api.bindRuntimeEnrollmentToken(item.id, { ai_endpoint_id: null })
      await refreshEndpoints()
      finishAction(`已解绑 ${item.token_label}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function bindRuntimeToSelected(item: ManagedRuntimeItem) {
    const endpoint = selectedEndpoint.value
    if (!endpoint) {
      syncState.value = 'error'
      syncMessage.value = '请先选择一个 AI 目标'
      return
    }

    beginAction(`bind-runtime-${item.id}`, `正在绑定 Runtime ${item.display_name}...`)
    try {
      await api.bindManagedRuntime(item.id, { ai_endpoint_id: endpoint.id })
      await refreshEndpoints()
      finishAction(`已将 ${item.display_name} 绑定到 ${endpoint.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function unbindRuntime(item: ManagedRuntimeItem) {
    beginAction(`unbind-runtime-${item.id}`, `正在解绑 Runtime ${item.display_name}...`)
    try {
      await api.bindManagedRuntime(item.id, { ai_endpoint_id: null })
      await refreshEndpoints()
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
      await refreshEndpoints()
      finishAction(`已批准 ${item.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  async function approveAndBindRuntime(item: ManagedRuntimeItem) {
    const endpoint = selectedEndpoint.value
    if (!endpoint) {
      syncState.value = 'error'
      syncMessage.value = '请先选择一个 AI 目标'
      return
    }

    beginAction(`approve-bind-runtime-${item.id}`, `正在批准并绑定 ${item.display_name}...`)
    try {
      await api.approveManagedRuntime(item.id, { ai_endpoint_id: endpoint.id })
      await refreshEndpoints()
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
      await refreshEndpoints()
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
      await refreshEndpoints()
      finishAction(`已撤销 ${item.display_name}`)
    } catch (errorValue) {
      failAction(errorValue)
    }
  }

  function runtimeStatusLabel(item: ManagedRuntimeItem) {
    if (item.status === 'pending') return '待审批'
    if (item.status === 'approved') return '待领凭据'
    if (item.status === 'active') return '已接入'
    if (item.status === 'rejected') return '已拒绝'
    if (item.status === 'revoked') return '已撤销'
    return item.status
  }

  function runtimeStatusTone(item: ManagedRuntimeItem): Tone {
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

  function bindingStateLabel(item: { binding_state?: string | null }) {
    return item.binding_state === 'bound' ? '已绑定' : '未绑定'
  }

  function bindingStateTone(item: { binding_state?: string | null }): Tone {
    return item.binding_state === 'bound' ? 'safe' : 'info'
  }

  return {
    loading,
    error,
    activeGroup,
    selectedIds,
    selectedCount,
    selectedEndpointId,
    selectedEndpoint,
    selectedEndpointIntegration,
    endpointItems,
    endpointSummary,
    runtimeSummary,
    runtimeTokens,
    runtimeItems,
    unboundTokens,
    unboundRuntimes,
    filteredItems,
    groupOptions,
    topRailItems,
    cleanupCandidates,
    selectedEndpointTokens,
    selectedEndpointRuntimes,
    drawerOpen,
    drawerMode,
    drawerTitle,
    drawerSummary,
    drawerForm,
    testOutput,
    testUsage,
    runtimeTokenLabel,
    runtimeTokenType,
    runtimeTokenUsageLimit,
    runtimeTokenExpiresAt,
    latestEnrollmentToken,
    latestEnrollmentSteps,
    syncState,
    syncMessage,
    lastActionAt,
    isBusy,
    endpointTone,
    endpointStatusLabel,
    endpointSummaryText,
    endpointMetaText,
    openCreateDrawer,
    openEndpoint,
    closeDrawer,
    saveDrawer,
    testEndpoint,
    setEndpointDefault,
    toggleEndpointEnabled,
    toggleEndpointProtection,
    setEndpointProtectionMode,
    deleteEndpoint,
    cleanupEndpointCandidates,
    runBatchUpdate,
    refreshList,
    copyText,
    createRuntimeToken,
    bindTokenToSelected,
    unbindToken,
    bindRuntimeToSelected,
    unbindRuntime,
    approveRuntime,
    approveAndBindRuntime,
    rejectRuntime,
    revokeRuntime,
    runtimeStatusLabel,
    runtimeStatusTone,
    tokenStatusLabel,
    tokenStatusTone,
    bindingStateLabel,
    bindingStateTone,
    selectEndpoint,
    isSelected,
    clearSelection,
    handleSelectionChange,
    protectionModeLabels: PROTECTION_MODE_LABELS,
    providerLabels: PROVIDER_LABELS,
  }
}

function blankEndpointForm(activeGroup: string, endpointCount: number): EndpointForm {
  return {
    endpoint_key: '',
    display_name: '',
    endpoint_group: activeGroup !== 'all' ? activeGroup : 'default',
    provider_type: 'openai_compatible',
    base_url: '',
    api_key: '',
    model_name: '',
    enabled: true,
    is_default: endpointCount === 0,
    protection_enabled: true,
    protection_mode: 'enforce',
    description: '',
    config_public_text: '{}',
    config_secret_items: [],
    new_secret_path: '',
    new_secret_value: '',
  }
}

function fillDrawerForm(form: EndpointForm, item: AiEndpointItem) {
  Object.assign(form, {
    endpoint_key: item.endpoint_key,
    display_name: item.display_name,
    endpoint_group: normalizeGroup(item.endpoint_group),
    provider_type: item.provider_type,
    base_url: item.base_url,
    api_key: '',
    model_name: item.model_name,
    enabled: item.enabled,
    is_default: item.is_default,
    protection_enabled: item.protection_enabled,
    protection_mode: item.protection_mode,
    description: item.description,
    config_public_text: JSON.stringify(item.config_public_json ?? {}, null, 2),
    config_secret_items: (item.config_secret_items ?? []).map((secret) => ({
      ...secret,
      next_value: '',
      remove: false,
    })),
    new_secret_path: '',
    new_secret_value: '',
  } satisfies EndpointForm)
}

function parseConfigText(text: string) {
  const trimmed = text.trim()
  if (!trimmed) {
    return {}
  }

  const parsed = JSON.parse(trimmed)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('公开配置必须是 JSON 对象')
  }
  return parsed as Record<string, unknown>
}

function parseSecretInputValue(text: string): unknown {
  const trimmed = text.trim()
  if (!trimmed) {
    return ''
  }

  if (
    trimmed === 'true' ||
    trimmed === 'false' ||
    trimmed === 'null' ||
    /^-?\d+(?:\.\d+)?$/.test(trimmed) ||
    ((trimmed.startsWith('{') || trimmed.startsWith('[') || trimmed.startsWith('"')) &&
      (trimmed.endsWith('}') || trimmed.endsWith(']') || trimmed.endsWith('"')))
  ) {
    try {
      return JSON.parse(trimmed)
    } catch {
      return trimmed
    }
  }

  return trimmed
}

function buildSecretPayload(form: EndpointForm) {
  const config_secret_updates = form.config_secret_items
    .filter((item) => !item.remove && item.next_value.trim())
    .map((item) => ({
      path: item.path.trim(),
      value: parseSecretInputValue(item.next_value),
    }))

  const config_secret_remove_paths = form.config_secret_items
    .filter((item) => item.remove)
    .map((item) => item.path.trim())

  return {
    config_secret_updates,
    config_secret_remove_paths,
  }
}

function buildPayloadFromDrawer(form: EndpointForm, includeApiKey: boolean) {
  const endpointKey = normalizeEndpointKey(form.endpoint_key || form.display_name)
  if (!endpointKey) {
    throw new Error('端点标识不能为空')
  }
  if (!form.base_url.trim()) {
    throw new Error('接入地址不能为空')
  }
  if (!form.model_name.trim()) {
    throw new Error('模型名称不能为空')
  }

  const payload: Record<string, unknown> = {
    endpoint_key: endpointKey,
    display_name: form.display_name.trim() || endpointKey,
    endpoint_group: normalizeGroup(form.endpoint_group),
    provider_type: form.provider_type,
    base_url: form.base_url.trim(),
    model_name: form.model_name.trim(),
    enabled: form.enabled,
    is_default: form.is_default,
    protection_enabled: form.protection_enabled,
    protection_mode: form.protection_mode,
    description: form.description.trim(),
    config_public_json: parseConfigText(form.config_public_text),
    ...buildSecretPayload(form),
  }

  if (includeApiKey) {
    payload.api_key = form.api_key.trim()
  }

  return payload
}
