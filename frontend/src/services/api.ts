import { clearAuthSession, getAccessToken } from './auth'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'
type DefenseMode = 'enforce' | 'observe' | 'off'

export type SystemActionTone = 'safe' | 'warn' | 'danger' | 'info'
export type SystemActionKey =
  | 'export-defense-config'
  | 'platform-backup'
  | 'refresh-permission-cache'
  | 'send-test-email'
export type FormFieldTone = SystemActionTone

export type FormFieldOption = {
  label: string
  value: string
  tone?: FormFieldTone
}

export type FormFieldMeta = {
  control: 'text' | 'password' | 'select' | 'segmented' | 'toggle' | 'token-input'
  placeholder: string
  helper_text: string
  options: FormFieldOption[]
  button_text?: string
  empty_text?: string
}

export type SystemActionDefinition = {
  action_key: SystemActionKey
  action_label: string
  detail: string
  button_text: string
  tone: SystemActionTone
  method: string
  status: string
}

export type SystemSettingFieldOption = FormFieldOption
export type SystemSettingFieldMeta = FormFieldMeta

export type SystemSettingItem = {
  setting_key: string
  setting_value: string
  description: string
  field_meta: SystemSettingFieldMeta
}

export type DefenseConfigFieldMeta = {
  enabled: FormFieldMeta
  mode: FormFieldMeta
}

export type DefenseCoverageSection = {
  label: string
  value: string
  entry_count: number
  risk_level?: string
  attack_stage?: string
}

export type DefenseCoveragePack = {
  label: string
  value: string
  entry_count: number
  test_mode?: string
}

export type DefenseCoverageMap = {
  summary_text: string
  sample_count: number
  section_count: number
  pack_count: number
  matched_sections: DefenseCoverageSection[]
  matched_packs: DefenseCoveragePack[]
  attack_surfaces: string[]
  attack_families: string[]
  attack_stages: string[]
}

export type DefenseConfigItem = {
  id: number
  defense_name: string
  defense_type: string
  threat_level: string
  mode: string
  enabled: boolean
  description: string
  config_json?: Record<string, unknown>
  coverage_map?: DefenseCoverageMap
  field_meta: DefenseConfigFieldMeta
  display_label?: string
  category_key?: string
  category_label?: string
  category_order?: number
  tone?: FormFieldTone
  surface_keys?: string[]
  surface_labels?: string[]
  stage_keys?: string[]
  stage_labels?: string[]
}

export type DefensePolicyRule = {
  key: string
  title: string
  description: string
  enabled: boolean
  mode: DefenseMode
  field_meta: DefenseConfigFieldMeta
  display_label?: string
  display_description?: string
  category_key?: string
  category_label?: string
  category_order?: number
  tone?: FormFieldTone
  surface_keys?: string[]
  surface_labels?: string[]
  stage_keys?: string[]
  stage_labels?: string[]
}

export type AiReviewMode = 'rules_only' | 'suspicious_review' | 'review_all_remaining'

export type AiReviewPolicy = {
  key: string
  title: string
  description: string
  mode: AiReviewMode
  field_meta: FormFieldMeta
  display_label?: string
  display_description?: string
  category_key?: string
  category_label?: string
  category_order?: number
  tone?: FormFieldTone
  surface_keys?: string[]
  surface_labels?: string[]
  stage_keys?: string[]
  stage_labels?: string[]
}

export type DefenseResourceGroup = {
  kind: 'path' | 'skill' | 'plugin'
  title: string
  description: string
  field_meta: FormFieldMeta
}

export type DefensePolicyProfile = {
  guard_rules: DefensePolicyRule[]
  scan_rules: DefensePolicyRule[]
  advanced_rule: DefensePolicyRule
  ai_review_policy: AiReviewPolicy
  protected_paths: string[]
  protected_skills: string[]
  protected_plugins: string[]
  resource_groups: DefenseResourceGroup[]
  global_field_meta: DefenseConfigFieldMeta
}

export type AssetFieldMeta = {
  status: FormFieldMeta
  risk_level: FormFieldMeta
}

export type AssetItem = {
  id: number
  asset_name: string
  asset_type: string
  asset_path: string
  risk_level: string
  status: string
  field_meta: AssetFieldMeta
}

export type AssetWhitelistFieldMeta = {
  whitelist_type: FormFieldMeta
  rule_value: FormFieldMeta
  description: FormFieldMeta
}

export type AssetWhitelistItem = {
  id: number
  asset_id: number
  whitelist_type: string
  rule_value: string
  description: string
}

export type SkillFieldMeta = {
  source_path: FormFieldMeta
  trust_status: FormFieldMeta
}

export type SkillCreateFieldMeta = {
  skill_name: FormFieldMeta
  skill_type: FormFieldMeta
  provider: FormFieldMeta
  source_path: FormFieldMeta
  trust_status: FormFieldMeta
}

export type SkillCreateMeta = {
  title: string
  helper_text: string
  submit_button_text: string
  field_meta: SkillCreateFieldMeta
}

export type SkillDirectoryImportFieldMeta = {
  directory_path: FormFieldMeta
  skill_type: FormFieldMeta
  provider: FormFieldMeta
  trust_status: FormFieldMeta
}

export type SkillDirectoryImportMeta = {
  title: string
  helper_text: string
  preview_button_text: string
  confirm_button_text: string
  recursive_enabled_text: string
  recursive_disabled_text: string
  recursive_default: boolean
  preview_title: string
  preview_empty_text: string
  field_meta: SkillDirectoryImportFieldMeta
}

export type SkillIntakeMeta = {
  create_skill: SkillCreateMeta
  directory_import: SkillDirectoryImportMeta
}

export type SkillScanSelectionMessagesMeta = {
  select_pending_template: string
  select_pending_empty_text: string
  clear_selection_text: string
  missing_selection_text: string
  scan_creating_template: string
  scan_completed_template: string
  scan_queued_template: string
  task_refresh_failed_text: string
  task_finished_template: string
  task_failed_template: string
  scan_create_failed_text: string
  event_suffix_template: string
  report_suffix_template: string
}

export type SkillTaskStatusMeta = {
  label: string
  tone: FormFieldTone
}

export type SkillActionButton = {
  action_key: string
  label: string
  tone: 'primary' | 'ghost'
  disabled?: boolean
  requires_selection?: boolean
  toggle_state_key?: string
  alternate_label?: string
}

export type SkillActionSummaryItem = {
  key: string
  template: string
  source: 'selected' | 'pending'
  display: 'pill' | 'text'
  tone?: FormFieldTone
  empty_tone?: FormFieldTone
}

export type SkillControlActionField = {
  key: string
  field_meta: FormFieldMeta
}

export type SkillControlActionDefinition = {
  key: string
  action_type: 'selection_toolbar' | 'form'
  title: string
  helper_text?: string
  model_key?: 'create_skill' | 'directory_import'
  fields?: SkillControlActionField[]
  summary_items?: SkillActionSummaryItem[]
  buttons?: SkillActionButton[]
  secondary_actions?: SkillActionButton[]
  submit_action?: SkillActionButton
  messages?: SkillScanSelectionMessagesMeta
  task_status_map?: Record<string, SkillTaskStatusMeta>
}

export type SkillActionMeta = {
  actions: SkillControlActionDefinition[]
}

export type SkillItem = {
  id: number
  skill_name: string
  skill_type: string
  provider: string
  source_path: string
  source_path_state: 'ready' | 'missing' | 'unconfigured' | string
  resolved_source_path: string
  trust_status: string
  created_at: string
  field_meta: SkillFieldMeta
}

export type SkillImportResponse = {
  created: number
  updated: number
  skipped: number
  items: SkillItem[]
  skipped_items: Array<{
    skill_name: string
    source_path: string
    action?: 'create' | 'update' | 'skip'
    action_label?: string
    action_tone?: FormFieldTone
    reason: string
    reason_label?: string
    reason_tone?: FormFieldTone
  }>
}

export type SkillImportPreviewItem = {
  skill_name: string
  source_path: string
  action: 'create' | 'update' | 'skip'
  action_label: string
  action_tone: FormFieldTone
  reason: string
  reason_label: string
  reason_tone: FormFieldTone
  existing_skill_id?: number | null
}

export type SkillImportPreviewSummaryItem = {
  key: string
  text: string
  value: number
  tone: FormFieldTone
}

export type SkillResultPanelBadge = {
  key: string
  text: string
  tone: FormFieldTone
}

export type SkillResultPanelItem = {
  key: string
  title: string
  subtitle: string
  badges: SkillResultPanelBadge[]
}

export type SkillResultPanel = {
  key: string
  panel_type: 'result_panel'
  title: string
  summary_text: string
  detail_text: string
  empty_text: string
  summary_items: SkillImportPreviewSummaryItem[]
  actions: SkillActionButton[]
  items: SkillResultPanelItem[]
}

export type SkillResultListItem = {
  key: string
  task_id?: number | null
  status: string
  title: string
  subtitle: string
  summary_text: string
  meta_text: string
  badges: SkillResultPanelBadge[]
  meta_badges: SkillResultPanelBadge[]
}

export type SkillResultList = {
  key: string
  panel_type: 'result_list'
  title: string
  empty_text: string
  total: number
  page: number
  page_size: number
  items: SkillResultListItem[]
}

export type SkillResultBlockSection = {
  id: string
  eyebrow: string
  title: string
  tag: string
  tone: FormFieldTone
}

export type SkillResultBlock = {
  key: string
  block_type: 'result_panel' | 'result_list'
  section: SkillResultBlockSection
  result_panel?: SkillResultPanel | null
  result_list?: SkillResultList | null
}

export type SkillResultMeta = {
  panels: SkillResultPanel[]
  lists: SkillResultList[]
  blocks: SkillResultBlock[]
}

export type SkillImportPreviewResponse = {
  title: string
  base_directory: string
  detected: number
  created: number
  updated: number
  skipped: number
  confirm_button_text: string
  empty_text: string
  summary_text: string
  summary_items: SkillImportPreviewSummaryItem[]
  items: SkillImportPreviewItem[]
  result_panel: SkillResultPanel
  result_blocks: SkillResultBlock[]
}

export type GuardRuleAssessment = {
  verdict: string
  summary: string
  detail: string
  hit_rules: string[]
  matched_signals: string[]
}

export type GuardTrace = {
  decision: string
  summary: string
  detail: string
  matched_controls: string[]
  matched_rules: string[]
  source: string
  reused: boolean
  ai_review_mode: string
  ai_review_invoked: boolean
  review_decision: string
  rule_verdict: string
  rule_assessment?: GuardRuleAssessment | null
}

export type SecurityEventSummary = {
  id: number
  task_id?: number | null
  event_type: string
  event_level: string
  source: string
  target: string
  status: string
  created_at: string
  detail: string
  hit_rules?: string[]
  hit_rule_details?: SecurityTriggerItem[]
  guard_trace?: GuardTrace | null
  trigger_summary?: string
  trigger_support_text?: string
  trigger_sections?: SecurityTriggerSection[]
}

export type SecurityEventDetail = SecurityEventSummary & {
  hit_rules: string[]
  raw_input: string
  result: string
  operation_logs: Array<{ operator: string; action: string; time: string }>
}

export type SecurityReportPayloadItem = {
  kind: 'control' | 'rule' | 'signal' | 'pattern'
  label: string
  detail: string
  source: string
  location: string
  evidence: string
  display_label?: string
  detail_label?: string
  category_key?: string
  category_label?: string
  tone?: FormFieldTone
  source_label?: string
  location_label?: string
  mapped_rule_key?: string
  mapped_rule_label?: string
}

export type SecurityTriggerItem = {
  key: string
  label: string
  detail: string
  category_key?: string
  category_label?: string
  tone: FormFieldTone
  kind?: 'control' | 'rule' | 'signal'
  surface_labels?: string[]
  stage_labels?: string[]
}

export type SecurityTriggerSection = {
  key: 'control' | 'rule' | 'signal'
  label: string
  tone: FormFieldTone
  summary: string
  items: SecurityTriggerItem[]
}

export type SensitiveFindingCategory = {
  category: string
  label: string
  count: number
}

export type SensitiveFindingItem = {
  category: string
  label: string
  source: string
  location: string
  preview: string
}

export type SecurityReportRawSection = {
  key: string
  title: string
  format: 'json' | 'text'
  content: unknown
}

export type SecurityEventReportView = {
  event: SecurityEventDetail
  task: AttackTaskItem | null
  report: ReportItem | null
  payload_detection: {
    summary_text: string
    total: number
    items: SecurityReportPayloadItem[]
  }
  sensitive_findings: {
    summary_text: string
    total: number
    categories: SensitiveFindingCategory[]
    items: SensitiveFindingItem[]
  }
  raw_sections: SecurityReportRawSection[]
}

export type ReportItem = {
  id: number
  report_name: string
  report_type: string
  task_id: number
  file_path: string
  summary_text: string
  created_by: number
  created_at: string
  artifact_exists?: boolean
  download_url?: string
  download_urls?: Record<string, string>
  supported_formats?: string[]
  available_formats?: string[]
  artifact_path?: string
  artifact_format?: string
  artifact_download_url?: string
}

export type AttackTaskItem = {
  id: number
  task_name: string
  attack_type: string
  target_agent: string
  ai_endpoint?: {
    id?: number | null
    endpoint_key: string
    display_name: string
    endpoint_group?: string
    provider_type: string
    base_url: string
    model_name: string
    protection_enabled: boolean
    protection_mode: string
    source: string
  } | null
  status: string
  source_type?: string | null
  source_ref?: string | null
  execution_mode?: string | null
  runtime_name?: string | null
  runtime_task_ref?: string | null
  params_json: Record<string, unknown>
  raw_response?: string
  result_summary?: string
  latest_event_id?: number | null
  latest_report_id?: number | null
  created_by?: number | null
  scheduled_at?: string | null
  started_at?: string | null
  finished_at?: string | null
  last_heartbeat_at?: string | null
  created_at?: string
  updated_at?: string
  guard_trace?: GuardTrace | null
}

export type AttackTaskExecutionResult = {
  task: AttackTaskItem
  event: SecurityEventSummary | null
  report: ReportItem | null
}

export type AttackWorkerStatus = {
  status: string
  queued_tasks: number
  active_task_id: number | null
  scheduled_tasks: number
}

export type AiEndpointConfigSecretItem = {
  path: string
  key: string
  masked_value: string
  value_type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'null'
}

export type AiEndpointRouteSelectorItem = {
  key: string
  label: string
  value: string
  detail: string
}

export type AiEndpointAuthMode = {
  key: string
  label: string
  header_name: string
  header_value: string
  summary: string
  recommended: boolean
}

export type AiEndpointAccessRoute = {
  key: string
  label: string
  method: string
  path: string
  summary: string
}

export type AiEndpointAccessMode = {
  key: string
  label: string
  summary: string
  detail: string
  routes: AiEndpointAccessRoute[]
  step_items: string[]
  sample_lines: string[]
}

export type AiEndpointIntegrationView = {
  gateway_base_path: string
  gateway_ws_base_path: string
  protection_summary: string
  default_route_summary: string
  route_selector_items: AiEndpointRouteSelectorItem[]
  auth_modes: AiEndpointAuthMode[]
  access_modes: AiEndpointAccessMode[]
}

export type AiEndpointItem = {
  id: number
  endpoint_key: string
  display_name: string
  endpoint_group: string
  provider_type: 'openai_compatible' | 'anthropic' | 'azure_openai' | 'gemini' | 'ollama' | 'bedrock'
  base_url: string
  model_name: string
  enabled: boolean
  is_default: boolean
  protection_enabled: boolean
  protection_mode: 'enforce' | 'observe' | 'off'
  description: string
  config_public_json: Record<string, unknown>
  config_secret_items: AiEndpointConfigSecretItem[]
  config_secret_count: number
  config_secret_summary: string
  integration_view: AiEndpointIntegrationView
  has_api_key: boolean
  api_key_hint: string
  usage_summary: {
    token_count: number
    runtime_count: number
    runtime_pending_count: number
    runtime_active_count: number
    runtime_online_count: number
    task_count: number
    active_task_count: number
    last_runtime_seen_at: string
  }
  is_demo_endpoint: boolean
  is_cleanup_candidate: boolean
  created_at: string
  updated_at: string
}

export type AiEndpointSummary = {
  total: number
  enabled: number
  protected: number
  default_id: number | null
  default_display_name?: string | null
  default_group?: string | null
  group_count?: number
  cleanup_candidates?: number
}

export type RuntimeBindingEndpoint = {
  id?: number | null
  endpoint_key: string
  display_name: string
  endpoint_group?: string
  provider_type: string
  base_url: string
  model_name: string
  protection_enabled: boolean
  protection_mode: string
  source: string
}

export type RuntimeEnrollmentTokenItem = {
  id: number
  token_key: string
  token_label: string
  token_hint: string
  runtime_type: string
  status: string
  usage_limit: number
  used_count: number
  remaining_uses: number
  expires_at: string
  created_at: string
  updated_at: string
  ai_endpoint: RuntimeBindingEndpoint | null
  binding_state: 'bound' | 'unbound' | string
}

export type ManagedRuntimeItem = {
  id: number
  registration_id: string
  display_name: string
  runtime_type: string
  runtime_key: string
  runtime_secret_hint: string
  status: string
  hostname: string
  fingerprint: string
  client_version: string
  ip_addresses: string[]
  requested_scopes: string[]
  capabilities: string[]
  metadata: Record<string, unknown>
  ai_endpoint: RuntimeBindingEndpoint | null
  approved_at: string
  rejected_at: string
  revoked_at: string
  last_seen_at: string
  credential_delivered_at: string
  created_at: string
  updated_at: string
  rejection_reason: string
  binding_state: 'bound' | 'unbound' | string
  status_summary: string
  is_online: boolean
}

export type RuntimeRegistrySummary = {
  tokens_total: number
  tokens_active: number
  runtimes_total: number
  runtimes_pending: number
  runtimes_approved: number
  runtimes_active: number
  tokens_unbound: number
  runtimes_unbound: number
  runtimes_online: number
}

export type RuntimeRegistryPayload = {
  summary: RuntimeRegistrySummary
  tokens: RuntimeEnrollmentTokenItem[]
  runtimes: ManagedRuntimeItem[]
  unbound_tokens: RuntimeEnrollmentTokenItem[]
  unbound_runtimes: ManagedRuntimeItem[]
}

export type SampleCatalogSummary = {
  total_entries: number
  by_source: Record<string, number>
  by_family: Record<string, number>
  by_section: Record<string, number>
  classification_groups?: SampleClassificationGroup[]
}

export type SampleClassification = {
  primary_key: string
  primary_label: string
  section_key: string
  section_label: string
  family_key: string
  family_label: string
  surface_key: string
  surface_label: string
  risk_key: string
  risk_label: string
  stage_key: string
  stage_label: string
  test_mode_key: string
  test_mode_label: string
  source_label: string
}

export type SampleSectionClassification = {
  primary_key: string
  primary_label: string
  section_key: string
  section_label: string
  surface_key: string
  surface_label: string
  risk_key: string
  risk_label: string
  stage_key: string
  stage_label: string
}

export type SampleClassificationGroup = {
  key: string
  label: string
  entry_count: number
  section_count: number
  sections: string[]
}

export type SampleSectionItem = {
  section_name: string
  handbook_file: string
  catalog_file: string
  entry_count: number
  sources: Record<string, number>
  families: Record<string, number>
  risk_level: string
  attack_stage: string
  classification?: SampleSectionClassification
}

export type SamplePackItem = {
  pack_name: string
  pack_file: string
  mapped_section: string
  entry_count: number
  families: Record<string, number>
  test_mode: string
  input_format: string
  runner_hint: string
  description: string
  classification?: (SampleSectionClassification & {
    test_mode_key: string
    test_mode_label: string
  })
}

export type SampleListItem = {
  id: string
  title: string
  attack_family: string
  mapped_section: string
  risk_level: string
  attack_stage: string
  expected_behavior: string
  source_repo: string
  source_file: string
  test_mode: string
  turn_count: number
  content_preview: string
  tags: string[]
  classification?: SampleClassification
}

export type SampleTurn = {
  role: string
  stage?: string
  content: string
}

export type SampleDetail = {
  id: string
  title: string
  content: string
  attack_family: string
  mapped_section: string
  risk_level: string
  attack_stage: string
  expected_behavior: string
  source_repo: string
  source_file: string
  source_family?: string
  test_mode?: string
  turns?: SampleTurn[]
  metadata?: Record<string, unknown>
  classification?: SampleClassification
}

export type SampleListResponse = {
  items: SampleListItem[]
  total: number
  page: number
  page_size: number
  filters: {
    section: string | null
    pack: string | null
    attack_family: string | null
    risk_level: string | null
    test_mode: string | null
    source_repo: string | null
    keyword: string | null
  }
}

export type AttackTaskFromSampleResponse = {
  task: AttackTaskItem
  sample: SampleDetail
  enqueued: boolean
}

export type AttackTaskDispatchResponse = {
  items: AttackTaskItem[]
  enqueued_task_ids: number[]
  scheduled_at: string | null
}

export type AttackTaskBatchCreateResponse = {
  items: AttackTaskItem[]
  created: number
  enqueued_task_ids: number[]
  scheduled: boolean
}

export type DownloadedFile = {
  blob: Blob
  filename: string
}

type ApiEnvelope<T> = {
  code: number
  message: string
  data: T
}

function buildNetworkError(error: unknown) {
  if (error instanceof TypeError) {
    const currentOrigin = typeof window === 'undefined' ? 'unknown' : window.location.origin
    return new Error(
      `无法连接后端接口 ${API_BASE_URL}。当前页面来源是 ${currentOrigin}，请确认后端已启动且已放行该来源。`
    )
  }
  return error instanceof Error ? error : new Error('请求失败')
}

function buildQuery(params: Record<string, string | number | boolean | null | undefined>) {
  const searchParams = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') {
      continue
    }
    searchParams.set(key, String(value))
  }
  const query = searchParams.toString()
  return query ? `?${query}` : ''
}

async function handleHttpError<T>(response: Response): Promise<never> {
  let message = `HTTP ${response.status}`
  const contentType = response.headers.get('Content-Type') || ''

  if (contentType.includes('application/json')) {
    try {
      const payload = (await response.json()) as ApiEnvelope<T>
      message = payload.message || message
    } catch {
      // Ignore malformed error payloads.
    }
  } else {
    try {
      const text = await response.text()
      if (text) {
        message = text
      }
    } catch {
      // Ignore non-text failure payloads.
    }
  }

  if (response.status === 401) {
    clearAuthSession()
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      const redirect = `${window.location.pathname}${window.location.search}`
      window.location.assign(`/login?redirect=${encodeURIComponent(redirect)}`)
    }
  }

  throw new Error(message)
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAccessToken()
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {})
      },
      ...init
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  if (!response.ok) {
    return handleHttpError<T>(response)
  }

  const payload = (await response.json()) as ApiEnvelope<T>
  if (payload.code !== 0) {
    throw new Error(payload.message || '接口返回失败')
  }

  return payload.data
}

async function requestBlob(path: string, init?: RequestInit): Promise<DownloadedFile> {
  const token = getAccessToken()
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {})
      },
      ...init
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  if (!response.ok) {
    return handleHttpError(response)
  }

  const blob = await response.blob()
  const disposition = response.headers.get('Content-Disposition') || ''
  const matchedFilename = disposition.match(/filename="?([^"]+)"?$/i)
  return {
    blob,
    filename: matchedFilename?.[1] || 'report.json'
  }
}

export const api = {
  dashboardOverview: () =>
    request<{
      attack_count: number
      blocked_count: number
      enabled_defense_count: number
      high_risk_event_count: number
      active_task_count: number
    }>('/dashboard/overview'),
  dashboardTrends: () =>
    request<{
      range: string
      items: Array<{ day: string; attack: number; block: number; false_positive: number }>
    }>('/dashboard/trends'),
  dashboardSessions: () =>
    request<{
      items: Array<{ session_id: string; session_name: string; status: string; risk_level: string }>
      total: number
    }>('/dashboard/sessions'),
  defenseConfigs: () =>
    request<{
      items: DefenseConfigItem[]
      total: number
    }>('/defense-configs'),
  defensePolicy: () => request<DefensePolicyProfile>('/defense-configs/profile'),
  updateDefenseConfig: (
    defenseId: number,
    payload: {
      enabled: boolean
      mode: string
      config_json: Record<string, unknown>
    }
  ) =>
    request<DefenseConfigItem>(`/defense-configs/${defenseId}`, {
      method: 'PUT',
      body: JSON.stringify(payload)
    }),
  batchUpdateDefenseConfigs: (payload: { ids: number[]; enabled?: boolean; mode?: string }) =>
    request<{
      items: DefenseConfigItem[]
      total: number
    }>('/defense-configs/batch-update', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  updateDefensePolicy: (payload: {
    guard_rules: Array<{
      key: string
      title: string
      description: string
      enabled: boolean
      mode: DefenseMode
    }>
    scan_rules: Array<{
      key: string
      title: string
      description: string
      enabled: boolean
      mode: DefenseMode
    }>
    advanced_rule: {
      key: string
      title: string
      description: string
      enabled: boolean
      mode: DefenseMode
    }
    ai_review_policy: {
      key: string
      title: string
      description: string
      mode: AiReviewMode
    }
    protected_paths: string[]
    protected_skills: string[]
    protected_plugins: string[]
  }) =>
    request<DefensePolicyProfile>('/defense-configs/profile', {
      method: 'PUT',
      body: JSON.stringify(payload)
    }),
  securityEvents: (params?: {
    page?: number
    page_size?: number
    event_type?: string
    event_level?: string
    status?: string
    keyword?: string
    start_time?: string
    end_time?: string
  }) =>
    request<{
      items: SecurityEventSummary[]
      total: number
      page: number
      page_size: number
    }>(`/security-events${buildQuery(params ?? {})}`),
  securityEvent: (eventId: number) => request<SecurityEventDetail>(`/security-events/${eventId}`),
  securityEventReportView: (eventId: number) =>
    request<SecurityEventReportView>(`/security-events/${eventId}/report-view`),
  updateSecurityEventStatus: (eventId: number, status: string) =>
    request<SecurityEventSummary>(`/security-events/${eventId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status })
    }),
  batchHandleSecurityEvents: (payload: { ids: number[]; status: string }) =>
    request<{
      items: SecurityEventSummary[]
      total: number
    }>('/security-events/batch-handle', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  assets: () =>
    request<{
      items: AssetItem[]
      total: number
    }>('/assets'),
  updateAsset: (
    assetId: number,
    payload: {
      asset_name: string
      asset_type: string
      asset_path: string
      risk_level: string
      status: string
    }
  ) =>
    request<AssetItem>(`/assets/${assetId}`, {
      method: 'PUT',
      body: JSON.stringify(payload)
    }),
  assetWhitelists: (assetId: number) =>
    request<{
      items: AssetWhitelistItem[]
      total: number
      field_meta: AssetWhitelistFieldMeta
    }>(`/assets/${assetId}/whitelists`),
  createAssetWhitelist: (
    assetId: number,
    payload: {
      whitelist_type: string
      rule_value: string
      description: string
    }
  ) =>
    request<AssetWhitelistItem>(`/assets/${assetId}/whitelists`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  deleteAssetWhitelist: (whitelistId: number) =>
    request<AssetWhitelistItem>(`/assets/whitelists/${whitelistId}`, {
      method: 'DELETE'
    }),
  skills: (params?: {
    page?: number
    page_size?: number
    scan_task_page?: number
    scan_task_page_size?: number
  }) =>
    request<{
      items: SkillItem[]
      total: number
      page: number
      page_size: number
      intake_meta: SkillIntakeMeta
      action_meta: SkillActionMeta
      result_meta: SkillResultMeta
    }>(`/skills${buildQuery(params ?? {})}`),
  createSkill: (payload: {
    skill_name: string
    skill_type: string
    provider: string
    source_path: string
    trust_status: string
  }) =>
    request<SkillItem>('/skills', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  importSkillDirectory: (payload: {
    directory_path: string
    skill_type: string
    provider: string
    trust_status: string
    recursive: boolean
  }) =>
    request<SkillImportResponse>('/skills/import-directory', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  previewSkillDirectoryImport: (payload: {
    directory_path: string
    skill_type: string
    provider: string
    trust_status: string
    recursive: boolean
  }) =>
    request<SkillImportPreviewResponse>('/skills/import-directory/preview', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  updateSkillTrustStatus: (skillId: number, trust_status: string) =>
    request<SkillItem>(`/skills/${skillId}/trust-status`, {
      method: 'PUT',
      body: JSON.stringify({ trust_status })
    }),
  updateSkillSourcePath: (skillId: number, source_path: string) =>
    request<SkillItem>(`/skills/${skillId}/source-path`, {
      method: 'PUT',
      body: JSON.stringify({ source_path })
    }),
  scanSkills: (skill_ids: number[]) =>
    request<AttackTaskItem>('/skills/scan', {
      method: 'POST',
      body: JSON.stringify({ skill_ids })
    }),
  aiEndpoints: () =>
    request<{
      items: AiEndpointItem[]
      summary: AiEndpointSummary
    }>('/ai-endpoints'),
  runtimeRegistry: () => request<RuntimeRegistryPayload>('/runtime-registry'),
  createRuntimeEnrollmentToken: (payload: {
    token_label: string
    runtime_type: string
    ai_endpoint_id?: number
    usage_limit: number
    expires_at?: string | null
  }) =>
    request<{
      token: RuntimeEnrollmentTokenItem
      enrollment_token: string
      onboarding_steps: string[]
    }>('/runtime-registry/tokens', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  bindRuntimeEnrollmentToken: (
    tokenId: number,
    payload: {
      ai_endpoint_id?: number | null
    }
  ) =>
    request<{
      token: RuntimeEnrollmentTokenItem
    }>(`/runtime-registry/tokens/${tokenId}/bind`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  approveManagedRuntime: (
    runtimeId: number,
    payload?: {
      display_name?: string
      ai_endpoint_id?: number | null
    }
  ) =>
    request<{
      runtime: ManagedRuntimeItem
      status_summary: string
    }>(`/runtime-registry/runtimes/${runtimeId}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload ?? {})
    }),
  bindManagedRuntime: (
    runtimeId: number,
    payload?: {
      display_name?: string
      ai_endpoint_id?: number | null
    }
  ) =>
    request<{
      runtime: ManagedRuntimeItem
      status_summary: string
    }>(`/runtime-registry/runtimes/${runtimeId}/bind`, {
      method: 'POST',
      body: JSON.stringify(payload ?? {})
    }),
  rejectManagedRuntime: (runtimeId: number, reason: string) =>
    request<{
      runtime: ManagedRuntimeItem
      status_summary: string
    }>(`/runtime-registry/runtimes/${runtimeId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason })
    }),
  revokeManagedRuntime: (runtimeId: number) =>
    request<{
      runtime: ManagedRuntimeItem
      status_summary: string
    }>(`/runtime-registry/runtimes/${runtimeId}/revoke`, {
      method: 'POST'
    }),
  aiEndpoint: (endpointId: number) => request<AiEndpointItem>(`/ai-endpoints/${endpointId}`),
  createAiEndpoint: (payload: {
    endpoint_key: string
    display_name: string
    endpoint_group?: string
    provider_type: 'openai_compatible' | 'anthropic' | 'azure_openai' | 'gemini' | 'ollama' | 'bedrock'
    base_url: string
    api_key?: string
    model_name: string
    enabled: boolean
    is_default: boolean
    protection_enabled: boolean
    protection_mode: 'enforce' | 'observe' | 'off'
    description?: string
    config_json?: Record<string, unknown>
    config_public_json?: Record<string, unknown>
    config_secret_updates?: Array<{ path: string; value: unknown }>
    config_secret_remove_paths?: string[]
  }) =>
    request<AiEndpointItem>('/ai-endpoints', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  updateAiEndpoint: (
    endpointId: number,
    payload: Partial<{
      endpoint_key: string
      display_name: string
      endpoint_group: string
      provider_type: 'openai_compatible' | 'anthropic' | 'azure_openai' | 'gemini' | 'ollama' | 'bedrock'
      base_url: string
      api_key: string
      model_name: string
      enabled: boolean
      is_default: boolean
      protection_enabled: boolean
      protection_mode: 'enforce' | 'observe' | 'off'
      description: string
      config_json: Record<string, unknown>
      config_public_json: Record<string, unknown>
      config_secret_updates: Array<{ path: string; value: unknown }>
      config_secret_remove_paths: string[]
    }>
  ) =>
    request<AiEndpointItem>(`/ai-endpoints/${endpointId}`, {
      method: 'PUT',
      body: JSON.stringify(payload)
    }),
  batchUpdateAiEndpoints: (payload: {
    ids: number[]
    enabled?: boolean
    protection_enabled?: boolean
    protection_mode?: 'enforce' | 'observe' | 'off'
    endpoint_group?: string
  }) =>
    request<{
      items: AiEndpointItem[]
      summary: AiEndpointSummary
    }>('/ai-endpoints/batch-update', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  deleteAiEndpoint: (endpointId: number) =>
    request<{
      id: number
      endpoint_key: string
      display_name: string
      released_tokens: number
      released_runtimes: number
    }>(`/ai-endpoints/${endpointId}`, {
      method: 'DELETE'
    }),
  cleanupAiEndpointCandidates: () =>
    request<{
      deleted_count: number
      released_tokens: number
      released_runtimes: number
      items: Array<{
        id: number
        endpoint_key: string
        display_name: string
        released_tokens: number
        released_runtimes: number
      }>
    }>('/ai-endpoints/cleanup-candidates', {
      method: 'POST'
    }),
  testAiEndpoint: (endpointId: number) =>
    request<{
      endpoint: AiEndpointItem
      provider: string
      model: string
      output_text: string
      usage: Record<string, unknown>
    }>(`/ai-endpoints/${endpointId}/test`, {
      method: 'POST'
    }),
  runAttackTask: (taskId: number) =>
    request<AttackTaskExecutionResult>(`/attack-tasks/${taskId}/run`, {
      method: 'POST'
    }),
  attackTasks: (params?: {
    page?: number
    page_size?: number
    attack_type?: string
    status?: string
    source_type?: string
    execution_mode?: string
    ai_endpoint_id?: number
    keyword?: string
  }) =>
    request<{
      items: AttackTaskItem[]
      total: number
      page: number
      page_size: number
    }>(`/attack-tasks${buildQuery(params ?? {})}`),
  attackTask: (taskId: number) => request<AttackTaskItem>(`/attack-tasks/${taskId}`),
  attackWorkerStatus: () => request<AttackWorkerStatus>('/attack-tasks/worker/status'),
  createAttackTask: (payload: {
    task_name: string
    attack_type: string
    target_agent: string
    ai_endpoint_id?: number
    params_json: Record<string, unknown>
  }) =>
    request<AttackTaskItem>('/attack-tasks', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  createAttackTaskFromSample: (payload: {
    sample_id: string
    target_agent: string
    ai_endpoint_id?: number
    task_name?: string
    params_json?: Record<string, unknown>
    auto_run?: boolean
    schedule_at?: string
  }) =>
    request<AttackTaskFromSampleResponse>('/attack-tasks/from-sample', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  createAttackTasksFromSamples: (payload: {
    sample_ids: string[]
    target_agent: string
    ai_endpoint_id?: number
    params_json?: Record<string, unknown>
    auto_run?: boolean
    schedule_at?: string
  }) =>
    request<AttackTaskBatchCreateResponse>('/attack-tasks/batch-from-samples', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  dispatchAttackTasks: (payload: { task_ids: number[]; schedule_at?: string }) =>
    request<AttackTaskDispatchResponse>('/attack-tasks/dispatch', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  sampleCatalogSummary: () => request<SampleCatalogSummary>('/samples/summary'),
  sampleSections: () =>
    request<{
      items: SampleSectionItem[]
    }>('/samples/sections'),
  samplePacks: () =>
    request<{
      items: SamplePackItem[]
    }>('/samples/packs'),
  samples: (params?: {
    page?: number
    page_size?: number
    section?: string
    pack?: string
    attack_family?: string
    risk_level?: string
    test_mode?: string
    source_repo?: string
    keyword?: string
  }) => request<SampleListResponse>(`/samples${buildQuery(params ?? {})}`),
  sampleDetail: (sampleId: string) => request<SampleDetail>(`/samples/${encodeURIComponent(sampleId)}`),
  reports: (params?: { page?: number; page_size?: number; report_type?: string; task_id?: number; keyword?: string }) =>
    request<{
      items: ReportItem[]
      total: number
      page: number
      page_size: number
    }>(`/reports${buildQuery(params ?? {})}`),
  report: (reportId: number) => request<ReportItem>(`/reports/${reportId}`),
  exportReport: (reportId: number, format = 'docx') =>
    request<ReportItem>(`/reports/${reportId}/export${buildQuery({ format })}`, {
      method: 'POST'
    }),
  downloadReport: (reportId: number, format = 'docx') =>
    requestBlob(`/reports/${reportId}/download${buildQuery({ format })}`),
  downloadReportBundle: (payload: { task_ids: number[]; include_manifest?: boolean; formats?: string[] }) =>
    requestBlob('/reports/batch-download', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    }),
  systemSettings: () =>
    request<{
      items: SystemSettingItem[]
      total: number
    }>('/system-settings'),
  updateSystemSetting: (setting_key: string, setting_value: string) =>
    request<{
      setting: SystemSettingItem
      audit_log: {
        id: number
        user_id: number
        module: string
        action: string
        detail: string
        created_at: string
      }
    }>(`/system-settings/${setting_key}`, {
      method: 'PUT',
      body: JSON.stringify({ setting_value })
    }),
  systemActionDefinitions: () =>
    request<{
      items: SystemActionDefinition[]
      total: number
    }>('/system-settings/actions'),
  runSystemAction: (action_key: SystemActionKey) =>
    request<{
      action_key: SystemActionKey
      action_label: string
      tone: SystemActionTone
      status: string
      detail: string
      output: string
      created_at: string
      audit_log: {
        id: number
        user_id: number
        module: string
        action: string
        detail: string
        created_at: string
      }
    }>(`/system-settings/actions/${action_key}`, {
      method: 'POST'
    }),
  auditLogs: (params?: { module?: string; action?: string; keyword?: string; page?: number; page_size?: number }) =>
    request<{
      items: Array<{
        id: number
        user_id: number
        module: string
        action: string
        detail: string
        created_at: string
      }>
      total: number
    }>(`/system-settings/audit-logs${buildQuery(params ?? {})}`)
}
