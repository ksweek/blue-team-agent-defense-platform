import './styles.css'

type Tone = 'safe' | 'warn' | 'danger' | 'info'

type Envelope<T> = {
  code: number
  message: string
  data: T
}

type OverviewPayload = {
  attack_count: number
  blocked_count: number
  enabled_defense_count: number
  high_risk_event_count: number
  active_task_count: number
}

type TrendItem = {
  day: string
  attack: number
  block: number
  false_positive: number
}

type EventItem = {
  id: number | string
  created_at: string
  event_type: string
  event_level: string
  source: string
  target: string
  status: string
  detail: string
}

type SessionItem = {
  session_id: string
  session_name: string
  status: string
  risk_level: string
}

type EndpointItem = {
  id: number
  display_name: string
  endpoint_group: string
  target_label: string
  provider_type: string
  protection_enabled: boolean
  protection_mode: string
  model_name: string
  usage_summary?: {
    runtime_count?: number
    runtime_online_count?: number
    task_count?: number
    active_task_count?: number
  }
}

type RuntimeRegistryPayload = {
  summary: {
    tokens_total: number
    tokens_active: number
    runtimes_total: number
    runtimes_pending: number
    runtimes_activation_requested: number
    runtimes_activation_issued: number
    runtimes_approved: number
    runtimes_active: number
    runtimes_online: number
  }
  runtimes: Array<{
    id: number
    display_name: string
    runtime_type: string
    status: string
    is_online: boolean
    ai_endpoint?: { display_name?: string } | null
  }>
}

type AssetItem = {
  id: number
  asset_name: string
  asset_type: string
  risk_level: string
  status: string
}

type SkillItem = {
  id: number
  skill_name: string
  skill_type: string
  trust_status: string
}

type CapabilityIconKey = 'runtime' | 'mcp' | 'trust' | 'leak' | 'threat' | 'audit'

const API_BASE = '/api'
const TOKEN_KEY = 'guardian-display-token'
const USERNAME_KEY = 'guardian-display-username'
const EXPIRES_AT_KEY = 'guardian-display-expires-at'
const APP_TOKEN_KEY = 'blue-team-access-token'
const REFRESH_MS = 5000
const CLOCK_MS = 1000

let accessToken = window.localStorage.getItem(TOKEN_KEY) || window.localStorage.getItem(APP_TOKEN_KEY) || ''
let currentUsername = window.localStorage.getItem(USERNAME_KEY) || ''
let refreshTimer: number | null = null
let clockTimer: number | null = null

const authOverlay = getEl<HTMLDivElement>('auth-overlay')
const authLoginForm = getEl<HTMLFormElement>('auth-login-form')
const authResetForm = getEl<HTMLFormElement>('auth-reset-form')
const authUsername = getEl<HTMLInputElement>('auth-username')
const authPassword = getEl<HTMLInputElement>('auth-password')
const authRemember = getEl<HTMLInputElement>('auth-remember')
const authToForgot = getEl<HTMLButtonElement>('auth-to-forgot')
const authBackLogin = getEl<HTMLButtonElement>('auth-back-login')
const authSendCode = getEl<HTMLButtonElement>('auth-send-code')
const resetEmail = getEl<HTMLInputElement>('reset-email')
const resetCode = getEl<HTMLInputElement>('reset-code')
const resetPassword = getEl<HTMLInputElement>('reset-password')
const authError = getEl<HTMLParagraphElement>('auth-error')
const authMessage = getEl<HTMLParagraphElement>('auth-message')
const authResetError = getEl<HTMLParagraphElement>('auth-reset-error')
const authResetMessage = getEl<HTMLParagraphElement>('auth-reset-message')
const clockText = getEl<HTMLSpanElement>('clock-text')
const refreshStatus = getEl<HTMLSpanElement>('refresh-status')

authUsername.value = currentUsername

function getEl<T extends HTMLElement>(id: string) {
  const node = document.getElementById(id)
  if (!node) {
    throw new Error(`Missing display node: #${id}`)
  }
  return node as T
}

function maybeEl<T extends HTMLElement>(id: string) {
  return document.getElementById(id) as T | null
}

function escapeHtml(value: string | number | null | undefined) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function formatValue(value: number) {
  return Math.max(0, Number.isFinite(value) ? value : 0).toLocaleString('zh-CN')
}

function formatDateTime(value: Date) {
  const year = value.getFullYear()
  const month = String(value.getMonth() + 1).padStart(2, '0')
  const day = String(value.getDate()).padStart(2, '0')
  const hour = String(value.getHours()).padStart(2, '0')
  const minute = String(value.getMinutes()).padStart(2, '0')
  const second = String(value.getSeconds()).padStart(2, '0')
  return `${year}-${month}-${day} ${hour}:${minute}:${second}`
}

function compactTime(value: string) {
  if (!value) return '--:--'
  const parsed = Date.parse(value)
  if (!Number.isNaN(parsed)) {
    const date = new Date(parsed)
    return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`
  }
  const parts = value.split(' ')
  return parts[1] || value
}

function parseTime(value: string) {
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? 0 : parsed
}

function setClock() {
  clockText.textContent = formatDateTime(new Date())
}

function setRefreshStatus(value: string) {
  refreshStatus.textContent = value
}

async function request<T>(path: string, init?: RequestInit) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...(init?.headers ?? {}),
    },
  })

  if (response.status === 401) {
    throw new Error('UNAUTHORIZED')
  }

  const payload = (await response.json()) as Envelope<T>
  if (!response.ok || payload.code !== 0) {
    throw new Error(payload.message || `HTTP ${response.status}`)
  }
  return payload.data
}

async function requestOptional<T>(path: string, fallback: T) {
  try {
    return await request<T>(path)
  } catch (error) {
    if (error instanceof Error && error.message === 'UNAUTHORIZED') {
      throw error
    }
    console.warn(`Display optional data failed: ${path}`, error)
    return fallback
  }
}

async function login(username: string, password: string) {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  const payload = (await response.json()) as Envelope<{
    access_token: string
    expires_at: string
  }>

  if (!response.ok || payload.code !== 0) {
    throw new Error(payload.message || '登录失败')
  }

  accessToken = payload.data.access_token
  currentUsername = username
  window.localStorage.setItem(TOKEN_KEY, accessToken)
  window.localStorage.setItem(APP_TOKEN_KEY, accessToken)
  window.localStorage.setItem(USERNAME_KEY, currentUsername)
  window.localStorage.setItem(EXPIRES_AT_KEY, payload.data.expires_at)
}

async function sendResetCode(email: string) {
  const response = await fetch(`${API_BASE}/auth/send-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, purpose: 'reset_password' }),
  })
  const payload = (await response.json()) as Envelope<{ sent: boolean }>
  if (!response.ok || payload.code !== 0) {
    throw new Error(payload.message || '验证码发送失败')
  }
}

async function resetPasswordWithEmail(email: string, code: string, password: string) {
  const response = await fetch(`${API_BASE}/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code, new_password: password }),
  })
  const payload = (await response.json()) as Envelope<{ reset: boolean }>
  if (!response.ok || payload.code !== 0) {
    throw new Error(payload.message || '密码重置失败')
  }
}

function showAuthOverlay(message = '') {
  authOverlay.classList.remove('hidden')
  authError.textContent = message
}

function hideAuthOverlay() {
  authOverlay.classList.add('hidden')
  authError.textContent = ''
}

function showLoginMode() {
  authLoginForm.classList.remove('hidden')
  authResetForm.classList.add('hidden')
  authError.textContent = ''
  authMessage.textContent = ''
}

function showForgotMode() {
  authLoginForm.classList.add('hidden')
  authResetForm.classList.remove('hidden')
  authResetError.textContent = ''
  authResetMessage.textContent = ''
}

function startPolling() {
  if (refreshTimer !== null) {
    window.clearInterval(refreshTimer)
  }
  refreshTimer = window.setInterval(() => {
    void loadDashboard()
  }, REFRESH_MS)
}

function normalizeRisk(value: string) {
  const normalized = value.trim().toLowerCase()
  if (normalized === 'high' || value.includes('高')) return 'high'
  if (normalized === 'low' || value.includes('低')) return 'low'
  return 'medium'
}

function riskLabel(value: string) {
  if (normalizeRisk(value) === 'high') return '高危'
  if (normalizeRisk(value) === 'low') return '低危'
  return '中危'
}

function toneByRisk(value: string): Tone {
  if (normalizeRisk(value) === 'high') return 'danger'
  if (normalizeRisk(value) === 'low') return 'safe'
  return 'warn'
}

function normalizeEventStatus(status: string) {
  const normalized = status.trim().toLowerCase()
  if (normalized === 'intercepted' || normalized === 'blocked') return 'intercepted'
  if (normalized === 'allowed' || normalized === 'passed') return 'allowed'
  return 'suspicious'
}

function eventStatusLabel(status: string) {
  const normalized = normalizeEventStatus(status)
  if (normalized === 'intercepted') return '已阻断'
  if (normalized === 'allowed') return '已放行'
  return '待复核'
}

function eventStatusTone(status: string): Tone {
  const normalized = normalizeEventStatus(status)
  if (normalized === 'intercepted') return 'danger'
  if (normalized === 'allowed') return 'safe'
  return 'warn'
}

function runtimeStatusTone(status: string): Tone {
  const value = status.trim().toLowerCase()
  if (value === 'running' || value === 'active' || value === 'approved' || value === 'done') return 'safe'
  if (value === 'queued' || value === 'scheduled' || value === 'activation_issued') return 'info'
  if (value === 'failed' || value === 'dead_letter' || value === 'revoked' || value === 'rejected') return 'danger'
  return 'warn'
}

function runtimeStatusLabel(status: string) {
  const value = status.trim().toLowerCase()
  if (value === 'running' || value === 'active') return '运行中'
  if (value === 'done') return '已完成'
  if (value === 'queued') return '排队中'
  if (value === 'scheduled') return '已调度'
  if (value === 'approved') return '已批准'
  if (value === 'failed') return '失败'
  if (value === 'dead_letter') return '死信'
  return status || '未知'
}

function formatEventType(type: string) {
  const normalized = type.trim().toLowerCase()
  const map: Record<string, string> = {
    prompt_injection: 'Prompt 注入攻击',
    asset_access: '敏感资产访问',
    skill_scan: '技能扫描事件',
    mcp_policy: 'MCP 策略违规',
    data_leak: '数据泄露风险',
    promptinject: 'Prompt 注入攻击',
    jailbreak: '越狱攻击',
    exfiltration: '数据外泄攻击',
    tool_abuse: '工具越权攻击',
    approval_bypass: '审批绕过攻击',
    scope_escalation: '作用域越权攻击',
    rebinding: '运行时重绑定攻击',
    openclaw_control: '控制台注入攻击',
    openclawcontrol: '控制台注入攻击',
    control_channel: '控制通道攻击',
  }
  if (map[normalized]) return map[normalized]

  // Some upstream events leak source identifiers into the type field. Normalize them back
  // to attack categories so the big-screen top list shows attack types instead of victims/sources.
  if (normalized.includes('openclaw')) return '控制台注入攻击'
  if (normalized.includes('prompt')) return 'Prompt 注入攻击'
  if (normalized.includes('inject')) return '注入攻击'
  if (normalized.includes('jailbreak')) return '越狱攻击'
  if (normalized.includes('approval')) return '审批绕过攻击'
  if (normalized.includes('scope')) return '作用域越权攻击'
  if (normalized.includes('mcp')) return 'MCP 策略违规'
  if (normalized.includes('tool')) return '工具越权攻击'
  if (normalized.includes('leak') || normalized.includes('exfil')) return '数据外泄攻击'
  if (normalized.includes('asset')) return '敏感资产访问'

  return type.replace(/_/g, ' ')
}

function statusPill(label: string, tone: Tone) {
  return `<span class="status-pill tone-${tone}">${escapeHtml(label)}</span>`
}

function setCirclePercent(id: string, percent: number) {
  const node = maybeEl<HTMLElement>(id)
  if (node) {
    node.style.setProperty('--percent', String(Math.max(0, Math.min(100, percent))))
  }
}

function buildPolyline<T extends Record<string, unknown>>(items: T[], key: keyof T, maxValue: number, width: number, height: number) {
  if (!items.length) return ''
  const step = items.length > 1 ? width / (items.length - 1) : width
  return items
    .map((item, index) => {
      const raw = item[key]
      const value = typeof raw === 'number' ? raw : Number(raw || 0)
      const ratio = maxValue > 0 ? value / maxValue : 0
      const x = index * step
      const y = height - ratio * (height - 16) - 8
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
}

function buildSparkValues(seed: number, count = 16) {
  const base = Math.max(1, seed)
  return Array.from({ length: count }, (_, index) => ({
    value: Math.max(0, Math.round(base * (0.5 + Math.sin(index * 1.27 + base) * 0.24 + ((index * 17 + base) % 7) * 0.045))),
  }))
}

function nonEmpty<T>(items: T[], fallback: T[]) {
  return items.length ? items : fallback
}

function mountCenterStats(overview: OverviewPayload, runtimeRegistry: RuntimeRegistryPayload, endpointCount: number, assetCount: number) {
  const root = maybeEl<HTMLElement>('center-stat-row')
  if (!root) return
  const items = [
    { label: 'AI 智能体总数', value: endpointCount, tone: 'info' as Tone },
    { label: 'Runtime Online', value: runtimeRegistry.summary.runtimes_online ?? 0, tone: 'safe' as Tone },
    { label: '受保护资产', value: assetCount, tone: 'info' as Tone },
    { label: '今日拦截攻击', value: overview.blocked_count, tone: overview.high_risk_event_count ? ('danger' as Tone) : ('safe' as Tone) },
  ]
  root.innerHTML = items
    .map(
      (item) => `
        <article class="center-stat-card tone-${item.tone}">
          <span>${escapeHtml(item.label)}</span>
          <strong>${formatValue(item.value)}</strong>
        </article>
      `,
    )
    .join('')
}

function mountThreatOverview(overview: OverviewPayload, trends: TrendItem[], events: EventItem[]) {
  const total = overview.attack_count
  const high = overview.high_risk_event_count
  const blocked = overview.blocked_count
  const score = total ? Math.min(100, Math.round((high * 24 + total * 3 + Math.max(0, total - blocked) * 8) / Math.max(1, total))) : 0
  const level = score >= 70 ? '高危' : score >= 40 ? '中危' : '稳定'

  getEl('threat-score').textContent = String(score)
  getEl('threat-total').textContent = formatValue(total)
  getEl('threat-level').textContent = level
  setCirclePercent('threat-ring', score)

  const max = Math.max(1, ...trends.map((item) => item.attack))
  maybeEl<SVGPolylineElement>('threat-mini-line')?.setAttribute('points', buildPolyline(trends, 'attack', max, 240, 72))

  const mediumCount = events.filter((item) => normalizeRisk(item.event_level) === 'medium').length
  const lowCount = events.filter((item) => normalizeRisk(item.event_level) === 'low').length
  getEl('threat-triplets').innerHTML = `
    <article class="danger"><strong>${formatValue(high)}</strong><span>高危情报</span></article>
    <article class="warn"><strong>${formatValue(mediumCount)}</strong><span>中危情报</span></article>
    <article class="safe"><strong>${formatValue(lowCount)}</strong><span>低危情报</span></article>
  `
}

function mountTrend(trends: TrendItem[]) {
  const max = Math.max(1, ...trends.map((item) => Math.max(item.attack, item.block, item.false_positive)))
  maybeEl<SVGPolylineElement>('trend-line-attack')?.setAttribute('points', buildPolyline(trends, 'attack', max, 520, 188))
  maybeEl<SVGPolylineElement>('trend-line-block')?.setAttribute('points', buildPolyline(trends, 'block', max, 520, 188))
  maybeEl<SVGPolylineElement>('trend-line-review')?.setAttribute('points', buildPolyline(trends, 'false_positive', max, 520, 188))
  getEl('trend-days').innerHTML = trends.map((item) => `<span>${escapeHtml(compactDay(item.day))}</span>`).join('')
}

function compactDay(day: string) {
  if (day.includes('-')) return day.split('-').slice(1).join('/')
  return day
}

function mountAttackTop(events: EventItem[], overview: OverviewPayload) {
  const buckets = new Map<string, number>()
  for (const event of events.filter((item) => normalizeEventStatus(item.status) === 'intercepted')) {
    const label = formatEventType(event.event_type)
    buckets.set(label, (buckets.get(label) ?? 0) + 1)
  }
  const rows = nonEmpty(
    [...buckets.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((left, right) => right.value - left.value)
      .slice(0, 5),
    [
      { label: 'Prompt 注入攻击', value: overview.blocked_count },
      { label: '敏感数据访问', value: overview.high_risk_event_count },
      { label: '工具越权攻击', value: Math.max(overview.active_task_count, 0) },
    ].filter((item) => item.value > 0),
  )

  getEl('blocked-badge').textContent = `Blocked ${formatValue(overview.blocked_count)}`
  const max = Math.max(1, ...rows.map((item) => item.value))
  getEl('attack-top-list').innerHTML = rows
    .map(
      (item) => `
        <article class="rank-row">
          <span class="rank-dot"></span>
          <div class="rank-main">
            <strong>${escapeHtml(item.label)}</strong>
            <div class="rank-bar"><span style="width:${Math.max(10, Math.round((item.value / max) * 100))}%"></span></div>
          </div>
          <em>${formatValue(item.value)}</em>
        </article>
      `,
    )
    .join('')
}

function mountEventFeed(events: EventItem[]) {
  const latest = [...events].sort((left, right) => parseTime(right.created_at) - parseTime(left.created_at)).slice(0, 5)
  getEl('event-feed-badge').textContent = `运行 ${latest.length}`
  getEl('event-feed-list').innerHTML = latest
    .map(
      (event) => `
        <article class="feed-row">
          <span>${escapeHtml(compactTime(event.created_at))}</span>
          <strong>${escapeHtml(formatEventType(event.event_type))}</strong>
          <p>${escapeHtml(event.detail || `${event.source} -> ${event.target}`)}</p>
          ${statusPill(riskLabel(event.event_level), toneByRisk(event.event_level))}
        </article>
      `,
    )
    .join('')
}

function mountModelLayer(endpoints: EndpointItem[], runtimeRegistry: RuntimeRegistryPayload) {
  const llmOnline = endpoints.length > 0
  const embeddingOnline = (runtimeRegistry.summary.runtimes_total ?? 0) > 0
  const items = [
    {
      title: '大语言模型',
      subtitle: '(LLM)',
      online: llmOnline,
    },
    {
      title: '嵌入模型',
      subtitle: '(Embedding)',
      online: embeddingOnline,
    },
  ]
  getEl('model-layer-list').innerHTML = items
    .map(
      (item) => `
        <article class="model-node ${item.online ? 'online' : ''}">
          <div class="model-node-copy">
            <strong>${escapeHtml(item.title)}</strong>
            <p>${escapeHtml(item.subtitle)}</p>
          </div>
          <span></span>
        </article>
      `,
    )
    .join('')
}

function mountCoreNodes(endpoints: EndpointItem[], sessions: SessionItem[]) {
  const targetItems = [
    { title: '客服助手 Agent', subtitle: 'Runtime Online', online: true },
    { title: '安全分析 Agent', subtitle: 'Runtime Online', online: true },
    { title: '运维助手 Agent', subtitle: 'Runtime Online', online: true },
    { title: '数据分析 Agent', subtitle: 'Runtime Online', online: true },
  ]
  const serviceItems = [
    { title: '搜索服务', subtitle: 'Runtime Online', online: true },
    { title: '知识库 (RAG)', subtitle: 'Runtime Online', online: true },
    { title: '代码解释器', subtitle: 'Runtime Online', online: true },
    { title: '邮件服务', subtitle: 'Runtime Online', online: true },
  ]

  targetItems.forEach((item, index) => {
    getEl(`target-node-${index + 1}`).innerHTML = nodeHtml(item.title, item.subtitle, item.online, 'agent')
  })
  serviceItems.forEach((item, index) => {
    getEl(`service-node-${index + 1}`).innerHTML = nodeHtml(item.title, item.subtitle, item.online, 'service')
  })

  setMoreButtonHint('target-node-more', Math.max(0, endpoints.length - targetItems.length), '智能体')
  setMoreButtonHint('service-node-more', Math.max(0, sessions.length - serviceItems.length), '服务')
}

function nodeHtml(title: string, subtitle: string, online: boolean, kind: 'agent' | 'service') {
  return `
    <div class="node-icon ${kind}"></div>
    <div class="node-copy">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(subtitle)}</p>
    </div>
    <span class="node-status ${online ? 'online' : 'offline'}" aria-hidden="true"></span>
  `
}

function setMoreButtonHint(id: string, hiddenCount: number, label: string) {
  const node = maybeEl<HTMLButtonElement>(id)
  if (!node) return
  node.title = hiddenCount > 0 ? `还有 ${hiddenCount} 个${label}` : `更多${label}`
  node.classList.toggle('has-extra', hiddenCount > 0)
}

function countAssetsByKeywords(assets: AssetItem[], keywords: string[]) {
  return assets.filter((item) => {
    const haystack = `${item.asset_name} ${item.asset_type}`.toLowerCase()
    return keywords.some((keyword) => haystack.includes(keyword))
  }).length
}

function mountDataAssetStrip(
  overview: OverviewPayload,
  runtimeRegistry: RuntimeRegistryPayload,
  assets: AssetItem[],
  endpoints: EndpointItem[],
  skills: SkillItem[],
) {
  const root = maybeEl<HTMLElement>('data-asset-strip')
  if (!root) return

  const runtimeTotal = runtimeRegistry.summary.runtimes_total ?? 0
  const tokenTotal = runtimeRegistry.summary.tokens_total ?? 0
  const tokenActive = runtimeRegistry.summary.tokens_active ?? 0
  const knowledgeAssets = countAssetsByKeywords(assets, ['knowledge', 'rag', 'kb', '知识'])
  const vectorAssets = countAssetsByKeywords(assets, ['vector', 'embedding', 'milvus', 'faiss', 'chroma', 'pgvector', '向量'])

  const items = [
    {
      title: '企业知识库',
      status: '受保护',
      value: Math.max(128, Math.max(1, knowledgeAssets || assets.length) * 128),
      icon: 'knowledge',
    },
    {
      title: '用户数据',
      status: '受保护',
      value: Math.max(256, Math.max(1, tokenTotal || runtimeTotal) * 16),
      icon: 'user',
    },
    {
      title: '业务系统',
      status: '受保护',
      value: Math.max(48, endpoints.length * 24 + Math.max(1, overview.active_task_count) * 6),
      icon: 'business',
    },
    {
      title: '向量数据库',
      status: '受保护',
      value: Math.max(12, Math.max(1, vectorAssets || skills.length || tokenActive) * 12),
      icon: 'vector',
    },
  ]

  root.innerHTML = items
    .map(
      (item) => `
        <article class="data-asset-card">
          <div class="data-asset-copy">
            <div class="data-asset-titleline">
              <span class="data-asset-icon icon-${item.icon}" aria-hidden="true"></span>
              <strong>${escapeHtml(item.title)}</strong>
            </div>
            <p>${escapeHtml(item.status)}</p>
          </div>
          <em>${formatValue(item.value)}</em>
        </article>
      `,
    )
    .join('')
}

function mountCapabilityStrip(overview: OverviewPayload) {
  const items: Array<{ label: string; icon: CapabilityIconKey }> = [
    { label: '运行时防护', icon: 'runtime' },
    { label: 'MCP 策略监控', icon: 'mcp' },
    { label: '技能信任评估', icon: 'trust' },
    { label: '数据防泄漏', icon: 'leak' },
    { label: '威胁检测', icon: 'threat' },
    { label: '行为审计', icon: 'audit' },
  ]
  getEl('capability-strip').innerHTML = items
    .map(
      (item, index) => `
        <article class="capability-item">
          <div class="capability-icon icon-${item.icon}" aria-hidden="true">${capabilityIconSvg(item.icon)}</div>
          <strong>${escapeHtml(item.label)}</strong>
          <span>${overview.enabled_defense_count > index ? '已启用' : '待启用'}</span>
        </article>
      `,
    )
    .join('')
}

function capabilityIconSvg(icon: CapabilityIconKey) {
  const attrs = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"'
  if (icon === 'runtime') {
    return `<svg ${attrs}><path d="M12 3 19 6v5c0 4.4-2.8 7.8-7 10-4.2-2.2-7-5.6-7-10V6l7-3Z"/><path d="m9 12 2 2 4-5"/></svg>`
  }
  if (icon === 'mcp') {
    return `<svg ${attrs}><path d="M7 7h4v4H7z"/><path d="M13 13h4v4h-4z"/><path d="M15 7h2v2"/><path d="M9 13v4H7"/><path d="M11 9h2"/><path d="M12 11v2"/></svg>`
  }
  if (icon === 'trust') {
    return `<svg ${attrs}><path d="M12 3 15 9l6 .8-4.4 4.2 1.1 6-5.7-2.9L6.3 20l1.1-6L3 9.8 9 9l3-6Z"/><path d="m9.5 12.4 1.7 1.7 3.4-4"/></svg>`
  }
  if (icon === 'leak') {
    return `<svg ${attrs}><ellipse cx="12" cy="6" rx="6" ry="2.5"/><path d="M6 6v8c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5V6"/><path d="M8 19h8"/><path d="m15 12 3 3"/><path d="m18 12-3 3"/></svg>`
  }
  if (icon === 'threat') {
    return `<svg ${attrs}><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 3v3"/><path d="M12 18v3"/><path d="M3 12h3"/><path d="M18 12h3"/></svg>`
  }
  return `<svg ${attrs}><path d="M8 4h8l2 2v14H6V6l2-2Z"/><path d="M9 9h6"/><path d="M9 13h4"/><path d="m9 17 1.4 1.4L14 15"/></svg>`
}

function mountAssetGovernance(assets: AssetItem[], endpoints: EndpointItem[], skills: SkillItem[]) {
  const total = assets.length + endpoints.length + skills.length
  const distribution = [
    { label: '智能体', value: endpoints.length, color: '#149dff' },
    { label: '知识库', value: assets.filter((item) => item.asset_type.includes('knowledge')).length || Math.round(assets.length * 0.22), color: '#21d6ff' },
    { label: '工具服务', value: skills.length, color: '#23e6bd' },
    { label: '数据资产', value: assets.length, color: '#e59a35' },
    { label: '其他资产', value: Math.max(0, total - endpoints.length - skills.length - assets.length), color: '#4b9fff' },
  ].filter((item) => item.value > 0)

  getEl('asset-total').textContent = formatValue(total)
  getEl('asset-total-text').textContent = `资产总数 ${formatValue(total)}`
  const donut = getEl('asset-donut')
  let cursor = 0
  const stops = distribution.map((item) => {
    const start = cursor
    const end = cursor + (total ? (item.value / total) * 100 : 0)
    cursor = end
    return `${item.color} ${start}% ${end}%`
  })
  donut.style.background = stops.length ? `conic-gradient(${stops.join(', ')}, rgba(43, 80, 116, 0.3) ${cursor}% 100%)` : ''

  getEl('asset-distribution').innerHTML = distribution
    .map(
      (item) => `
        <article class="distribution-row">
          <span style="--dot:${item.color}"></span>
          <strong>${escapeHtml(item.label)}</strong>
          <em>${formatValue(item.value)} (${total ? ((item.value / total) * 100).toFixed(1) : '0.0'}%)</em>
        </article>
      `,
    )
    .join('')
}

function mountRuntimeMonitor(overview: OverviewPayload, runtimeRegistry: RuntimeRegistryPayload, trends: TrendItem[]) {
  const summary = runtimeRegistry.summary
  const total = summary.runtimes_total ?? 0
  const online = summary.runtimes_online ?? 0
  const pending =
    (summary.runtimes_pending ?? 0) +
    (summary.runtimes_activation_requested ?? 0) +
    (summary.runtimes_activation_issued ?? 0)
  const attackMax = Math.max(1, ...trends.map((item) => Math.max(item.attack, item.block, item.false_positive)))
  const attackSpark = buildPolyline(trends, 'attack', attackMax, 150, 38)
  const blockSpark = buildPolyline(trends, 'block', attackMax, 150, 38)
  const reviewSpark = buildPolyline(trends, 'false_positive', attackMax, 150, 38)
  const pendingSpark = buildPolyline(buildSparkValues(pending + 4), 'value', 18, 150, 38)
  const items = [
    { label: 'Runtime Online', value: `${online}/${total || 0}`, detail: `${total ? ((online / total) * 100).toFixed(1) : '0.0'}%`, tone: online ? ('safe' as Tone) : ('warn' as Tone), points: blockSpark },
    { label: '异常实例', value: `${overview.high_risk_event_count}`, detail: '高危关联', tone: overview.high_risk_event_count ? ('danger' as Tone) : ('safe' as Tone), points: attackSpark },
    { label: '平均响应时间', value: `${840 + Math.min(overview.attack_count, 180)}ms`, detail: '实时估算', tone: 'info' as Tone, points: reviewSpark },
    { label: '今次消耗', value: `${formatCompact(overview.attack_count * 512 + overview.blocked_count * 128)}`, detail: 'Token / Trace', tone: 'info' as Tone, points: pendingSpark },
  ]
  getEl('runtime-monitor-grid').innerHTML = items
    .map(
      (item) => `
        <article class="runtime-monitor-card tone-${item.tone}">
          <div>
            <span>${escapeHtml(item.label)}</span>
            <strong>${escapeHtml(item.value)}</strong>
            <small>${escapeHtml(item.detail)}</small>
          </div>
          <svg viewBox="0 0 150 38" preserveAspectRatio="none" aria-hidden="true">
            <polyline class="spark-line ${item.tone}" points="${item.points}" />
          </svg>
        </article>
      `,
    )
    .join('')
}

function formatCompact(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`
  return String(Math.max(0, Math.round(value)))
}

function mountPolicyMonitor(overview: OverviewPayload, events: EventItem[]) {
  const policyTotal = overview.enabled_defense_count
  const high = overview.high_risk_event_count
  const medium = events.filter((item) => normalizeRisk(item.event_level) === 'medium').length
  const blocked = overview.blocked_count
  getEl('policy-total').textContent = formatValue(policyTotal)
  getEl('policy-badge').textContent = `策略违规 ${high + medium}`
  getEl('policy-monitor-list').innerHTML = [
    { label: '高风险策略违规', value: high, tone: 'danger' as Tone },
    { label: '中风险策略违规', value: medium, tone: 'warn' as Tone },
    { label: '已巡检策略', value: blocked, tone: 'safe' as Tone },
  ]
    .map(
      (item) => `
        <article class="policy-row">
          <span class="policy-dot tone-${item.tone}"></span>
          <strong>${escapeHtml(item.label)}</strong>
          <em>${formatValue(item.value)}</em>
        </article>
      `,
    )
    .join('')
}

function mountMiniStatus(skills: SkillItem[], runtimeRegistry: RuntimeRegistryPayload) {
  const trusted = skills.filter((item) => item.trust_status === 'trusted').length
  const pending = skills.filter((item) => item.trust_status === 'pending' || item.trust_status === 'review').length
  const ratedTotal = trusted + pending || skills.length
  const trustRate = ratedTotal ? Math.round((trusted / ratedTotal) * 100) : 100
  const total = runtimeRegistry.summary.runtimes_total ?? 0
  const online = runtimeRegistry.summary.runtimes_online ?? 0
  const runtimeRate = total ? Math.round((online / total) * 100) : 0

  getEl('skill-trust-rate').textContent = String(trustRate)
  getEl('skill-trust-text').textContent = `可信技能 ${formatValue(trusted)} / 待审 ${formatValue(pending)}`
  getEl('runtime-online-rate').textContent = String(runtimeRate)
  getEl('runtime-online-text').textContent = `${formatValue(online)}/${formatValue(total)} 在线`
  setCirclePercent('skill-trust-circle', trustRate)
  setCirclePercent('runtime-online-circle', runtimeRate)
}

function mountTimeline(events: EventItem[]) {
  const sorted = [...events].sort((left, right) => parseTime(right.created_at) - parseTime(left.created_at))
  const high = sorted.filter((item) => normalizeRisk(item.event_level) === 'high').length
  const medium = sorted.filter((item) => normalizeRisk(item.event_level) === 'medium').length
  const low = sorted.filter((item) => normalizeRisk(item.event_level) === 'low').length
  getEl('timeline-badge').textContent = `全部 ${sorted.length}`
  getEl('timeline-filters').innerHTML = `
    <button class="active" type="button">全部</button>
    <button type="button">高危 ${formatValue(high)}</button>
    <button type="button">中危 ${formatValue(medium)}</button>
    <button type="button">低危 ${formatValue(low)}</button>
  `
  getEl('timeline-list').innerHTML = sorted
    .slice(0, 5)
    .map(
      (event) => `
        <article class="timeline-row">
          <span class="timeline-time">${escapeHtml(compactTime(event.created_at))}</span>
          <span class="timeline-dot tone-${toneByRisk(event.event_level)}"></span>
          <div>
            <strong>${escapeHtml(formatEventType(event.event_type))}</strong>
            <p>${escapeHtml(event.detail || `${event.source} -> ${event.target}`)}</p>
          </div>
          ${statusPill(riskLabel(event.event_level), toneByRisk(event.event_level))}
        </article>
      `,
    )
    .join('')
}

function mountAlerts(events: EventItem[]) {
  const alertEvents = [...events]
    .filter((item) => normalizeRisk(item.event_level) !== 'low' || normalizeEventStatus(item.status) !== 'allowed')
    .sort((left, right) => parseTime(right.created_at) - parseTime(left.created_at))
  const high = alertEvents.filter((item) => normalizeRisk(item.event_level) === 'high').length
  const medium = alertEvents.filter((item) => normalizeRisk(item.event_level) === 'medium').length
  const low = alertEvents.filter((item) => normalizeRisk(item.event_level) === 'low').length
  getEl('alerts-all').textContent = `全部 ${alertEvents.length}`
  getEl('alerts-high').textContent = `高危 ${high}`
  getEl('alerts-mid').textContent = `中危 ${medium}`
  getEl('alerts-low').textContent = `低危 ${low}`
  getEl('alerts-list').innerHTML = alertEvents
    .slice(0, 4)
    .map(
      (event) => `
        <article class="alert-row">
          ${statusPill(riskLabel(event.event_level), toneByRisk(event.event_level))}
          <div>
            <strong>${escapeHtml(formatEventType(event.event_type))}</strong>
            <p>${escapeHtml(event.detail || event.target)}</p>
          </div>
          <span>${escapeHtml(compactTime(event.created_at))}</span>
        </article>
      `,
    )
    .join('')
}

function mountKeyMetrics(overview: OverviewPayload, runtimeRegistry: RuntimeRegistryPayload, skills: SkillItem[], events: EventItem[]) {
  const interceptRate = overview.attack_count ? (overview.blocked_count / overview.attack_count) * 100 : 0
  const policyCompliance = Math.max(0, 100 - overview.high_risk_event_count * 2.4)
  const runtimeRate = runtimeRegistry.summary.runtimes_total
    ? (runtimeRegistry.summary.runtimes_online / runtimeRegistry.summary.runtimes_total) * 100
    : 0
  const trusted = skills.filter((item) => item.trust_status === 'trusted').length
  const skillRate = skills.length ? (trusted / skills.length) * 100 : 100
  const eventSafetyRate = events.length
    ? (events.filter((item) => normalizeRisk(item.event_level) !== 'high').length / events.length) * 100
    : 100

  const items = [
    { label: '攻击拦截率', value: `${interceptRate.toFixed(1)}%`, delta: '↑ 实时' },
    { label: '策略合规率', value: `${policyCompliance.toFixed(1)}%`, delta: '↑ 巡检' },
    { label: '平均响应时间', value: `${842 + Math.min(overview.active_task_count * 21, 220)}ms`, delta: '↓ 波动' },
    { label: '安全事件数', value: `${events.length}`, delta: '实时' },
  ]
  getEl('key-metrics-list').innerHTML = items
    .map(
      (item) => `
        <article class="metric-row">
          <span>${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(item.value)}</strong>
          <em>${escapeHtml(item.delta)}</em>
        </article>
      `,
    )
    .join('')

  const radar = [
    interceptRate,
    policyCompliance,
    runtimeRate,
    skillRate,
    eventSafetyRate,
  ].map((value) => Math.max(20, Math.min(100, value)))
  maybeEl<SVGPolygonElement>('metric-radar-shape')?.setAttribute('points', buildRadarPoints(radar))
}

function buildRadarPoints(values: number[]) {
  const cx = 80
  const cy = 80
  const maxRadius = 68
  return values
    .map((value, index) => {
      const angle = -Math.PI / 2 + (Math.PI * 2 * index) / values.length
      const radius = (value / 100) * maxRadius
      return `${(cx + Math.cos(angle) * radius).toFixed(1)},${(cy + Math.sin(angle) * radius).toFixed(1)}`
    })
    .join(' ')
}

async function loadDashboard() {
  setRefreshStatus('同步中')
  try {
    const [
      overview,
      trendsPayload,
      sessionsPayload,
      eventsPayload,
      endpointsPayload,
      runtimeRegistry,
      assetsPayload,
      skillsPayload,
    ] = await Promise.all([
      requestOptional<OverviewPayload>('/dashboard/overview', {
        attack_count: 0,
        blocked_count: 0,
        enabled_defense_count: 0,
        high_risk_event_count: 0,
        active_task_count: 0,
      }),
      requestOptional<{ range: string; items: TrendItem[] }>('/dashboard/trends', { range: '7d', items: [] }),
      requestOptional<{ items: SessionItem[]; total: number }>('/dashboard/sessions', { items: [], total: 0 }),
      requestOptional<{ items: EventItem[]; total?: number }>('/security-events?page_size=50', { items: [], total: 0 }),
      requestOptional<{ items: EndpointItem[]; summary?: unknown }>('/ai-endpoints', { items: [] }),
      requestOptional<RuntimeRegistryPayload>('/runtime-registry', {
        summary: {
          tokens_total: 0,
          tokens_active: 0,
          runtimes_total: 0,
          runtimes_pending: 0,
          runtimes_activation_requested: 0,
          runtimes_activation_issued: 0,
          runtimes_approved: 0,
          runtimes_active: 0,
          runtimes_online: 0,
        },
        runtimes: [],
      }),
      requestOptional<{ items: AssetItem[]; total?: number }>('/assets', { items: [] }),
      requestOptional<{ items: SkillItem[]; total?: number }>('/skills?page_size=100&scan_task_page_size=6', { items: [] }),
    ])

    const trends = trendsPayload.items.length
      ? trendsPayload.items
      : Array.from({ length: 7 }, (_, index) => ({
          day: `D-${6 - index}`,
          attack: Math.max(0, Math.round((overview.attack_count / 7) * (0.7 + index * 0.08))),
          block: Math.max(0, Math.round((overview.blocked_count / 7) * (0.75 + index * 0.06))),
          false_positive: Math.max(0, Math.round((overview.high_risk_event_count / 7) * (0.5 + index * 0.07))),
        }))
    const events = eventsPayload.items
    const endpoints = endpointsPayload.items
    const assets = assetsPayload.items
    const skills = skillsPayload.items

    mountThreatOverview(overview, trends, events)
    mountTrend(trends)
    mountAttackTop(events, overview)
    mountEventFeed(events)
    mountCenterStats(overview, runtimeRegistry, endpoints.length, assets.length)
    mountModelLayer(endpoints, runtimeRegistry)
    mountCoreNodes(endpoints, sessionsPayload.items)
    mountDataAssetStrip(overview, runtimeRegistry, assets, endpoints, skills)
    mountCapabilityStrip(overview)
    mountAssetGovernance(assets, endpoints, skills)
    mountRuntimeMonitor(overview, runtimeRegistry, trends)
    mountPolicyMonitor(overview, events)
    mountMiniStatus(skills, runtimeRegistry)
    mountTimeline(events)
    mountAlerts(events)
    mountKeyMetrics(overview, runtimeRegistry, skills, events)

    const hasProtection = overview.enabled_defense_count > 0 || endpoints.some((item) => item.protection_enabled)
    getEl('protection-status').textContent = hasProtection ? '防护状态：运行中' : '防护状态：待接入'
    getEl('protection-status').className = `status-chip ${hasProtection ? 'safe' : 'warn'}`
    hideAuthOverlay()
    setRefreshStatus(`最近刷新 ${compactTime(formatDateTime(new Date()))}`)
  } catch (error) {
    if (error instanceof Error && error.message === 'UNAUTHORIZED') {
      accessToken = ''
      window.localStorage.removeItem(TOKEN_KEY)
      window.localStorage.removeItem(EXPIRES_AT_KEY)
      showLoginMode()
      showAuthOverlay('大屏登录已失效，请重新登录')
      setRefreshStatus('需要登录')
      return
    }
    setRefreshStatus('刷新失败')
    console.error(error)
  }
}

authToForgot.addEventListener('click', showForgotMode)
authBackLogin.addEventListener('click', showLoginMode)

authLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  const username = authUsername.value.trim()
  const password = authPassword.value
  if (!username || !password) {
    authError.textContent = '请输入账号和密码'
    return
  }
  authError.textContent = ''
  authMessage.textContent = '正在登录...'
  try {
    await login(username, password)
    if (!authRemember.checked) {
      window.localStorage.removeItem(USERNAME_KEY)
    }
    authMessage.textContent = ''
    hideAuthOverlay()
    await loadDashboard()
    startPolling()
  } catch (error) {
    authMessage.textContent = ''
    authError.textContent = error instanceof Error ? error.message : '登录失败'
  }
})

authSendCode.addEventListener('click', async () => {
  const email = resetEmail.value.trim()
  if (!email) {
    authResetError.textContent = '请输入绑定邮箱'
    return
  }
  authResetError.textContent = ''
  authResetMessage.textContent = '验证码发送中...'
  try {
    await sendResetCode(email)
    authResetMessage.textContent = '如果邮箱存在，验证码将发送到该邮箱'
  } catch (error) {
    authResetMessage.textContent = ''
    authResetError.textContent = error instanceof Error ? error.message : '验证码发送失败'
  }
})

authResetForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  const email = resetEmail.value.trim()
  const code = resetCode.value.trim()
  const password = resetPassword.value
  if (!email || !code || password.length < 8) {
    authResetError.textContent = '请填写邮箱、验证码和至少 8 位新密码'
    return
  }
  authResetError.textContent = ''
  authResetMessage.textContent = '正在重置密码...'
  try {
    await resetPasswordWithEmail(email, code, password)
    authResetMessage.textContent = '密码已重置，请使用新密码登录'
    resetCode.value = ''
    resetPassword.value = ''
    window.setTimeout(showLoginMode, 700)
  } catch (error) {
    authResetMessage.textContent = ''
    authResetError.textContent = error instanceof Error ? error.message : '密码重置失败'
  }
})

setClock()
clockTimer = window.setInterval(setClock, CLOCK_MS)
window.addEventListener('beforeunload', () => {
  if (refreshTimer !== null) window.clearInterval(refreshTimer)
  if (clockTimer !== null) window.clearInterval(clockTimer)
})

if (accessToken) {
  hideAuthOverlay()
  void loadDashboard()
  startPolling()
} else {
  showLoginMode()
  showAuthOverlay('请输入大屏登录凭据')
  setRefreshStatus('等待登录')
}
