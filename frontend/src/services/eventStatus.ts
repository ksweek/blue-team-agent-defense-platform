export type Tone = 'safe' | 'warn' | 'danger' | 'info'
export type SecurityEventStatus = 'intercepted' | 'suspicious' | 'allowed'

const LEGACY_EVENT_STATUS_MAP: Record<string, SecurityEventStatus> = {
  blocked: 'intercepted',
  pending: 'suspicious',
  closed: 'allowed',
}

export function normalizeEventStatus(status?: string | null): SecurityEventStatus | string {
  const lowered = (status || '').trim().toLowerCase()
  if (lowered in LEGACY_EVENT_STATUS_MAP) {
    return LEGACY_EVENT_STATUS_MAP[lowered]
  }
  if (lowered === 'intercepted' || lowered === 'suspicious' || lowered === 'allowed') {
    return lowered
  }
  return status || ''
}

export function eventStatusTone(status?: string | null): Tone {
  const normalized = normalizeEventStatus(status)
  if (normalized === 'intercepted') return 'safe'
  if (normalized === 'suspicious') return 'warn'
  if (normalized === 'allowed') return 'info'
  return 'info'
}

export function eventStatusLabel(status?: string | null) {
  const normalized = normalizeEventStatus(status)
  if (normalized === 'intercepted') return '已拦截'
  if (normalized === 'suspicious') return '可疑'
  if (normalized === 'allowed') return '已放行'
  return status || '未记录'
}

export function eventStatusRank(status?: string | null) {
  const normalized = normalizeEventStatus(status)
  if (normalized === 'suspicious') return 0
  if (normalized === 'intercepted') return 1
  if (normalized === 'allowed') return 2
  return 3
}
