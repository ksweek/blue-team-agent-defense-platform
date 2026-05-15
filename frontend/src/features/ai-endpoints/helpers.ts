import type { AiEndpointItem, FormFieldTone } from '../../services/api'
import { redactSensitiveText } from '../../services/redaction'
import { PROTECTION_MODE_LABELS, TARGET_TYPE_LABELS, type ProtectionMode } from './constants'

type Tone = FormFieldTone

export function normalizeGroup(value: string | null | undefined) {
  const normalized = String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
  return normalized || 'default'
}

export function normalizeEndpointKey(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

export function protectionModeTone(mode: ProtectionMode): Tone {
  if (mode === 'enforce') {
    return 'danger'
  }
  if (mode === 'observe') {
    return 'warn'
  }
  return 'info'
}

export function endpointTone(item: AiEndpointItem): Tone {
  if (!item.enabled) {
    return 'info'
  }
  if (item.protection_enabled && item.protection_mode === 'enforce') {
    return 'danger'
  }
  if (item.protection_enabled && item.protection_mode === 'observe') {
    return 'warn'
  }
  return 'safe'
}

export function endpointStatusLabel(item: AiEndpointItem) {
  if (!item.enabled) {
    return '已停用'
  }
  if (!item.protection_enabled || item.protection_mode === 'off') {
    return '仅路由'
  }
  return PROTECTION_MODE_LABELS[item.protection_mode]
}

export function endpointSummaryText(item: AiEndpointItem) {
  return `${TARGET_TYPE_LABELS[item.target_type as 'openclaw_control' | 'standard_api'] ?? item.target_label ?? item.target_type} / ${normalizeGroup(item.endpoint_group)}`
}

export function endpointMetaText(item: AiEndpointItem) {
  if (item.target_type === 'openclaw_control') {
    return `Runtime 桥接 / 在线 ${item.usage_summary.runtime_online_count} / 已绑定 ${item.usage_summary.runtime_count}`
  }
  return redactSensitiveText(item.base_url)
}
