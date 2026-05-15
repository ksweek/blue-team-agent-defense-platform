import type { AiEndpointItem, FormFieldTone } from '../../services/api'

export type Tone = FormFieldTone
export type ProtectionMode = AiEndpointItem['protection_mode']
export type ProviderType = AiEndpointItem['provider_type']
export type TargetType = AiEndpointItem['target_type']

export const TARGET_TYPE_LABELS: Record<'openclaw_control' | 'standard_api', string> = {
  openclaw_control: 'OpenClaw 受保护目标',
  standard_api: '标准 API 目标',
}

export const TARGET_TYPE_OPTIONS: Array<{ label: string; value: 'openclaw_control' | 'standard_api' }> = [
  { label: 'OpenClaw 受保护目标', value: 'openclaw_control' },
]

export const CONNECTION_MODE_LABELS: Record<string, string> = {
  runtime_bridge_only: 'Runtime 桥接',
  direct_provider: '直连 Provider',
}

export const PROVIDER_LABELS: Record<ProviderType, string> = {
  openai_compatible: 'OpenAI Compatible',
  anthropic: 'Anthropic',
  azure_openai: 'Azure OpenAI',
  gemini: 'Gemini',
  ollama: 'Ollama',
  bedrock: 'AWS Bedrock',
}

export const PROTECTION_MODE_LABELS: Record<ProtectionMode, string> = {
  enforce: '拦截',
  observe: '观察',
  off: '关闭',
}

export const PROVIDER_OPTIONS: Array<{ label: string; value: ProviderType }> = [
  { label: 'OpenAI Compatible', value: 'openai_compatible' },
  { label: 'Anthropic', value: 'anthropic' },
  { label: 'Azure OpenAI', value: 'azure_openai' },
  { label: 'Gemini', value: 'gemini' },
  { label: 'Ollama', value: 'ollama' },
  { label: 'AWS Bedrock', value: 'bedrock' },
]

export const PROTECTION_MODE_OPTIONS: Array<{ label: string; value: ProtectionMode; tone: Tone }> = [
  { label: '拦截', value: 'enforce', tone: 'danger' },
  { label: '观察', value: 'observe', tone: 'warn' },
  { label: '关闭', value: 'off', tone: 'info' },
]
