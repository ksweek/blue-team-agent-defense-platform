import type { AiEndpointItem, FormFieldTone } from '../../services/api'

export type Tone = FormFieldTone
export type ProtectionMode = AiEndpointItem['protection_mode']
export type ProviderType = AiEndpointItem['provider_type']

export const PROVIDER_LABELS: Record<ProviderType, string> = {
  openai_compatible: 'OpenAI 兼容',
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
  { label: 'OpenAI 兼容', value: 'openai_compatible' },
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
