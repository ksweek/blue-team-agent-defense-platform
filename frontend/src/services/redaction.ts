const AUTHORIZATION_VALUE_RE = /(\bAuthorization\b\s*[:=]\s*(?:Bearer|Basic)\s+)([^\s"',]+)/gi
const QUERY_SECRET_RE =
  /([?&](?:api[_-]?key|access_token|refresh_token|token|sig(?:nature)?|auth|password|secret|client_secret)=)([^&#\s]+)/gi
const JSON_SECRET_VALUE_RE =
  /("?(?:api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|smtp_password|smtpPassword|password|passwd|pwd|secret|client[_-]?secret|clientSecret|private[_-]?key|privateKey|handoff_token|handoffToken|x-api-key|x_api_key|bearer[_-]?token|bearerToken|session[_-]?token|sessionToken|jwt)"?\s*:\s*")([^"]+)(")/gi
const TEXT_SECRET_VALUE_RE =
  /(\b(?:api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|smtp_password|smtpPassword|password|passwd|pwd|secret|client[_-]?secret|clientSecret|private[_-]?key|privateKey|handoff_token|handoffToken|x-api-key|x_api_key|bearer[_-]?token|bearerToken|session[_-]?token|sessionToken|jwt)\b\s*[:=]\s*)([^\s"',}]+)/gi
const COOKIE_RE = /(\b(?:cookie|set-cookie)\b\s*[:=]\s*)([^\r\n]+)/gi
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
const OPENAI_KEY_RE = /\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b/g
const ANTHROPIC_KEY_RE = /\bsk-ant-[A-Za-z0-9_-]{12,}\b/g
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
const WINDOWS_PATH_RE = /\b(?:[A-Za-z]:\\|\\\\)[^\s"'<>|]+/g
const UNIX_PATH_RE = /(^|[^A-Za-z0-9:])((?:\/[^/\s"'`]+){2,})/g
const SENSITIVE_FIELD_KEY_RE =
  /(?:^|[_\-.])(?:api(?:[_\-.]?key)?|access(?:[_\-.]?token)?|refresh(?:[_\-.]?token)?|auth(?:orization)?|bearer(?:[_\-.]?token)?|session(?:[_\-.]?token)?|jwt|password|passwd|pwd|secret|client(?:[_\-.]?secret)?|smtp(?:[_\-.]?password)?|private(?:[_\-.]?key)?|cookie|set[_\-.]?cookie|handoff(?:[_\-.]?token)?|x[_\-.]?api[_\-.]?key)(?:$|[_\-.])/i
const NORMALIZED_SENSITIVE_FIELD_KEYS = new Set([
  'apikey',
  'accesstoken',
  'refreshtoken',
  'auth',
  'authorization',
  'bearertoken',
  'sessiontoken',
  'jwt',
  'password',
  'passwd',
  'pwd',
  'secret',
  'clientsecret',
  'smtppassword',
  'privatekey',
  'cookie',
  'setcookie',
  'handofftoken',
  'xapikey',
])

export function maskMiddle(value: string, visibleStart = 4, visibleEnd = 2) {
  const text = value.trim()
  if (!text) {
    return ''
  }
  if (text.length <= visibleStart + visibleEnd + 1) {
    return '***'
  }
  return `${text.slice(0, visibleStart)}***${text.slice(-visibleEnd)}`
}

export function maskEmail(value: string) {
  const [localPart, domain = '***'] = value.split('@')
  const local = localPart.trim()
  if (!local) {
    return `***@${domain}`
  }
  const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2)
  return `${visible}***@${domain}`
}

export function maskWindowsPath(value: string) {
  const normalized = value.replace(/\//g, '\\')
  const segments = normalized.split(/\\+/).filter(Boolean)
  const tail = segments[segments.length - 1] || '***'
  if (/^[A-Za-z]:\\/.test(normalized)) {
    return `${normalized.slice(0, 2)}\\...\\${tail}`
  }
  return `\\\\...\\${tail}`
}

export function maskUnixPath(value: string) {
  const segments = value.split('/').filter(Boolean)
  const tail = segments[segments.length - 1] || '***'
  return `/.../${tail}`
}

export function shouldMaskUnixPath(value: string) {
  return !/^\/(?:api|@vite|src|assets|node_modules)\b/i.test(value)
}

export function redactSensitiveText(value: string | null | undefined) {
  let text = typeof value === 'string' ? value : value == null ? '' : String(value)
  if (!text) {
    return ''
  }

  text = text.replace(AUTHORIZATION_VALUE_RE, (_match, prefix, token) => `${prefix}${maskMiddle(token, 6, 4)}`)
  text = text.replace(QUERY_SECRET_RE, (_match, prefix, token) => `${prefix}${maskMiddle(token, 4, 2)}`)
  text = text.replace(JSON_SECRET_VALUE_RE, (_match, prefix, token, suffix) => `${prefix}${maskMiddle(token, 4, 2)}${suffix}`)
  text = text.replace(TEXT_SECRET_VALUE_RE, (_match, prefix, token) => `${prefix}${maskMiddle(token, 4, 2)}`)
  text = text.replace(COOKIE_RE, (_match, prefix, token) => `${prefix}${maskMiddle(token, 8, 4)}`)
  text = text.replace(JWT_RE, (token) => maskMiddle(token, 10, 6))
  text = text.replace(OPENAI_KEY_RE, (token) => maskMiddle(token, 8, 4))
  text = text.replace(ANTHROPIC_KEY_RE, (token) => maskMiddle(token, 8, 4))
  text = text.replace(EMAIL_RE, (email) => maskEmail(email))
  text = text.replace(WINDOWS_PATH_RE, (path) => maskWindowsPath(path))
  text = text.replace(UNIX_PATH_RE, (match, prefix, path) => {
    if (!shouldMaskUnixPath(path)) {
      return match
    }
    return `${prefix}${maskUnixPath(path)}`
  })

  return text
}

export function isSensitiveFieldKey(value: string | null | undefined) {
  const raw = typeof value === 'string' ? value.trim() : ''
  if (!raw) {
    return false
  }

  const normalized = raw.replace(/[^A-Za-z0-9]/g, '').toLowerCase()
  return NORMALIZED_SENSITIVE_FIELD_KEYS.has(normalized) || SENSITIVE_FIELD_KEY_RE.test(raw)
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object') {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function looksLikeStructuredText(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return false
  }

  return (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  )
}

function tryParseStructuredText(value: string) {
  if (!looksLikeStructuredText(value)) {
    return undefined
  }

  try {
    return JSON.parse(value) as unknown
  } catch {
    return undefined
  }
}

function maskSensitiveScalar(value: string) {
  if (!value.trim()) {
    return ''
  }

  return value
    .split(/(\r?\n)/)
    .map((segment) => (/^\r?\n$/.test(segment) ? segment : maskMiddle(segment, 4, 2)))
    .join('')
}

function redactStringValue(value: string, fieldKey?: string, forceMask = false) {
  const sensitive = forceMask || isSensitiveFieldKey(fieldKey)
  const parsed = tryParseStructuredText(value)
  if (parsed !== undefined) {
    const redactedParsed = redactUnknown(parsed, fieldKey, new WeakSet<object>(), sensitive)
    if (JSON.stringify(redactedParsed) !== JSON.stringify(parsed)) {
      return JSON.stringify(redactedParsed, null, 2)
    }
  }

  const redacted = redactSensitiveText(value)
  if (!sensitive) {
    return redacted
  }

  if (redacted !== value) {
    return redacted
  }

  return maskSensitiveScalar(value)
}

function redactUnknown<T>(
  value: T,
  fieldKey?: string,
  seen = new WeakSet<object>(),
  parentSensitive = false
): T {
  const currentSensitive = parentSensitive || isSensitiveFieldKey(fieldKey)

  if (typeof value === 'string') {
    return redactStringValue(value, fieldKey, currentSensitive) as T
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactUnknown(item, fieldKey, seen, currentSensitive)) as T
  }

  if (!isPlainObject(value)) {
    return value
  }

  if (seen.has(value)) {
    return value
  }
  seen.add(value)

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, redactUnknown(item, key, seen, currentSensitive)])
  ) as T
}

export function redactSensitiveValue<T>(value: T) {
  return redactUnknown(value)
}

export function stringifyRedactedValue(value: unknown, space = 2) {
  const redacted = redactSensitiveValue(value)
  if (typeof redacted === 'string') {
    return redacted
  }
  if (redacted === undefined) {
    return ''
  }

  try {
    return JSON.stringify(redacted, null, space)
  } catch {
    return redactSensitiveText(String(value))
  }
}

export function redactSettingToken(settingKey: string, value: string) {
  if (settingKey === 'notify_email_recipients') {
    return maskEmail(value)
  }
  return redactSensitiveText(value)
}

export function redactSettingValue(settingKey: string, value: string | null | undefined) {
  if (!value) {
    return ''
  }
  if (settingKey === 'notify_email_recipients') {
    return value
      .split(/[,\n;]+/)
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => maskEmail(item))
      .join(', ')
  }
  if (settingKey === 'notify_email_sender' || settingKey === 'smtp_username') {
    return maskEmail(value)
  }
  return redactSensitiveText(value)
}
