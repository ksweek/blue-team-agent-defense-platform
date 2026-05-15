import type { SecurityReportPayloadItem, SecurityReportRawSection, SensitiveFindingItem } from './api'
import {
  maskEmail,
  maskMiddle,
  maskUnixPath,
  maskWindowsPath,
  redactSensitiveValue,
  shouldMaskUnixPath
} from './redaction'

type SegmentKind = 'plain' | 'payload' | 'sensitive'

type Match = {
  start: number
  end: number
  kind: Exclude<SegmentKind, 'plain'>
  label: string
  displayText?: string
}

type BaseRow = {
  id: string
  label: string
  locator: string
  value: string
}

export type RawHighlightSegment = {
  kind: SegmentKind
  text: string
  label?: string
}

export type RawHighlightRow = {
  id: string
  label: string
  locator: string
  locationKey: string
  anchor: string
  value: string
  segments: RawHighlightSegment[]
  payloadPatterns: string[]
  sensitiveLabels: string[]
  sensitiveCategories: string[]
  hasHits: boolean
}

export type RawHighlightSectionView = {
  section: SecurityReportRawSection
  rows: RawHighlightRow[]
}

export function buildRawLocationKey(sectionKey: string, locator: string) {
  return encodeURIComponent(`${sectionKey}:${locator || 'content'}`)
}

export function buildRawRowAnchor(sectionKey: string, rowId: string) {
  return encodeURIComponent(`${sectionKey}:${rowId}`)
}

const AUTHORIZATION_VALUE_RE = /(\bAuthorization\b\s*[:=]\s*(?:Bearer|Basic)\s+)([^\s"',]+)/gi
const QUERY_SECRET_RE =
  /([?&](?:api[_-]?key|access_token|refresh_token|token|sig(?:nature)?|auth|password|secret|client_secret)=)([^&#\s]+)/gi
const JSON_SECRET_VALUE_RE =
  /("?(?:api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|smtp_password|smtpPassword|qq_email_auth_code|qqEmailAuthCode|password|passwd|pwd|secret|client[_-]?secret|clientSecret|private[_-]?key|privateKey|handoff_token|handoffToken|x-api-key|x_api_key|bearer[_-]?token|bearerToken|session[_-]?token|sessionToken|jwt)"?\s*:\s*")([^"]+)(")/gi
const TEXT_SECRET_VALUE_RE =
  /(\b(?:api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|smtp_password|smtpPassword|qq_email_auth_code|qqEmailAuthCode|password|passwd|pwd|secret|client[_-]?secret|clientSecret|private[_-]?key|privateKey|handoff_token|handoffToken|x-api-key|x_api_key|bearer[_-]?token|bearerToken|session[_-]?token|sessionToken|jwt)\b\s*[:=]\s*)([^\s"',}]+)/gi
const COOKIE_RE = /(\b(?:cookie|set-cookie)\b\s*[:=]\s*)([^\r\n]+)/gi
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
const OPENAI_KEY_RE = /\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b/g
const ANTHROPIC_KEY_RE = /\bsk-ant-[A-Za-z0-9_-]{12,}\b/g
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
const WINDOWS_PATH_RE = /\b(?:[A-Za-z]:\\|\\\\)[^\s"'<>|]+/g
const UNIX_PATH_RE = /(^|[^A-Za-z0-9:])((?:\/[^/\s"'`]+){2,})/g

export function buildRawHighlightRows(
  section: SecurityReportRawSection,
  payloadItems: SecurityReportPayloadItem[],
  sensitiveItems: SensitiveFindingItem[]
) {
  const rows = flattenRawSection(section)

  return rows.map((row) => {
    const rowPayloadPatterns = uniqueStrings(
      payloadItems
        .filter(
          (item) =>
            item.kind === 'pattern' &&
            item.source === section.title &&
            sameLocation(item.location, row.locator)
        )
        .map((item) => item.label)
    )

    const rowSensitiveItems = sensitiveItems.filter(
      (item) => item.source === section.title && sameLocation(item.location, row.locator)
    )
    const rowSensitiveLabels = uniqueStrings(rowSensitiveItems.map((item) => item.label))
    const rowSensitiveCategories = uniqueStrings(rowSensitiveItems.map((item) => item.category))

    return {
      ...row,
      locationKey: buildRawLocationKey(section.key, row.locator),
      anchor: buildRawRowAnchor(section.key, row.id),
      payloadPatterns: rowPayloadPatterns,
      sensitiveLabels: rowSensitiveLabels,
      sensitiveCategories: rowSensitiveCategories,
      segments: buildHighlightedSegments(row.value, rowPayloadPatterns, rowSensitiveCategories),
      hasHits: rowPayloadPatterns.length > 0 || rowSensitiveLabels.length > 0
    } satisfies RawHighlightRow
  })
}

export function buildRawHighlightSectionViews(
  sections: SecurityReportRawSection[],
  payloadItems: SecurityReportPayloadItem[],
  sensitiveItems: SensitiveFindingItem[]
) {
  return sections.map((section) => ({
    section,
    rows: buildRawHighlightRows(section, payloadItems, sensitiveItems)
  })) satisfies RawHighlightSectionView[]
}

function flattenRawSection(section: SecurityReportRawSection) {
  if (section.format === 'text') {
    return flattenTextContent(asDisplayString(section.content), 'content')
  }
  return flattenStructuredContent(redactSensitiveValue(section.content), '')
}

function flattenStructuredContent(value: unknown, path: string): BaseRow[] {
  if (typeof value === 'string') {
    return flattenTextContent(value, path || 'content')
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return [
      {
        id: `${path || 'content'}-0`,
        label: path || 'content',
        locator: path || 'content',
        value: JSON.stringify(value)
      }
    ]
  }

  if (value === null) {
    return [
      {
        id: `${path || 'content'}-0`,
        label: path || 'content',
        locator: path || 'content',
        value: 'null'
      }
    ]
  }

  if (Array.isArray(value)) {
    if (!value.length) {
      return [
        {
          id: `${path || 'root'}-0`,
          label: path || 'root',
          locator: path || 'root',
          value: '[]'
        }
      ]
    }
    return value.flatMap((item, index) => flattenStructuredContent(item, path ? `${path}[${index}]` : `[${index}]`))
  }

  if (typeof value === 'object' && value) {
    const entries = Object.entries(value as Record<string, unknown>)
    if (!entries.length) {
      return [
        {
          id: `${path || 'root'}-0`,
          label: path || 'root',
          locator: path || 'root',
          value: '{}'
        }
      ]
    }
    return entries.flatMap(([key, item]) => flattenStructuredContent(item, path ? `${path}.${key}` : key))
  }

  return [
    {
      id: `${path || 'content'}-0`,
      label: path || 'content',
      locator: path || 'content',
      value: asDisplayString(value)
    }
  ]
}

function flattenTextContent(value: string, locator: string) {
  const text = value.replace(/\r\n/g, '\n')
  const lines = text.split('\n')
  if (lines.length <= 1) {
    return [
      {
        id: `${locator}-1`,
        label: locator,
        locator,
        value: text
      }
    ]
  }

  return lines
    .map((line, index) => ({
      id: `${locator}-${index + 1}`,
      label: `${locator}:${index + 1}`,
      locator,
      value: line
    }))
    .filter((item) => item.value.trim().length > 0)
}

function buildHighlightedSegments(value: string, payloadPatterns: string[], sensitiveCategories: string[]) {
  const sensitiveMatches = collectSensitiveMatches(value, sensitiveCategories)
  const segments = applyMatches(value, sensitiveMatches)

  return segments.flatMap((segment) => {
    if (segment.kind !== 'plain') {
      return [segment]
    }

    const payloadMatches = collectPayloadMatches(segment.text, payloadPatterns)
    return applyMatches(segment.text, payloadMatches)
  })
}

function applyMatches(value: string, matches: Match[]) {
  if (!matches.length) {
    return [{ kind: 'plain', text: value }] satisfies RawHighlightSegment[]
  }

  const segments: RawHighlightSegment[] = []
  let cursor = 0

  for (const match of matches) {
    if (match.start > cursor) {
      segments.push({
        kind: 'plain',
        text: value.slice(cursor, match.start)
      })
    }

    segments.push({
      kind: match.kind,
      text: match.displayText ?? value.slice(match.start, match.end),
      label: match.label
    })

    cursor = match.end
  }

  if (cursor < value.length) {
    segments.push({
      kind: 'plain',
      text: value.slice(cursor)
    })
  }

  return segments
}

function collectSensitiveMatches(value: string, sensitiveCategories: string[]) {
  if (!value) {
    return []
  }

  const matches: Match[] = []

  matches.push(
    ...collectRegexMatches(value, AUTHORIZATION_VALUE_RE, '敏感凭据', (matched) => {
      const prefix = matched.groups[0] ?? ''
      const token = matched.groups[1] ?? ''
      return `${prefix}${maskMiddle(token, 6, 4)}`
    })
  )
  matches.push(
    ...collectRegexMatches(value, QUERY_SECRET_RE, '敏感参数', (matched) => {
      const prefix = matched.groups[0] ?? ''
      const token = matched.groups[1] ?? ''
      return `${prefix}${maskMiddle(token, 4, 2)}`
    })
  )
  matches.push(
    ...collectRegexMatches(value, JSON_SECRET_VALUE_RE, '敏感字段', (matched) => {
      const prefix = matched.groups[0] ?? ''
      const token = matched.groups[1] ?? ''
      const suffix = matched.groups[2] ?? ''
      return `${prefix}${maskMiddle(token, 4, 2)}${suffix}`
    })
  )
  matches.push(
    ...collectRegexMatches(value, TEXT_SECRET_VALUE_RE, '敏感字段', (matched) => {
      const prefix = matched.groups[0] ?? ''
      const token = matched.groups[1] ?? ''
      return `${prefix}${maskMiddle(token, 4, 2)}`
    })
  )
  matches.push(
    ...collectRegexMatches(value, COOKIE_RE, 'Cookie', (matched) => {
      const prefix = matched.groups[0] ?? ''
      const token = matched.groups[1] ?? ''
      return `${prefix}${maskMiddle(token, 8, 4)}`
    })
  )
  matches.push(...collectSimpleMatches(value, JWT_RE, 'JWT', (token) => maskMiddle(token, 10, 6)))
  matches.push(...collectSimpleMatches(value, OPENAI_KEY_RE, 'OpenAI Key', (token) => maskMiddle(token, 8, 4)))
  matches.push(...collectSimpleMatches(value, ANTHROPIC_KEY_RE, 'Anthropic Key', (token) => maskMiddle(token, 8, 4)))
  matches.push(...collectSimpleMatches(value, EMAIL_RE, '邮箱', (token) => maskEmail(token)))
  matches.push(...collectSimpleMatches(value, WINDOWS_PATH_RE, '路径', (token) => maskWindowsPath(token)))
  matches.push(
    ...collectUnixPathMatches(value).map((item) => ({
      ...item,
      displayText: maskUnixPath(item.displayText ?? '')
    }))
  )

  const selected = selectNonOverlappingMatches(matches)
  if (selected.length) {
    return selected
  }

  if (sensitiveCategories.includes('secret_field') && value.trim()) {
    return [
      {
        start: 0,
        end: value.length,
        kind: 'sensitive' as const,
        label: '敏感字段',
        displayText: maskMiddle(value, 4, 2)
      }
    ]
  }

  return []
}

function collectPayloadMatches(value: string, payloadPatterns: string[]) {
  if (!value || !payloadPatterns.length) {
    return []
  }

  const matches: Match[] = []
  for (const pattern of uniqueStrings(payloadPatterns).sort((left, right) => right.length - left.length)) {
    const escaped = escapeRegExp(pattern)
    const regex = new RegExp(escaped, 'gi')
    let matched: RegExpExecArray | null
    while ((matched = regex.exec(value)) !== null) {
      matches.push({
        start: matched.index,
        end: matched.index + matched[0].length,
        kind: 'payload',
        label: pattern
      })
    }
  }
  return selectNonOverlappingMatches(matches)
}

function collectRegexMatches(
  value: string,
  pattern: RegExp,
  label: string,
  formatter: (payload: { match: string; groups: string[] }) => string
) {
  const matches: Match[] = []
  const regex = new RegExp(pattern.source, pattern.flags)
  let matched: RegExpExecArray | null

  while ((matched = regex.exec(value)) !== null) {
    matches.push({
      start: matched.index,
      end: matched.index + matched[0].length,
      kind: 'sensitive',
      label,
      displayText: formatter({
        match: matched[0],
        groups: matched.slice(1)
      })
    })
  }

  return matches
}

function collectSimpleMatches(value: string, pattern: RegExp, label: string, formatter: (match: string) => string) {
  const matches: Match[] = []
  const regex = new RegExp(pattern.source, pattern.flags)
  let matched: RegExpExecArray | null

  while ((matched = regex.exec(value)) !== null) {
    matches.push({
      start: matched.index,
      end: matched.index + matched[0].length,
      kind: 'sensitive',
      label,
      displayText: formatter(matched[0])
    })
  }

  return matches
}

function collectUnixPathMatches(value: string) {
  const matches: Match[] = []
  const regex = new RegExp(UNIX_PATH_RE.source, UNIX_PATH_RE.flags)
  let matched: RegExpExecArray | null

  while ((matched = regex.exec(value)) !== null) {
    const prefix = matched[1] ?? ''
    const path = matched[2] ?? ''
    if (!path || !shouldMaskUnixPath(path)) {
      continue
    }

    const start = matched.index + prefix.length
    matches.push({
      start,
      end: start + path.length,
      kind: 'sensitive',
      label: '路径',
      displayText: path
    })
  }

  return matches
}

function selectNonOverlappingMatches(matches: Match[]) {
  return [...matches]
    .sort((left, right) => {
      if (left.start !== right.start) {
        return left.start - right.start
      }
      if (right.end - right.start !== left.end - left.start) {
        return right.end - right.start - (left.end - left.start)
      }
      return left.kind === 'sensitive' && right.kind !== 'sensitive' ? -1 : 1
    })
    .reduce<Match[]>((selected, item) => {
      const last = selected[selected.length - 1]
      if (!last || item.start >= last.end) {
        selected.push(item)
      }
      return selected
    }, [])
}

function sameLocation(left: string, right: string) {
  return (left || 'content') === (right || 'content')
}

function uniqueStrings(values: string[]) {
  return values.filter((value, index) => value && values.indexOf(value) === index)
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function asDisplayString(value: unknown) {
  if (typeof value === 'string') {
    return value
  }
  if (value === undefined) {
    return ''
  }
  return JSON.stringify(value)
}
