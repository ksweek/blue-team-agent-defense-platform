import { reactive } from 'vue'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'
const TOKEN_KEY = 'blue-team-access-token'
const USER_KEY = 'blue-team-user'
const EXPIRES_AT_KEY = 'blue-team-expires-at'

type ApiEnvelope<T> = {
  code: number
  message: string
  data: T
}

export type AuthUser = {
  id: number
  username: string
  real_name: string
  roles: string[]
  pages: string[]
}

type LoginResponse = {
  access_token: string
  token_type: string
  expires_at: string
  user: AuthUser
}

type AuthCodePurpose = 'register' | 'reset_password'

type RegisterPayload = {
  username: string
  email: string
  password: string
  code: string
  real_name?: string
}

type ResetPasswordPayload = {
  email: string
  code: string
  new_password: string
}

function readStorage(key: string) {
  if (typeof window === 'undefined') {
    return null
  }
  return window.localStorage.getItem(key)
}

function parseStoredUser() {
  const raw = readStorage(USER_KEY)
  if (!raw) {
    return null
  }

  try {
    return JSON.parse(raw) as AuthUser
  } catch {
    return null
  }
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

function messageFromStatus(status: number) {
  if (status === 401) return '用户名或密码错误'
  if (status === 403) return '当前账号无权访问'
  if (status === 404) return '认证接口不存在，请确认后端已启动并正确代理 /api'
  if (status === 422) return '提交参数不完整或格式不正确'
  if (status === 429) return '操作过于频繁，请稍后再试'
  if (status >= 500) return '后端服务异常，请查看后端日志'
  return `HTTP ${status}`
}

async function readEnvelope<T>(response: Response): Promise<ApiEnvelope<T>> {
  const rawText = await response.text()
  if (!rawText.trim()) {
    const detail =
      response.status >= 500
        ? '后端接口没有返回内容，通常是前端代理目标未启动或后端进程已退出'
        : '接口没有返回内容'
    throw new Error(`${messageFromStatus(response.status)}：${detail}`)
  }

  try {
    return JSON.parse(rawText) as ApiEnvelope<T>
  } catch {
    const preview = rawText.replace(/\s+/g, ' ').slice(0, 120)
    throw new Error(
      `${messageFromStatus(response.status)}：接口未返回 JSON，请检查 Vite 代理或后端地址。响应片段：${preview}`
    )
  }
}

async function unwrapEnvelope<T>(response: Response): Promise<T> {
  const payload = await readEnvelope<T>(response)
  if (!response.ok || payload.code !== 0) {
    throw new Error(payload.message || messageFromStatus(response.status))
  }
  return payload.data
}

function persistSession() {
  if (typeof window === 'undefined') {
    return
  }

  if (authState.token) {
    window.localStorage.setItem(TOKEN_KEY, authState.token)
  } else {
    window.localStorage.removeItem(TOKEN_KEY)
  }

  if (authState.user) {
    window.localStorage.setItem(USER_KEY, JSON.stringify(authState.user))
  } else {
    window.localStorage.removeItem(USER_KEY)
  }

  if (authState.expiresAt) {
    window.localStorage.setItem(EXPIRES_AT_KEY, authState.expiresAt)
  } else {
    window.localStorage.removeItem(EXPIRES_AT_KEY)
  }
}

export const authState = reactive<{
  token: string | null
  user: AuthUser | null
  expiresAt: string | null
  initialized: boolean
}>({
  token: readStorage(TOKEN_KEY),
  user: parseStoredUser(),
  expiresAt: readStorage(EXPIRES_AT_KEY),
  initialized: false
})

export function getAccessToken() {
  return authState.token
}

export function isAuthenticated() {
  return Boolean(authState.token && authState.user)
}

export function clearAuthSession() {
  authState.token = null
  authState.user = null
  authState.expiresAt = null
  persistSession()
}

export async function login(username: string, password: string) {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  const data = await unwrapEnvelope<LoginResponse>(response)
  authState.token = data.access_token
  authState.user = data.user
  authState.expiresAt = data.expires_at
  authState.initialized = true
  persistSession()
  return data
}

export async function sendAuthCode(email: string, purpose: AuthCodePurpose, username?: string) {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/auth/send-code`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, purpose, username })
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  return unwrapEnvelope<{ sent: boolean }>(response)
}

export async function registerWithEmail(payload: RegisterPayload) {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  const data = await unwrapEnvelope<LoginResponse>(response)
  authState.token = data.access_token
  authState.user = data.user
  authState.expiresAt = data.expires_at
  authState.initialized = true
  persistSession()
  return data
}

export async function resetPasswordWithEmail(payload: ResetPasswordPayload) {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
  } catch (error) {
    throw buildNetworkError(error)
  }

  return unwrapEnvelope<{ reset: boolean }>(response)
}

export async function initializeAuth() {
  if (authState.initialized) {
    return
  }

  if (!authState.token) {
    authState.initialized = true
    return
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: {
        Authorization: `Bearer ${authState.token}`
      }
    })
    authState.user = await unwrapEnvelope<AuthUser>(response)
    persistSession()
  } catch {
    clearAuthSession()
  } finally {
    authState.initialized = true
  }
}

export function logout() {
  clearAuthSession()
}
