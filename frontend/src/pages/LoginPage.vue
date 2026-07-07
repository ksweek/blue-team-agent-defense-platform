<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandLogo from '../components/BrandLogo.vue'
import { login, registerWithEmail, resetPasswordWithEmail, sendAuthCode } from '../services/auth'

type LoginMode = 'login' | 'register' | 'forgot'
type AuthRouteName = 'login' | 'register' | 'forgot-password'

const router = useRouter()
const route = useRoute()

const loading = ref(false)
const sendingRegisterCode = ref(false)
const sendingResetCode = ref(false)
const error = ref('')
const message = ref('')
const rememberUsername = ref(true)

const rememberedUsernameKey = 'blue-team-login-username'
const rememberedUsername =
  typeof window === 'undefined' ? '' : window.localStorage.getItem(rememberedUsernameKey) ?? ''

const loginForm = reactive({
  username: rememberedUsername || 'admin',
  password: 'admin_123',
})

const registerForm = reactive({
  username: '',
  email: '',
  code: '',
  password: '',
  realName: '',
})

const resetForm = reactive({
  email: '',
  code: '',
  password: '',
})

const mode = computed<LoginMode>(() => {
  if (route.name === 'register') {
    return 'register'
  }
  if (route.name === 'forgot-password') {
    return 'forgot'
  }
  return 'login'
})

const pageCopy = computed(() => {
  if (mode.value === 'register') {
    return {
      eyebrow: '创建账号',
      title: '邮箱验证码注册',
      helper: '',
      action: '注册',
    }
  }

  if (mode.value === 'forgot') {
    return {
      eyebrow: '重置密码',
      title: '找回登录密码',
      helper: '',
      action: '重置密码',
    }
  }

  return {
    eyebrow: '欢迎使用',
    title: '登录 GuardianAgent',
    helper: '',
    action: '登录',
  }
})

watch(mode, clearNotice)

function isExternalRedirect(target: string) {
  if (typeof window === 'undefined') {
    return false
  }

  try {
    const url = new URL(target, window.location.origin)
    return url.origin !== window.location.origin
  } catch {
    return false
  }
}

function buildExternalRedirect(target: string, payload: { access_token: string; expires_at: string; user: { username: string } }) {
  const url = new URL(target)
  url.hash = new URLSearchParams({
    display_token: payload.access_token,
    display_expires_at: payload.expires_at,
    display_user: payload.user.username,
  }).toString()
  return url.toString()
}

function redirectAfterAuth(payload?: { access_token: string; expires_at: string; user: { username: string } }) {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
  if (payload && isExternalRedirect(redirect)) {
    window.location.assign(buildExternalRedirect(redirect, payload))
    return Promise.resolve()
  }
  return router.replace(redirect)
}

function authRoute(name: AuthRouteName) {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : ''
  return {
    name,
    query: redirect ? { redirect } : {},
  }
}

function clearNotice() {
  error.value = ''
  message.value = ''
}

function normalizeError(err: unknown, fallback: string) {
  return err instanceof Error && err.message ? err.message : fallback
}

function isEmail(value: string) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value.trim())
}

function validateRegisterBase() {
  if (registerForm.username.trim().length < 3) {
    error.value = '账号至少需要 3 个字符'
    return false
  }
  if (!isEmail(registerForm.email)) {
    error.value = '请填写正确的邮箱地址'
    return false
  }
  return true
}

function validateResetBase() {
  if (!isEmail(resetForm.email)) {
    error.value = '请填写正确的绑定邮箱'
    return false
  }
  return true
}

async function submitLogin() {
  loading.value = true
  error.value = ''
  message.value = ''

  try {
    const payload = await login(loginForm.username.trim(), loginForm.password)
    if (typeof window !== 'undefined') {
      if (rememberUsername.value) {
        window.localStorage.setItem(rememberedUsernameKey, loginForm.username.trim())
      } else {
        window.localStorage.removeItem(rememberedUsernameKey)
      }
    }
    await redirectAfterAuth(payload)
  } catch (err) {
    error.value = normalizeError(err, '登录失败，请检查账号和密码')
  } finally {
    loading.value = false
  }
}

async function sendRegisterCode() {
  sendingRegisterCode.value = true
  error.value = ''
  message.value = ''

  try {
    if (!validateRegisterBase()) {
      return
    }
    await sendAuthCode(registerForm.email.trim(), 'register', registerForm.username.trim())
    message.value = '注册验证码已发送，请查看邮箱'
  } catch (err) {
    error.value = normalizeError(err, '验证码发送失败')
  } finally {
    sendingRegisterCode.value = false
  }
}

async function submitRegister() {
  loading.value = true
  error.value = ''
  message.value = ''

  try {
    if (!validateRegisterBase()) {
      return
    }
    if (registerForm.password.length < 8) {
      error.value = '密码至少需要 8 个字符'
      return
    }
    if (registerForm.code.trim().length < 4) {
      error.value = '请填写邮箱验证码'
      return
    }
    const payload = await registerWithEmail({
      username: registerForm.username.trim(),
      email: registerForm.email.trim(),
      code: registerForm.code.trim(),
      password: registerForm.password,
      real_name: registerForm.realName.trim() || undefined,
    })
    await redirectAfterAuth(payload)
  } catch (err) {
    error.value = normalizeError(err, '注册失败，请检查验证码和表单信息')
  } finally {
    loading.value = false
  }
}

async function sendResetCode() {
  sendingResetCode.value = true
  error.value = ''
  message.value = ''

  try {
    if (!validateResetBase()) {
      return
    }
    await sendAuthCode(resetForm.email.trim(), 'reset_password')
    message.value = '如果邮箱存在，验证码将发送到该邮箱'
  } catch (err) {
    error.value = normalizeError(err, '验证码发送失败')
  } finally {
    sendingResetCode.value = false
  }
}

async function submitResetPassword() {
  loading.value = true
  error.value = ''
  message.value = ''

  try {
    if (!validateResetBase()) {
      return
    }
    if (resetForm.password.length < 8) {
      error.value = '新密码至少需要 8 个字符'
      return
    }
    if (resetForm.code.trim().length < 4) {
      error.value = '请填写邮箱验证码'
      return
    }
    await resetPasswordWithEmail({
      email: resetForm.email.trim(),
      code: resetForm.code.trim(),
      new_password: resetForm.password,
    })
    resetForm.code = ''
    resetForm.password = ''
    await router.push(authRoute('login'))
    message.value = '密码已重置，请使用新密码登录'
  } catch (err) {
    error.value = normalizeError(err, '密码重置失败，请检查验证码')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="login-shell">
    <div class="login-grid" aria-hidden="true"></div>

    <article class="login-panel">
      <aside class="login-visual">
        <div class="login-visual-top">
          <BrandLogo class="login-brand-mark" />
          <div class="login-visual-brand">
            <span>GuardianAgent</span>
            <strong>AI 防御与评估平台</strong>
          </div>
        </div>

        <div class="login-visual-copy">
          <h1>面向 Function-Calling Agent 的多维 AI 防御与评估平台</h1>
        </div>
      </aside>

      <main class="login-stage">
        <div class="login-stage-topbar">
          <div class="login-stage-brand">
            <BrandLogo class="login-stage-logo" />
            <div>
              <span>GuardianAgent</span>
              <strong>安全访问入口</strong>
            </div>
          </div>
          <span class="login-stage-badge">{{ pageCopy.eyebrow }}</span>
        </div>

        <section class="login-card">
          <div class="login-card-head">
            <span>{{ pageCopy.eyebrow }}</span>
            <h2>{{ pageCopy.title }}</h2>
            <p v-if="pageCopy.helper">{{ pageCopy.helper }}</p>
          </div>

          <form v-if="mode === 'login'" class="login-form" @submit.prevent="submitLogin">
            <label class="login-field">
              <span>账号</span>
              <input
                v-model="loginForm.username"
                class="text-input"
                autocomplete="username"
                placeholder="admin"
                type="text"
              />
            </label>

            <label class="login-field">
              <span>密码</span>
              <input
                v-model="loginForm.password"
                class="text-input"
                autocomplete="current-password"
                placeholder="admin_123"
                type="password"
              />
            </label>

            <div class="login-options-row">
              <label class="login-remember">
                <input v-model="rememberUsername" type="checkbox" />
                <span>记住用户名</span>
              </label>
              <RouterLink class="login-inline-link" :to="authRoute('forgot-password')" @click="clearNotice">
                忘记密码
              </RouterLink>
            </div>

            <p v-if="error" class="login-error">{{ error }}</p>
            <p v-if="message" class="login-message">{{ message }}</p>

            <div class="login-login-actions">
              <button class="login-primary-button" :disabled="loading" type="submit">
                {{ loading ? '登录中...' : pageCopy.action }}
              </button>
              <RouterLink class="login-secondary-button" :to="authRoute('register')" @click="clearNotice">
                注册账号
              </RouterLink>
            </div>
          </form>

          <form v-else-if="mode === 'register'" class="login-form" @submit.prevent="submitRegister">
            <div class="login-form-grid">
              <label class="login-field">
                <span>账号</span>
                <input
                  v-model="registerForm.username"
                  class="text-input"
                  autocomplete="username"
                  placeholder="例如 analyst01"
                  type="text"
                />
              </label>

              <label class="login-field">
                <span>姓名</span>
                <input
                  v-model="registerForm.realName"
                  class="text-input"
                  autocomplete="name"
                  placeholder="可选"
                  type="text"
                />
              </label>
            </div>

            <label class="login-field">
              <span>邮箱</span>
              <input
                v-model="registerForm.email"
                class="text-input"
                autocomplete="email"
                placeholder="name@example.com"
                type="email"
              />
            </label>

            <div class="login-code-row">
              <label class="login-field">
                <span>验证码</span>
                <input
                  v-model="registerForm.code"
                  class="text-input"
                  autocomplete="one-time-code"
                  placeholder="6 位验证码"
                  type="text"
                />
              </label>
              <button class="login-code-button" :disabled="sendingRegisterCode" type="button" @click="sendRegisterCode">
                {{ sendingRegisterCode ? '发送中...' : '发送验证码' }}
              </button>
            </div>

            <label class="login-field">
              <span>密码</span>
              <input
                v-model="registerForm.password"
                class="text-input"
                autocomplete="new-password"
                placeholder="至少 8 位"
                type="password"
              />
            </label>

            <p v-if="error" class="login-error">{{ error }}</p>
            <p v-if="message" class="login-message">{{ message }}</p>

            <div class="login-action-stack">
              <button class="login-primary-button" :disabled="loading" type="submit">
                {{ loading ? '注册中...' : pageCopy.action }}
              </button>
              <RouterLink class="login-secondary-button" :to="authRoute('login')" @click="clearNotice">
                返回登录
              </RouterLink>
            </div>
          </form>

          <form v-else class="login-form" @submit.prevent="submitResetPassword">
            <label class="login-field">
              <span>绑定邮箱</span>
              <input
                v-model="resetForm.email"
                class="text-input"
                autocomplete="email"
                placeholder="name@example.com"
                type="email"
              />
            </label>

            <div class="login-code-row">
              <label class="login-field">
                <span>验证码</span>
                <input
                  v-model="resetForm.code"
                  class="text-input"
                  autocomplete="one-time-code"
                  placeholder="6 位验证码"
                  type="text"
                />
              </label>
              <button class="login-code-button" :disabled="sendingResetCode" type="button" @click="sendResetCode">
                {{ sendingResetCode ? '发送中...' : '发送验证码' }}
              </button>
            </div>

            <label class="login-field">
              <span>新密码</span>
              <input
                v-model="resetForm.password"
                class="text-input"
                autocomplete="new-password"
                placeholder="至少 8 位"
                type="password"
              />
            </label>

            <p v-if="error" class="login-error">{{ error }}</p>
            <p v-if="message" class="login-message">{{ message }}</p>

            <div class="login-action-stack">
              <button class="login-primary-button" :disabled="loading" type="submit">
                {{ loading ? '提交中...' : pageCopy.action }}
              </button>
              <RouterLink class="login-secondary-button" :to="authRoute('login')" @click="clearNotice">
                返回登录
              </RouterLink>
            </div>
          </form>
        </section>

      </main>
    </article>
  </section>
</template>
