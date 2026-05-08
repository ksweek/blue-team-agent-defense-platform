<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { login } from '../services/auth'

const router = useRouter()
const route = useRoute()

const username = ref('admin')
const password = ref('admin123')
const loading = ref(false)
const error = ref('')

async function submit() {
  loading.value = true
  error.value = ''

  try {
    await login(username.value.trim(), password.value)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (err) {
    error.value = err instanceof Error ? err.message : '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="login-shell">
    <article class="login-panel">
      <div class="login-head">
        <div class="login-brand-mark">蓝</div>
        <div class="login-copy">
          <span class="login-kicker">蓝队防御平台</span>
          <h1>登录</h1>
        </div>
        <div class="login-account-list">
          <span class="login-account-chip">admin / admin123</span>
          <span class="login-account-chip">analyst / analyst123</span>
        </div>
      </div>

      <form class="login-form" @submit.prevent="submit">
        <label class="login-field">
          <span>账号</span>
          <input
            v-model="username"
            class="text-input"
            autocomplete="username"
            placeholder="admin"
            type="text"
          />
        </label>

        <label class="login-field">
          <span>密码</span>
          <input
            v-model="password"
            class="text-input"
            autocomplete="current-password"
            placeholder="admin123"
            type="password"
          />
        </label>

        <p v-if="error" class="login-error">{{ error }}</p>

        <button class="primary-button login-submit" :disabled="loading" type="submit">
          {{ loading ? '登录中...' : '登录' }}
        </button>
      </form>
    </article>
  </section>
</template>
