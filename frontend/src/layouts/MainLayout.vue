<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandLogo from '../components/BrandLogo.vue'
import SidebarIcon from '../components/SidebarIcon.vue'
import { navSections } from '../data/platform'
import { authState, logout } from '../services/auth'
import { api } from '../services/api'

const route = useRoute()
const router = useRouter()

const pageTitle = computed(() => (route.meta.title as string) ?? 'GuardianAgent')

const visibleNavSections = computed(() => {
  const pages = new Set(authState.user?.pages ?? [])

  return navSections
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => item.to === '/' || pages.has(item.to)),
    }))
    .filter((section) => section.items.length > 0)
})

const activeSectionTitle = computed(() =>
  visibleNavSections.value.find((section) => section.items.some((item) => isActive(item.to)))?.title ?? '主入口'
)

const sessionRoles = computed(() =>
  authState.user?.roles.length ? authState.user.roles.join(' / ') : '未登录'
)

const dashboardOverview = ref<null | {
  attack_count: number
  blocked_count: number
  enabled_defense_count: number
  high_risk_event_count: number
  active_task_count: number
}>(null)

const dashboardTopStats = computed(() => {
  if (!dashboardOverview.value) {
    return []
  }

  return [
    { label: '攻击', value: dashboardOverview.value.attack_count, tone: 'danger' },
    { label: '拦截', value: dashboardOverview.value.blocked_count, tone: 'safe' },
    { label: '高危', value: dashboardOverview.value.high_risk_event_count, tone: 'warn' },
    { label: '防线', value: dashboardOverview.value.enabled_defense_count, tone: 'info' },
    { label: '活跃', value: dashboardOverview.value.active_task_count, tone: 'warn' },
  ] as const
})

watch(
  () => route.path,
  async () => {
    try {
      dashboardOverview.value = await api.dashboardOverview()
    } catch {
      dashboardOverview.value = null
    }
  },
  { immediate: true },
)

function isActive(path: string) {
  if (path === '/') {
    return route.path === '/'
  }
  return route.path.startsWith(path)
}

function handleLogout() {
  logout()
  void router.push('/login')
}
</script>

<template>
  <div class="layout-shell">
    <aside class="sidebar">
      <div class="sidebar-hero">
        <div class="brand">
          <BrandLogo class="brand-mark" />
          <div class="brand-copy">
            <h1>GuardianAgent</h1>
            <p>安全防护平台</p>
          </div>
        </div>
      </div>

      <div class="sidebar-scroll">
        <section
          v-for="section in visibleNavSections"
          :key="section.title"
          class="nav-section"
        >
          <p v-if="visibleNavSections.length > 1" class="sidebar-section-title">{{ section.title }}</p>

          <nav class="nav-list">
            <RouterLink
              v-for="item in section.items"
              :key="item.label"
              :class="['nav-item', { active: isActive(item.to) }]"
              :to="item.to"
            >
              <span class="nav-icon">
                <SidebarIcon :name="item.icon" />
              </span>
              <span class="nav-text">
                <span class="nav-title">{{ item.label }}</span>
              </span>
            </RouterLink>
          </nav>
        </section>
      </div>

      <div class="sidebar-footer">
        <div v-if="dashboardTopStats.length" class="sidebar-runtime-card">
          <div class="sidebar-runtime-head">
            <strong>运行态总览</strong>
            <span>实时</span>
          </div>
          <div class="sidebar-runtime-grid">
            <article
              v-for="item in dashboardTopStats"
              :key="item.label"
              :class="['sidebar-runtime-stat', `tone-${item.tone}`, { wide: item.label === '活跃' }]"
            >
              <span>{{ item.label }}</span>
              <strong>{{ item.value }}</strong>
            </article>
          </div>
        </div>

        <div class="sidebar-user">
          <strong class="sidebar-user-name">{{ authState.user?.real_name ?? '未登录' }}</strong>
          <p class="sidebar-user-role">{{ authState.user?.username ?? '-' }} / {{ sessionRoles }}</p>
          <button class="ghost-button sidebar-logout" type="button" @click="handleLogout">退出登录</button>
        </div>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div class="topbar-surface">
          <div class="topbar-copy">
            <p class="topbar-breadcrumb">{{ activeSectionTitle }} / {{ pageTitle }}</p>
            <h2>{{ pageTitle }}</h2>
          </div>

          <div class="topbar-side">
            <span class="topbar-chip">{{ authState.user?.real_name ?? '未登录' }}</span>
            <span class="topbar-chip muted">{{ sessionRoles }}</span>
          </div>
        </div>
      </header>

      <div class="main-content">
        <RouterView />
      </div>
    </main>
  </div>
</template>
