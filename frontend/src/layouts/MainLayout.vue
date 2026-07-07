<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandLogo from '../components/BrandLogo.vue'
import SidebarIcon from '../components/SidebarIcon.vue'
import { navSections } from '../data/platform'
import { authState, logout } from '../services/auth'

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
  visibleNavSections.value.find((section) => section.items.some((item) => isActive(item.to)))?.title ?? '导航'
)

const sessionRoles = computed(() =>
  authState.user?.roles.length ? authState.user.roles.join(' / ') : '未登录'
)

const userInitial = computed(() => {
  const raw = authState.user?.real_name?.trim() || authState.user?.username?.trim() || 'G'
  return raw.slice(0, 1).toUpperCase()
})

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
      <div class="sidebar-brand-shell">
        <div class="brand">
          <BrandLogo class="brand-mark" />
          <div class="brand-copy">
            <h1>GuardianAgent</h1>
            <p>安全防护平台</p>
          </div>
        </div>
      </div>

      <div class="sidebar-scroll">
        <div class="sidebar-nav-stack">
          <section
            v-for="section in visibleNavSections"
            :key="section.title"
            class="sidebar-group"
          >
            <header class="sidebar-group-head">
              <span class="sidebar-group-icon">
                <SidebarIcon :name="section.icon" />
              </span>
              <strong class="sidebar-group-title">{{ section.title }}</strong>
            </header>

            <nav class="sidebar-subnav">
              <RouterLink
                v-for="item in section.items"
                :key="item.label"
                :class="['sidebar-subnav-item', { active: isActive(item.to) }]"
                :to="item.to"
              >
                <span class="sidebar-subnav-dot" />
                <span class="sidebar-subnav-label">{{ item.label }}</span>
              </RouterLink>
            </nav>
          </section>
        </div>
      </div>

      <div class="sidebar-footer">
        <div class="sidebar-user">
          <span class="sidebar-user-avatar">{{ userInitial }}</span>
          <div class="sidebar-user-copy">
            <span class="sidebar-user-kicker">当前会话</span>
            <strong class="sidebar-user-name">{{ authState.user?.real_name ?? '未登录' }}</strong>
            <p class="sidebar-user-role">{{ authState.user?.username ?? '-' }} / {{ sessionRoles }}</p>
          </div>
          <button class="ghost-button sidebar-user-action" type="button" @click="handleLogout">退出</button>
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
