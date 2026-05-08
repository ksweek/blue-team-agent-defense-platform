<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import SidebarIcon from '../components/SidebarIcon.vue'
import { navSections } from '../data/platform'
import { authState, logout } from '../services/auth'

const route = useRoute()
const router = useRouter()

const pageTitle = computed(() => (route.meta.title as string) ?? '蓝队防御平台')

const visibleNavSections = computed(() => {
  const pages = new Set(authState.user?.pages ?? [])

  return navSections
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => item.to === '/' || pages.has(item.to)),
    }))
    .filter((section) => section.items.length > 0)
})

const sessionRoles = computed(() =>
  authState.user?.roles.length ? authState.user.roles.join(' / ') : '未登录'
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
      <div class="brand">
        <div class="brand-mark">蓝</div>
        <div class="brand-copy">
          <h1>蓝队防御</h1>
          <p>AI 安全联调平台</p>
        </div>
      </div>

      <div class="sidebar-scroll">
        <section
          v-for="section in visibleNavSections"
          :key="section.title"
          class="nav-section"
        >
          <p class="sidebar-section-title">{{ section.title }}</p>

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
        <div class="sidebar-user">
          <strong class="sidebar-user-name">{{ authState.user?.real_name ?? '未登录' }}</strong>
          <p class="sidebar-user-role">{{ authState.user?.username ?? '-' }} / {{ sessionRoles }}</p>
          <button class="ghost-button sidebar-logout" type="button" @click="handleLogout">退出登录</button>
        </div>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div class="topbar-copy">
          <p class="topbar-breadcrumb">工作台 / {{ pageTitle }}</p>
          <h2>{{ pageTitle }}</h2>
        </div>
      </header>

      <RouterView />
    </main>
  </div>
</template>
