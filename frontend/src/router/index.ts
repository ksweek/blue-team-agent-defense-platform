import { createRouter, createWebHistory } from 'vue-router'
import MainLayout from '../layouts/MainLayout.vue'
import LoginPage from '../pages/LoginPage.vue'
import SecurityDashboardPage from '../pages/SecurityDashboardPage.vue'
import AttackTestingPage from '../pages/AttackTestingPage.vue'
import AiEndpointsPage from '../pages/AiEndpointsPage.vue'
import DefenseConfigPage from '../pages/DefenseConfigPage.vue'
import SecurityEventsPage from '../pages/SecurityEventsPage.vue'
import SecurityEventReportPage from '../pages/SecurityEventReportPage.vue'
import AssetProtectionPage from '../pages/AssetProtectionPage.vue'
import SkillManagementPage from '../pages/SkillManagementPage.vue'
import SystemSettingsPage from '../pages/SystemSettingsPage.vue'
import { authState, initializeAuth, isAuthenticated } from '../services/auth'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginPage,
      meta: {
        requiresAuth: false,
        title: '登录'
      }
    },
    {
      path: '/attack-lab',
      name: 'attack-testing',
      component: AttackTestingPage,
      meta: {
        title: '攻击测试',
        accessPath: '/attack-lab'
      }
    },
    {
      path: '/',
      component: MainLayout,
      children: [
        {
          path: '',
          name: 'dashboard',
          component: SecurityDashboardPage,
          meta: {
            title: '安全仪表盘'
          }
        },
        {
          path: 'ai-endpoints',
          name: 'ai-endpoints',
          component: AiEndpointsPage,
          meta: {
            title: 'AI 目标'
          }
        },
        {
          path: 'defense-config',
          name: 'defense-config',
          component: DefenseConfigPage,
          meta: {
            title: '防御配置'
          }
        },
        {
          path: 'security-events',
          name: 'security-events',
          component: SecurityEventsPage,
          meta: {
            title: '安全事件'
          }
        },
        {
          path: 'security-events/:eventId/report',
          name: 'security-event-report',
          component: SecurityEventReportPage,
          meta: {
            title: '安全报告',
            accessPath: '/security-events'
          }
        },
        {
          path: 'asset-protection',
          name: 'asset-protection',
          component: AssetProtectionPage,
          meta: {
            title: '资产保护'
          }
        },
        {
          path: 'skill-management',
          name: 'skill-management',
          component: SkillManagementPage,
          meta: {
            title: '技能管理'
          }
        },
        {
          path: 'system-settings',
          name: 'system-settings',
          component: SystemSettingsPage,
          meta: {
            title: '系统设置'
          }
        }
      ]
    }
  ]
})

router.beforeEach(async (to) => {
  await initializeAuth()

  if (to.meta.requiresAuth === false) {
    if (to.name === 'login' && isAuthenticated()) {
      return authState.user?.pages[0] || '/'
    }
    return true
  }

  if (!isAuthenticated()) {
    return {
      name: 'login',
      query: {
        redirect: to.fullPath
      }
    }
  }

  const accessPath = (to.meta.accessPath as string | undefined) ?? to.path
  if (accessPath !== '/' && authState.user && !authState.user.pages.includes(accessPath)) {
    return authState.user.pages[0] || '/'
  }

  return true
})

export default router
