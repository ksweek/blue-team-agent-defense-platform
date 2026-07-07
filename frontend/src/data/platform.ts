export const navSections = [
  {
    title: '快捷入口',
    icon: 'dashboard',
    items: [
      { label: '系统安全总览', to: '/', icon: 'dashboard' },
    ],
  },
  {
    title: '目标治理',
    icon: 'ai',
    items: [
      { label: 'AI 目标', to: '/ai-endpoints', icon: 'ai' },
    ],
  },
  {
    title: '监测响应',
    icon: 'events',
    items: [
      { label: '安全事件', to: '/security-events', icon: 'events' },
      { label: '攻击实验室', to: '/attack-lab', icon: 'samples' },
    ],
  },
  {
    title: '配置管理',
    icon: 'settings',
    items: [
      { label: '系统设置', to: '/system-settings', icon: 'settings' },
    ],
  },
] as const

export const attackCards = [
  {
    title: '越权调用',
    level: '高风险',
    tone: 'danger',
    detail: '检查目标是否会调用未授权工具、路径或技能。',
  },
  {
    title: '提示注入',
    level: '高风险',
    tone: 'danger',
    detail: '覆盖直接注入、间接注入、多轮污染和组合攻击链。',
  },
  {
    title: '权限绕过',
    level: '中高风险',
    tone: 'warn',
    detail: '重点看跨插件、MCP、审批链和角色借用风险。',
  },
  {
    title: '输出泄露',
    level: '中高风险',
    tone: 'warn',
    detail: '确认输出中是否出现敏感信息泄露和脱敏失败。',
  },
] as const

export const eventFilters = ['全部', '高危', '可疑', '已拦截', '已放行'] as const
