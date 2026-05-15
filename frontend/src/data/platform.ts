export const navSections = [
  {
    title: '主入口',
    items: [
      { label: '系统安全总览', to: '/', icon: 'dashboard' },
      { label: 'AI 目标', to: '/ai-endpoints', icon: 'ai' },
      { label: '安全事件', to: '/security-events', icon: 'events' },
      { label: '攻击实验室', to: '/attack-lab', icon: 'samples' },
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
