# 蓝队防御管理平台前端

前端基于 `Vue 3 + TypeScript + Vite`，当前已完成登录页、安全总览、攻击测试、AI 目标、防御配置、安全事件、资产保护、技能管理、系统设置等核心页面。

截至 `2026-04-19`，前端已经具备：

- JWT 登录态管理
- 路由守卫
- 按角色过滤页面
- 多页面即时反馈模型
- 防御配置 / 资产 / 技能 / 系统设置的后端字段元数据驱动

## 启动与构建

开发模式：

```powershell
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --clearScreen false
```

生产构建：

```powershell
cd frontend
npm run build
```

默认地址：

- `http://127.0.0.1:5173`

默认后端地址：

- `http://127.0.0.1:8000/api`

如果需要修改 API 地址，可配置：

- `VITE_API_BASE_URL`

## 公网部署

前端开发和预览服务已支持对外监听：

- `vite.config.ts` 已启用 `server.host = true`
- `vite.config.ts` 已启用 `preview.host = true`
- 开发代理默认转发 `/api` 到 `VITE_API_PROXY_TARGET`

可复制 `frontend/.env.example` 为本地环境文件，并按需设置：

- `VITE_PUBLIC_BASE`
- `VITE_API_BASE_URL`
- `VITE_API_PROXY_TARGET`
- `VITE_PORT`
- `VITE_PREVIEW_PORT`

推荐做法：

- 开发环境：前端走 `/api` 代理到本机或远端后端
- 生产环境：前后端同域部署，前端继续使用 `VITE_API_BASE_URL=/api`
- 跨域部署：后端额外配置 `CORS_ORIGINS` 或 `CORS_ORIGIN_REGEX`

## 当前页面

- 登录页
- 安全总览
- 攻击测试
- AI 目标
- 防御配置
- 安全事件
- 资产保护
- 技能管理
- 系统设置

## 当前交互特点

### 即时反馈

以下页面已经统一为“点一下即生效”：

- 技能管理
- 资产保护
- 安全事件
- 系统设置动作区

表现为：

- 顶部反馈条显示 `saving / saved / error`
- 动作完成后立即回写列表和焦点卡片

### 自动保存

以下页面已取消传统“保存”按钮：

- 防御配置
- 系统设置

表现为：

- 切换开关、模式或输入字段后自动提交
- 后端返回最新值后直接回写本地状态

### 后端元数据驱动

以下页面的控件映射已从前端挪到后端：

- 防御配置
- 资产保护
- 技能管理
- 系统设置

前端根据后端下发的：

- `control`
- `options`
- `tone`
- `placeholder`
- `helper_text`

来决定渲染方式。

## 目录说明

```text
frontend/
├─ src/
│  ├─ components/          # 通用组件
│  ├─ composables/         # 组合式逻辑
│  ├─ data/                # 页面辅助数据
│  ├─ layouts/             # 主布局
│  ├─ pages/               # 业务页面
│  ├─ router/              # 路由与守卫
│  ├─ services/            # API 与认证
│  ├─ App.vue
│  ├─ main.ts
│  └─ style.css            # 全局样式
├─ Dockerfile
├─ nginx.conf
├─ index.html
├─ package.json
└─ vite.config.ts
```

## Docker

根目录直接启动：

```powershell
docker compose up --build -d
```

前端容器说明：

- 构建时默认注入 `VITE_API_BASE_URL=/api`
- 运行时通过 Nginx 代理 `/api` 到后端
- 对外端口：`5173`

## 当前边界

- 当前没有专门的全局状态库，例如 Pinia
- 还没有复杂图表组件体系
- 任务结果对比和更细粒度报表检索还可继续增强

## 下一步建议

1. 增加样本选择与批量任务执行页。
2. 增加任务 / 报告对比视图。
3. 抽离更多列表、表单和状态反馈组件，降低重复代码。
4. 增加统一消息中心和会话过期提示。
