# 蓝队防御管理平台

面向 Agent / LLM 的安全治理与在线防护平台，提供统一接入网关、执行前授权、事件归档、报告导出、Skill 治理与扫描、多 AI 目标接入等能力。

这份目录是整理后的 GitHub 发布版，仅保留运行、部署、接入与平台说明所需内容。

## 核心能力

- 统一防护网关：提供 `/gateway/v1/*` 入口，可部署在模型端点或 Agent Runtime 前方。
- 多目标路由：支持纳管多个 AI / Agent 目标，并通过默认目标、目标组和运行时绑定进行路由。
- 执行前授权：对高风险路径、Skill、Plugin、MCP 能力和审批链进行前置判定。
- 事件与报告：对执行结果进行归档，输出 JSON、HTML、DOCX 和批量 ZIP 报告。
- Skill 治理：支持 Skill 录入、目录导入、风险扫描和信任状态管理。
- 中文控制台：前端控制台覆盖登录、总览、AI 目标、防护配置、安全事件、资产保护、技能管理、系统设置等页面。

## 技术栈

### 后端

- Python 3.9+
- FastAPI
- SQLAlchemy
- Pydantic v2
- Alembic
- SQLite / PostgreSQL

### 前端

- Node.js 18+
- Vue 3
- TypeScript
- Vite

### 可选组件

- Docker / Docker Compose
- 外部 AI Provider 或受管 AI 目标
- `agent-scan` 类 Skill 扫描工具

## 仓库结构

```text
github-release/
├─ backend/                       # FastAPI 后端、网关、Worker、数据库与服务层
├─ frontend/                      # Vue 控制台前端
├─ datasets/github_attack_sets/   # 运行时使用的整理后样本目录
├─ docs/                          # 平台设计、接口说明、接入文档
├─ tools/agent_gateway/           # 统一接入向导与前置网关工具
├─ connect_agent_gateway.cmd      # Windows 接入入口
├─ connect_agent_gateway.sh       # Linux / macOS 接入入口
├─ docker-compose.yml
├─ start.ps1
└─ README.md
```

说明：

- `datasets/github_attack_sets/` 仅保留运行时需要的 `curated/` 数据。
- 根目录接入脚本仅保留 `connect_agent_gateway.cmd` 与 `connect_agent_gateway.sh`。

## 快速开始

### 1. 准备环境变量

```powershell
Copy-Item .env.example .env
```

默认本地配置使用 SQLite，并在开发模式下启用基础引导数据。

### 2. 一键启动

```powershell
.\start.ps1
```

如果依赖已经安装完成：

```powershell
.\start.ps1 -SkipInstall
```

默认地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- OpenAPI：`http://127.0.0.1:8000/docs`
- 健康检查：`http://127.0.0.1:8000/health`

本地默认账号，仅用于开发环境初始化：

- `admin / admin123`
- `analyst / analyst123`

### 3. 手动启动

后端：

```powershell
cd backend
pip install -r requirements.txt
python scripts/init_db.py
python run_dev.py
```

前端：

```powershell
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --clearScreen false
```

## Agent 接入

发布版只保留统一接入脚本。

### Windows

```powershell
.\connect_agent_gateway.cmd
```

### Linux / macOS

```bash
sh ./connect_agent_gateway.sh
```

无参数运行时会进入中文菜单，可完成：

- 启动接入向导
- 查看支持的预设
- 导出平台模板
- 校验已有配置
- 启动已有网关

详细说明见：

- [Agent 接入保护脚本说明](./docs/platform/Agent接入保护脚本说明.md)
- [统一代理入口实施方案](./docs/platform/统一代理入口实施方案.md)

## 文档索引

- [文档总览](./docs/README.md)
- [后端说明](./backend/README.md)
- [前端说明](./frontend/README.md)
- [平台工程设计](./docs/platform/蓝队防御平台工程设计.md)
- [平台接口设计](./docs/platform/蓝队防御平台接口设计文档.md)
- [完整方案](./docs/platform/蓝队防御管理平台完整方案.md)
- [统一代理入口实施方案](./docs/platform/统一代理入口实施方案.md)
- [Agent 接入保护脚本说明](./docs/platform/Agent接入保护脚本说明.md)
- [防御规则库更新说明](./docs/platform/防御规则库更新说明.md)
