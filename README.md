# 蓝队防御管理平台

面向 Agent / LLM 的安全联调与在线防护平台原型，覆盖攻击样本回归、统一代理网关、执行前授权、事件归档、报告导出、Skill 纳管与扫描、多 AI 目标接入等能力。

这个仓库当前更接近“可运行的控制面 + 执行面原型”，而不是单纯的界面演示工程。核心闭环已经打通：

`选样本 -> 建任务 -> Worker 执行 -> 调模型/Agent -> 记录原始响应 -> 生成安全事件 -> 导出报告`

## 核心特点

- 统一防护入口：后端提供 `/gateway/v1/*` 网关，可接在模型端点或 Agent 运行时之前。
- 样本执行闭环：支持从本地攻击样本集创建任务、调度执行、归档事件与下载报告。
- 多 AI 目标接入：可纳管多个 AI/Agent 端点，而不是只依赖单一 `.env` Provider。
- 策略与审计并存：执行前授权、规则命中、AI 复核、输出脱敏、运行时回传可以串成一条链。
- Skill 纳管与扫描：支持新增 Skill、目录预览导入、扫描所选 Skill，并保留任务回显。
- 中文控制台：前端已收敛为中文页面，偏向安全运营台风格，而不是营销式仪表盘。

## 当前已具备的能力

- 后端：FastAPI + SQLAlchemy + JWT + RBAC + 外置 / 内嵌 Worker + 多 Provider 接入
- 网关：
  - `/gateway/v1/chat/completions`
  - `/gateway/v1/responses`
  - `/gateway/v1/agents/run`
  - `/gateway/v1/ws/*`
  - `/gateway/v1/runtime/*`
- 报告：
  - JSON
  - HTML
  - DOCX
  - 批量 ZIP
- 数据层：
  - SQLite 本地开发
  - PostgreSQL 生产接入
- 样本层：
  - 本地 GitHub 攻击集整理
  - 中文攻击面 / 规则分类
  - 事件与报告内中文触发说明

## 技术栈

### 后端

- Python 3.9+
- FastAPI
- SQLAlchemy
- Pydantic v2
- Alembic
- PostgreSQL / SQLite

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
ai_pc/
├─ backend/                       # FastAPI 后端、网关、Worker、数据库与服务层
├─ frontend/                      # Vue 控制台前端
├─ datasets/github_attack_sets/   # 攻击样本集与目录工具
├─ docs/                          # 平台设计、接口说明、测试文档
├─ tools/agent_gateway/           # 接入向导与代理工具
├─ scripts/                       # 仓库级校验脚本
├─ docker-compose.yml
├─ start.ps1
├─ smoke_test.py
└─ test_ai_provider.py
```

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

如果依赖已安装完成：

```powershell
.\start.ps1 -SkipInstall
```

默认地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- OpenAPI：`http://127.0.0.1:8000/docs`
- 健康检查：`http://127.0.0.1:8000/health`

本地默认账号，仅用于开发环境引导：

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

### 4. 运行最小回归测试

```powershell
cd backend
pip install -r requirements-dev.txt
cd ..
pytest backend/tests/test_regression_flows.py -q
```

这组回归会直接验证：

- `admin / admin123` 登录与 JWT 会话
- 样本任务创建、执行、事件落库、报告导出与下载
- Skill 目录预览导入、入库与扫描任务
- 系统动作导出/备份产物的真实落盘与下载接口

前端：

```powershell
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --clearScreen false
```

## 本地校验

仓库新增了统一校验脚本，用于在提交前做最基本的工程完整性检查。

Windows：

```powershell
.\scripts\validate.ps1
```

Unix：

```bash
sh ./scripts/validate.sh
```

默认会执行：

- 后端编译检查
- 数据库连通性校验
- 前端生产构建

按侧验证：

```powershell
.\scripts\validate.ps1 -BackendOnly
.\scripts\validate.ps1 -FrontendOnly
```

## 真实接入方式

当前项目主要有两类接入方式：

### 1. 离线回归 / 攻击样本验证

- 在控制台选择攻击样本
- 创建单个或批量任务
- 由 Worker 调度执行
- 自动生成安全事件与报告

### 2. 在线流量防护

- 让模型或 Agent 请求先进入平台网关
- 由平台做预检、策略判定、可选 AI 复核、输出脱敏与审计
- 再转发到真实模型端点或 Agent 运行时

详细方案见：

- [统一代理入口实施方案](./docs/platform/统一代理入口实施方案.md)
- [Agent 接入保护脚本说明](./docs/platform/Agent接入保护脚本说明.md)

## 文档索引

- [文档总览](./docs/README.md)
- [后端说明](./backend/README.md)
- [前端说明](./frontend/README.md)
- [平台工程设计](./docs/platform/蓝队防御平台工程设计.md)
- [平台接口设计](./docs/platform/蓝队防御平台接口设计文档.md)
- [完整方案](./docs/platform/蓝队防御管理平台完整方案.md)
- [AI 联调与可行性评估指南](./docs/testing/AI联调与可行性评估指南.md)
- [AI 攻击测试样本集](./docs/testing/AI攻击测试样本集.md)
- [攻击集使用说明](./docs/testing/攻击集使用说明.md)

## GitHub 协作规范

- [贡献指南](./CONTRIBUTING.md)
- [安全策略](./SECURITY.md)
- [CI 工作流](./.github/workflows/ci.yml)
