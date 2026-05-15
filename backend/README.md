# GuardianAgent 后端

后端基于 `FastAPI + SQLAlchemy + JWT + 可嵌入/外置 Worker + 多 Provider 接入 + 网关代理`。

截至 `2026-05-06`，后端已经支持：

- SQLite / PostgreSQL
- JWT 登录与 RBAC
- 防御配置、资产、技能、任务、事件、报告、系统设置落库
- 后台 Worker 异步执行攻击任务
- 外置 Worker 进程 `python run_worker.py`
- OpenAI-compatible / Azure OpenAI / Anthropic / Gemini / Ollama / Bedrock
- 统一网关 `/gateway/v1/*`
- WebSocket 网关 `/gateway/v1/ws/*`
- 备份、恢复、配置导入、回滚

说明：

- 对外导出的防御配置和平台备份默认会脱敏密码类设置、密码哈希和 AI 端点密钥
- 平台备份 ZIP 默认不再附带原始 `app.db` 文件
- 统一命令行日志输出

## 快速启动

```powershell
cd backend
pip install -r requirements.txt
python scripts/init_db.py
python run_dev.py
```

本地外置 Worker 模式：

终端 1：

```powershell
cd backend
$env:TASK_WORKER_EMBEDDED="false"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

终端 2：

```powershell
cd backend
$env:TASK_WORKER_EMBEDDED="false"
python run_worker.py
```

默认地址：

- OpenAPI：`http://127.0.0.1:8000/docs`
- 健康检查：`http://127.0.0.1:8000/health`

## 默认账号

- 本地引导管理员：`admin / admin123`
- 本地引导分析员：`analyst / analyst123`

说明：

- `scripts/init_db.py --mode setup` 会创建表、补基线默认项，并在本地导入样本数据
- `scripts/init_db.py --mode schema` 会创建表和基线默认项，但不会导入样本任务/事件/报告
- 如果数据库里已经有旧用户，脚本不会强制重置密码
- 生产环境必须替换 `BOOTSTRAP_ADMIN_PASSWORD / BOOTSTRAP_ANALYST_PASSWORD`

## 数据库配置

环境变量加载顺序：

1. 项目根目录 `.env`
2. `backend/.env`
3. 代码默认值

### SQLite

```env
APP_ENV=development
BOOTSTRAP_MODE=auto
DATABASE_URL=sqlite:///backend/data/app.db
DATABASE_ECHO=false
DATABASE_POOL_PRE_PING=true

BOOTSTRAP_ADMIN_PASSWORD=admin123
BOOTSTRAP_ANALYST_PASSWORD=analyst123
SEED_SAMPLE_DATA=true
```

默认数据库文件：

- `backend/data/app.db`

### PostgreSQL

```env
DATABASE_URL=postgresql+psycopg://blue_team:blue_team_pw@127.0.0.1:5432/blue_team
DATABASE_ECHO=false
DATABASE_POOL_PRE_PING=true
```

配合 Docker Compose 时，可一起配置：

```env
POSTGRES_DB=blue_team
POSTGRES_USER=blue_team
POSTGRES_PASSWORD=blue_team_pw
```

## AI Provider 配置

```env
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=your-api-key
AI_MODEL=your-model-id
AI_TIMEOUT_SECONDS=60
AI_TEMPERATURE=0
AI_MAX_TOKENS=1200
TASK_WORKER_POLL_INTERVAL=0.5
TASK_WORKER_RECOVERY_LIMIT=200
APP_LOG_LEVEL=INFO
```

说明：

- `APP_ENV=production` 时，运行态默认使用 `BOOTSTRAP_MODE=validate`
- 生产环境应先执行 `python scripts/init_db.py --mode schema`，再启动 API / Worker
- `AI_PROVIDER=disabled` 时，平台仍可运行，任务执行会退化为 rule-only 模式
- 需要 AI 复核但没有可用端点时，任务会写入 `review_decision=no_ai_endpoint_configured`
- 受管 AI 端点优先于 legacy `.env` Provider

可配置的 Worker 相关变量：

```env
TASK_WORKER_EMBEDDED=true
TASK_WORKER_CONCURRENCY=1
TASK_WORKER_POLL_INTERVAL=0.5
TASK_WORKER_RECOVERY_LIMIT=200
TASK_WORKER_HEARTBEAT_INTERVAL=5
TASK_WORKER_STALE_SECONDS=180
TASK_WORKER_RETRY_DELAY_SECONDS=10
TASK_WORKER_MAX_ATTEMPTS=3
```

## 后台 Worker

当前 Worker 设计：

- 应用启动时可自动启动嵌入式 Worker
- 也可单独启动 `python run_worker.py`
- 自动释放到点 `scheduled` 任务
- 自动回收陈旧 `running` 任务
- 负责 `queued -> running -> done / scheduled / dead_letter` 流转
- 运行日志持久化写入 `task_runtime_logs`

当前边界：

- 当前仍是数据库轮询调度，不是 Redis / RabbitMQ 消息队列
- 运行中的上游 HTTP 请求仍是协作式中断，不是强制硬中断
- 更大规模的跨节点并发控制仍需进一步建设

## 网关

当前已提供：

- `POST /gateway/v1/chat/completions`
- `POST /gateway/v1/responses`
- `POST /gateway/v1/agents/run`
- `POST /gateway/v1/runtime/authorize`
- `POST /gateway/v1/runtime/heartbeat`
- `POST /gateway/v1/runtime/complete`
- `WS /gateway/v1/ws/chat/completions`
- `WS /gateway/v1/ws/responses`
- `WS /gateway/v1/ws/agents/run`

说明：

- HTTP SSE 和 WebSocket 两套接入面都已可用
- 当输出脱敏模式为 `off` 时，可使用上游实时流式透传
- 当输出脱敏模式为 `observe / enforce` 时，会切换为治理后缓冲输出

## 日志

本地开发模式使用统一日志格式，主要组件包括：

- `lifecycle`
- `http`
- `worker`
- `pipeline`
- `provider`

样例：

```text
[2026-04-19 08:38:49] INFO    worker             -          worker started | thread=attack-task-worker poll_interval=0.50s
[2026-04-19 08:38:49] WARNING http               demo-task  GET /api/attack-tasks -> 401 1ms ip=127.0.0.1
```

## 初始化与自检

```powershell
cd backend
python scripts/init_db.py
```

成功时会输出：

- 数据库类型
- 脱敏后的连接串
- `Database initialized and reachable.`

## Docker Compose

项目根目录已提供：

```powershell
docker compose up --build -d
```

默认会启动：

- `postgres`
- `backend`
- `frontend`

说明：

- Compose 下后端默认连接容器内 PostgreSQL
- 如需继续使用 SQLite，可在根目录 `.env` 中覆盖 `DATABASE_URL`
- 如需外置 Worker，可执行：

```powershell
docker compose --profile external-worker up -d
```

同时将 `.env` 中的 `TASK_WORKER_EMBEDDED=false`

## 当前边界

- Alembic 目前只有 baseline revision，后续 schema 演进还需要继续沉淀
- Worker 目前仍是数据库轮询，不是独立消息队列
- 运行中任务仍是协作式中断
- 报告中心已经支持 JSON / HTML 导出，但还没有 PDF 等更完整的导出形态
