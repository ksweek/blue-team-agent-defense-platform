# AI 联调与可行性评估指南

本文档说明当前项目怎样接入真实 AI / Agent、如何做联调、怎样判断现阶段是否“可用”。

截至 `2026-06-20`，平台已经支持：

- 配置真实 OpenAI-compatible Provider
- 创建和执行攻击任务
- 嵌入式或外置 Worker 异步跑任务
- 记录原始响应
- 生成安全事件和报告记录
- 样本目录查询、单条/批量样本建任务和批量报告下载
- `/gateway/v1/chat/completions`、`/responses`、`/agents/run` 统一代理入口
- 对应的 SSE / WebSocket 联调入口
- Runtime 注册、授权、心跳、命令拉取和完成回传
- MCP 策略与一次性执行票据校验
- Redis 优先缓存、入口限流、请求大小限制和敏感字段脱敏

它已经具备最小“运行时 AI 网关”闭环，但还不是生产级高可用网关。更准确的定位是：

**一个可联调的安全治理控制台 + 最小任务执行闭环 + 最小统一代理网关。**

## 1. 先把项目跑起来

### 本地启动

```powershell
.\start.ps1
```

如果依赖已经装好：

```powershell
.\start.ps1 -SkipInstall
```

### Docker 启动

```powershell
.\start.ps1 -Mode docker -Build
```

默认地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- OpenAPI：`http://127.0.0.1:8000/docs`

默认账号：

- `admin / admin_123`
- `analyst / analyst123`

## 2. 先做基础健康检查

### 健康接口

访问：

```text
http://127.0.0.1:8000/health
```

你应该关注：

- `status=ok`
- `task_worker=running`
- `ai_provider`
- `ai_configured`

### 冒烟测试

```powershell
python smoke_test.py
```

当前会覆盖：

- 登录
- JWT
- RBAC
- 防御配置落库
- 技能扫描任务创建与执行
- 样本目录、样本建任务与批量报告
- AI 目标、Runtime Registry、Gateway 与 MCP Ticket 主链路
- 资产与白名单读写
- 系统设置动作
- 仪表盘聚合接口

### 后端测试状态

当前已验证：

```powershell
python -m pytest backend/tests --collect-only -q
python -m pytest backend/tests -q
```

结果：

- 收集到 `57` 个测试。
- 完整执行结果为 `56 passed, 1 failed, 4 warnings`。
- 失败用例是 `backend/tests/test_concurrent_all_features.py::test_concurrent_all_feature_flows`，原因是在本地 SQLite 下 100 并发写入 Skill 导入链路时出现 `database is locked`。

因此本地 SQLite 适合开发和联调；如果要验证高并发任务、Gateway 或 Runtime 回调，应切换到 PostgreSQL，并启用 Redis 缓存。

## 3. 配置真实 AI Provider

在项目根目录创建 `.env`：

```env
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=your-api-key
AI_MODEL=your-model-id
AI_TIMEOUT_SECONDS=60
AI_TEMPERATURE=0
AI_MAX_TOKENS=1200
```

说明：

- `AI_PROVIDER=disabled` 时，任务不会真正调用模型
- `AI_BASE_URL` 可以换成任意兼容 OpenAI Chat Completions 的服务
- Provider 适配层核心仍是 OpenAI-compatible Chat Completions；Gateway 已提供 Responses 兼容入口，但多模态和复杂 tool protocol 仍需要按目标 Provider 继续适配

## 4. 当前项目怎么做 AI 联调

### 4.1 平台内最直接的入口

当前最直接的联调入口是“技能管理”页：

1. 登录前端
2. 进入“技能管理”
3. 勾选一个或多个技能
4. 点击“扫描所选技能”
5. 前端会创建攻击任务并立即触发执行
6. 后台 Worker 调用 Provider
7. 平台生成安全事件和报告记录

这是当前最完整、最顺手的内置联调路径。

### 4.2 通过 API 做联调

如果你要接外部脚本、Agent Runtime 或回归工具，最核心的 API 是：

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/defense-configs`
- `GET /api/defense-configs/profile`
- `GET /api/ai-endpoints`
- `GET /api/samples`
- `POST /api/attack-tasks/from-sample`
- `POST /api/attack-tasks/batch-from-samples`
- `POST /api/attack-tasks`
- `POST /api/attack-tasks/{id}/run`
- `GET /api/attack-tasks/{id}`
- `GET /api/security-events`
- `GET /api/security-events/{id}/report-view`
- `GET /api/reports`
- `POST /api/reports/batch-download`
- `POST /gateway/v1/chat/completions`
- `POST /gateway/v1/responses`
- `POST /gateway/v1/agents/run`
- `POST /gateway/v1/runtime/authorize`
- `POST /gateway/v1/runtime/heartbeat`
- `POST /gateway/v1/runtime/complete`

建议的基本流程：

1. 登录拿 `access_token`
2. 拉取当前策略与受保护资源
3. 创建任务
4. 提交后台执行
5. 轮询任务状态直到 `done / failed`
6. 再查询事件与报告

如果测试的是在线代理入口，可以改为：

1. 登录或准备服务令牌 / Runtime 凭据
2. 选择受保护 AI 目标
3. 调 `/gateway/v1/chat/completions`、`/gateway/v1/responses` 或 `/gateway/v1/agents/run`
4. 观察响应头 `X-Request-ID`、网关决策、事件和报告记录
5. 对 `stream=true` 和 WebSocket 入口做单独回归

## 5. 推荐的对接方式

当前最合理的接法不是让这个项目直接替代你的 Agent Runtime，而是把它当作：

**策略中心 + 任务记录中心 + 结果归档中心 + 统一代理入口**

推荐结构：

```text
用户 / 攻击样本
        |
        v
Blue Team Gateway / 你的 Agent Runtime / Adapter
        |
        +--> 调真实模型
        +--> 在输入、工具调用、输出阶段做策略判断
        +--> 将结果回写到本平台
        |
        v
蓝队防御管理平台
```

这样做的好处：

- 不需要把现有 Agent Runtime 推倒重来
- 平台负责“治理和记录”
- 你的运行时继续负责“执行和拦截”

## 6. 目前能验证什么

### 6.1 工程可行性

当前已经可以验证：

- 服务能否稳定启动
- 登录与权限链路是否成立
- 配置是否真实落库
- 后台任务能否正确流转
- Provider 是否能真实调用
- 事件和报告是否能归档

### 6.2 平台可行性

当前已经可以验证：

- 是否能集中管理策略
- 是否能管理资产、技能和受保护对象
- 是否能形成“动作执行区 + 设置编辑区 + 审计回显区”
- 是否能把模型联调结果回收到统一控制台

### 6.3 防护效果可行性

当前可以做初步验证，但不能直接下最终结论。

你可以观察：

- Prompt Injection 是否被识别
- 越权工具调用是否被阻断
- 输出是否被脱敏
- 多轮上下文污染是否会失控

但当前平台还不能单独证明“生产级运行时防护能力”，因为：

- Worker 已支持嵌入式/外置形态，但还没有完整的跨实例抢占、死信队列和任务超时回收机制
- 样本选择、批量运行、批量报告已经可用，但大规模回归的统计看板、误报分析和趋势对比仍需继续产品化
- Runtime 授权、心跳、命令和完成回传已经落地，但多租户隔离、密钥生命周期审计和命令队列 HA 仍需加强
- 在线网关已落地，但高并发场景需要 PostgreSQL + Redis；本地 SQLite 已在 100 并发测试中暴露写锁边界

## 7. 当前最实用的测试方式

### 方式一：平台内置闭环

适合：

- 快速联调
- 演示页面动作和任务执行
- 验证数据库与任务状态流转

步骤：

1. 配置 `.env`
2. 启动平台
3. 进入技能管理页
4. 触发扫描
5. 查看任务、事件、报告和日志

### 方式二：外部脚本调用 API

适合：

- 接样本集
- 跑回归
- 与你自己的 Agent Runtime 联调

建议：

- 用 `datasets/github_attack_sets/curated/by_section/*.jsonl` 作为输入
- 优先使用 `/api/attack-tasks/from-sample` 和 `/api/attack-tasks/batch-from-samples`
- 需要完全自定义参数时，再用 `/api/attack-tasks` 和 `/api/attack-tasks/{id}/run` 驱动执行
- 执行后用 `/api/reports/batch-download` 打包归档报告

### 方式三：先跑无模型模式

适合：

- 只验证平台链路
- 先不消耗模型调用成本

说明：

- 当 `AI_PROVIDER=disabled` 时，任务会失败
- 但这能帮助你确认“任务创建、Worker 接管、失败回写、事件边界”是否清晰

## 8. 怎么判断这个项目有没有继续做的价值

建议分三层判断。

### 8.1 工程层

问自己：

- 能不能稳定启动？
- 前后端能不能联通？
- 配置和动作是不是能真正落库？
- 任务闭环是不是能跑通？

当前结论：可以。

### 8.2 平台层

问自己：

- 是否形成统一治理入口？
- 是否形成统一事件和审计入口？
- 是否适合作为未来运行时适配层的控制面？

当前结论：可以。

### 8.3 防护效果层

问自己：

- 对真实攻击样本是否有足够拦截率？
- 是否误报过多？
- 是否会让运行成本或延迟不可接受？

当前结论：还需要继续用样本集和真实 Runtime 验证，不能只凭平台原型下结论。

## 9. 建议重点观察的指标

- 启动成功率
- 登录成功率
- 配置写入成功率
- 任务成功率 / 失败率
- 平均任务耗时
- 事件生成率
- 报告生成率
- 越权调用拦截率
- 输出脱敏命中率

## 10. 下一步最值得补的三件事

1. 把 Worker、命令队列和 Gateway 压测切到 PostgreSQL + Redis，补齐死信队列、超时回收和跨实例抢占。
2. 增加样本回归统计看板，沉淀拦截率、误报率、敏感输出命中率和模型/策略对比趋势。
3. 强化 Runtime 与 Gateway 的生产治理，包括多租户隔离、长连接限速、熔断、密钥轮换审计和 Provider 错误码归一。
