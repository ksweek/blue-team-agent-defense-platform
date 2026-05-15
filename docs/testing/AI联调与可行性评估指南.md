# AI 联调与可行性评估指南

本文档说明当前项目怎样接入真实 AI / Agent、如何做联调、怎样判断现阶段是否“可用”。

截至 `2026-04-19`，平台已经支持：

- 配置真实 OpenAI-compatible Provider
- 创建和执行攻击任务
- 后台 Worker 异步跑任务
- 记录原始响应
- 生成安全事件和报告记录

但它还不是一个完整的“运行时 AI 网关”，更准确的定位是：

**一个可联调的安全治理控制台 + 最小任务执行闭环。**

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

- `admin / admin123`
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
- 资产与白名单读写
- 系统设置动作
- 仪表盘聚合接口

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
- 当前适配层不支持 Responses API、多模态或自定义 tool protocol

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
- `POST /api/attack-tasks`
- `POST /api/attack-tasks/{id}/run`
- `GET /api/attack-tasks/{id}`
- `GET /api/security-events`
- `GET /api/reports`

建议的基本流程：

1. 登录拿 `access_token`
2. 拉取当前策略与受保护资源
3. 创建任务
4. 提交后台执行
5. 轮询任务状态直到 `done / failed`
6. 再查询事件与报告

## 5. 推荐的对接方式

当前最合理的接法不是让这个项目直接替代你的 Agent Runtime，而是把它当作：

**策略中心 + 任务记录中心 + 结果归档中心**

推荐结构：

```text
用户 / 攻击样本
        |
        v
你的 Agent Runtime / Adapter
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

- Worker 仍是进程内线程
- 样本选择和批量运行还没完全产品化
- 运行时事件回传接口还不完整
- 策略执行更多体现在任务评估链路，而不是在线拦截网关

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
- 每条样本转成任务参数
- 用 `/api/attack-tasks` 和 `/api/attack-tasks/{id}/run` 驱动执行

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

1. 增加外部 Agent Runtime 结果回传接口，把运行时链路真正接进来。
2. 增加样本选择、批量任务执行和回归报告能力。
3. 把 Worker 从进程内线程升级为独立队列消费模型。
