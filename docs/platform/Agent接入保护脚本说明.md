# Agent 接入保护脚本说明

这套脚本的目标不是“把一个地址填进平台就自动受保护”，而是帮你快速起一个统一前置网关，让外部请求先过防护平台，再决定是否转发到真实 Agent。

## 适用场景

- OpenClaw / 自研 HTTP JSON Agent
- OpenAI 兼容聊天接口
- Dify / Chatflow / Workflow 类 HTTP API
- 其他需要“前置授权 + 审计回传”的 Agent 服务

## 这套脚本会做什么

脚本启动后，会通过中文交互方式帮你完成以下步骤：

1. 采集保护平台地址、注册码 `Enrollment Token`
2. 采集 Runtime 显示名称和类型
3. 采集上游 Agent 地址，例如 `http://100.100.100.25:4567`
4. 采集本地监听地址，以及业务侧最终准备访问的网关地址
5. 根据接入类型生成字段映射
6. 自动发起 Runtime 注册
7. 自动轮询管理员审批结果
8. 将 `runtime_key` / `runtime_secret` 落地到本地配置
9. 生成 Windows / Linux 的启动脚本
10. 可直接启动一个前置网关

网关运行后的处理链路是：

```text
调用方 -> 前置防护网关 -> 保护平台建任务
                    -> 保护平台前置授权
                    -> 放行时转发到真实 Agent
                    -> 将真实结果回传平台
```

## 可用脚本

默认使用方式已经切成 shell 优先：

- 用户直接运行 `.cmd` 或 `.sh`
- 菜单负责中文引导、收集输入、选择动作
- Python 只作为后台执行引擎，不再作为主操作入口暴露给普通用户

### Windows

```powershell
.\connect_agent_gateway.cmd
```

### Linux / macOS

```bash
sh ./connect_agent_gateway.sh
```

无参数运行时会进入菜单，可直接选择：

- 启动接入向导
- 查看支持的预设
- 导出单个平台模板
- 批量导出内置模板
- 校验已有配置
- 启动已有网关

如果你要脚本化调用，也保留了参数直传模式。

查看当前已支持的平台预设：

```powershell
.\connect_agent_gateway.cmd presets
```

```bash
sh ./connect_agent_gateway.sh presets
```

导出某个平台的专用映射模板：

```powershell
.\connect_agent_gateway.cmd template --preset coze --output .\tools\agent_gateway\templates\coze-template.json
.\connect_agent_gateway.cmd template --write-all
```

```bash
sh ./connect_agent_gateway.sh template --preset dify_like --output ./tools/agent_gateway/templates/dify_like-template.json
sh ./connect_agent_gateway.sh template --write-all
```

如果你已经生成过配置，也可以直接运行网关：

```powershell
.\connect_agent_gateway.cmd run --config .\tools\agent_gateway\generated\openclaw-prod.json
```

```bash
sh ./connect_agent_gateway.sh run --config ./tools/agent_gateway/generated/openclaw-prod.json
```

## OpenClaw 快速接入

如果你接的是标准 OpenClaw 网关地址，可以直接使用新的快速命令，不再手工输入 Runtime 标识和大部分默认项：

### Windows

```powershell
.\connect_agent_gateway.cmd quick-openclaw `
  --platform-base-url http://127.0.0.1:8000 `
  --enrollment-token <一次性注册码> `
  --upstream-base-url http://192.168.137.140:18789 `
  --upstream-token <openclaw-token> `
  --listen-port 9010 `
  --access-host 192.168.1.20
```

### Linux / macOS

```bash
sh ./connect_agent_gateway.sh quick-openclaw \
  --platform-base-url http://127.0.0.1:8000 \
  --enrollment-token <一次性注册码> \
  --upstream-base-url http://192.168.137.140:18789 \
  --upstream-token <openclaw-token> \
  --listen-port 9010 \
  --access-host 192.168.1.20
```

这个命令会自动完成：

1. 生成接入名称、Runtime 显示名称、Runtime 类型
2. 将 OpenClaw Token 自动规范成 `Authorization: Bearer ...`
3. 预探测上游 `/health` 和根路径连通性
4. 发起 Runtime 注册
5. 审批后自动落地长期凭据
6. 生成本地配置和 `run-xxx.cmd` / `run-xxx.sh`

如果你只想先注册、不想阻塞等待审批，可以加：

```powershell
--skip-approval-wait
```

审批完成后再执行：

```powershell
.\connect_agent_gateway.cmd validate --config .\tools\agent_gateway\generated\<profile>.json
```

脚本会继续轮询并自动把 Runtime 凭据写回配置文件。

## OpenClaw 控制台桥接

如果你面对的是 OpenClaw 的 Control UI / WebChat 控制台，而不是一个标准的 HTTP 推理接口，可以使用独立的本地桥接脚本，把页面和 WebSocket 一起代理到远端 OpenClaw：

### Windows

```powershell
.\connect_openclaw_control.cmd `
  --upstream-http-url http://192.168.137.140:18789 `
  --gateway-token <openclaw-gateway-token> `
  --listen-port 19090 `
  --access-host 127.0.0.1 `
  --log-jsonl .\run_logs\openclaw-control-frames.jsonl
```

### Linux / macOS

```bash
sh ./connect_openclaw_control.sh \
  --upstream-http-url http://192.168.137.140:18789 \
  --gateway-token <openclaw-gateway-token> \
  --listen-port 19090 \
  --access-host 127.0.0.1 \
  --log-jsonl ./run_logs/openclaw-control-frames.jsonl
```

如果你希望它不只是本地桥接，而是直接接到当前保护平台的 Runtime 注册、审批、授权和事件回传链，请在同一条命令里补上平台参数：

### Windows

```powershell
.\connect_openclaw_control.cmd `
  --upstream-http-url http://192.168.137.140:18789 `
  --gateway-token <openclaw-gateway-token> `
  --platform-base-url http://127.0.0.1:8000 `
  --enrollment-token <一次性注册码> `
  --runtime-display-name openclaw-control-192.168.137.140:18789 `
  --target-agent-name OpenClaw-控制台-192.168.137.140 `
  --review-action block `
  --listen-port 19090 `
  --access-host 127.0.0.1 `
  --log-jsonl .\run_logs\openclaw-control-frames.jsonl
```

### Linux / macOS

```bash
sh ./connect_openclaw_control.sh \
  --upstream-http-url http://192.168.137.140:18789 \
  --gateway-token <openclaw-gateway-token> \
  --platform-base-url http://127.0.0.1:8000 \
  --enrollment-token <一次性注册码> \
  --runtime-display-name openclaw-control-192.168.137.140:18789 \
  --target-agent-name OpenClaw-控制台-192.168.137.140 \
  --review-action block \
  --listen-port 19090 \
  --access-host 127.0.0.1 \
  --log-jsonl ./run_logs/openclaw-control-frames.jsonl
```

这套新参数会额外完成：

1. 自动生成或复用本地 Runtime 配置文件
2. 自动发起 Runtime 注册并等待审批
3. 对非只读的 OpenClaw WS 方法执行“建任务 -> 授权 -> 心跳 -> 完成回传”
4. 把阻断、可疑和放行结果回传到平台任务、事件和报告链路
5. 在审批尚未完成时保留本地桥接能力，不会把浏览器入口打断

启动后，脚本会打印一个本地浏览器地址，形如：

```text
http://127.0.0.1:19090/?gatewayUrl=ws://127.0.0.1:19090&token=<gateway-token>
```

请直接打开这个本地地址，而不要再直连远端 `192.168.137.140:18789`。这样：

1. 页面和静态资源会从本地桥接器反向代理到远端 OpenClaw
2. Control UI 的 WebSocket 也会先经过本地桥接器
3. 你可以在本地看到 WS 方法日志，后续再把策略判定接到这层

如果你已经知道某些高风险 WS 方法名，也可以临时阻断：

```powershell
.\connect_openclaw_control.cmd `
  --upstream-http-url http://192.168.137.140:18789 `
  --gateway-token <openclaw-gateway-token> `
  --block-methods config.set,chat.send
```

如果管理员尚未审批，你也不需要重跑整套向导。已有配置可以直接续跑：

```powershell
.\connect_agent_gateway.cmd validate --config .\tools\agent_gateway\generated\openclaw-prod.json
```

```bash
sh ./connect_agent_gateway.sh validate --config ./tools/agent_gateway/generated/openclaw-prod.json
```

`validate` 和 `run` 都会自动继续轮询审批，并在批准后把长期 Runtime 凭据写回配置文件。

## 当前内置平台预设

目前脚本已经内置以下接入预设，优先减少手工字段映射：

- `OpenClaw / 通用 HTTP Agent`
- `OpenAI 兼容聊天接口`
- `Azure OpenAI / Azure AI Foundry`
- `OpenWebUI`
- `Dify / Chatflow / Workflow`
- `Coze / 扣子 API`
- `FastGPT`
- `Langflow`
- `RAGFlow`
- `AnythingLLM`
- `n8n / Webhook Agent`
- `自定义字段映射`

这些预设主要帮你预填：

- 用户输入字段路径
- 多轮消息字段路径
- skills / tools 字段路径
- plugins 字段路径
- 路径访问字段路径
- 高风险 scope 字段路径

如果平台请求体结构和预设不完全一致，再进入“高级字段映射”微调即可。

### 常见鉴权头提示

- `OpenAI 兼容聊天接口`：通常使用 `Authorization`
- `Azure OpenAI / Azure AI Foundry`：通常使用 `api-key`
- `Dify / Coze / FastGPT / AnythingLLM`：很多场景使用 `Authorization`

注意：

- 这里填的是“Header 名称”和“Header 值”
- 如果上游要求 `Bearer xxx`，请把完整值填进 Header 值里

## OpenClaw 接入示例

如果你的 OpenClaw 运行在：

```text
http://100.100.100.25:4567
```

建议按下面方式接：

1. 运行 `connect_agent_gateway.cmd` 或 `connect_agent_gateway.sh`
2. 接入类型选：
   - `OpenClaw / 通用 HTTP Agent`
3. 保护平台地址填：
   - `http://127.0.0.1:8000`
4. 注册码填：
   - 由保护平台控制台提前生成的一次性 `Enrollment Token`
5. 上游 Agent 地址填：
   - `http://100.100.100.25:4567`
6. 本地监听地址填：
   - `0.0.0.0`
7. 本地监听端口填：
   - `9010`
8. 业务侧访问网关地址填：
   - 例如 `192.168.1.20`
9. 如果 OpenClaw 需要鉴权头，再填上游 Header 名和值
10. 如果 OpenClaw 请求体字段比较特殊，打开“高级字段映射”补充字段路径
11. 等待管理员审批，脚本会自动轮询并落地 Runtime 凭据

完成后，调用侧不要再直接访问 `100.100.100.25:4567`，而是改成访问：

```text
http://你的网关机器IP:9010
```

这样网关就会先向平台发起：

- 创建任务
- 前置授权
- 运行态回传

## 高级字段映射怎么理解

很多 Agent 的请求体字段名不一样，所以脚本支持手工映射：

- 用户输入字段路径：例如 `query`、`prompt`、`inputs.query`
- 多轮消息字段路径：例如 `messages`、`history`、`conversation.messages`
- skill 列表字段路径：例如 `skills`、`tool_names`
- plugin 列表字段路径：例如 `plugins`
- 路径字段路径：例如 `paths`、`target_path`
- 高风险 scope 字段路径：例如 `requested_scopes`

路径支持简单点号形式，例如：

```text
inputs.query
conversation.messages
messages.0.content
```

## 生成文件在哪里

脚本会在下面目录生成本地配置和启动脚本：

```text
tools/agent_gateway/generated/
```

默认会生成：

- `xxx.json`
- `run-xxx.cmd`
- `run-xxx.sh`

说明：

- 这里的配置文件会包含 Runtime Key / Secret、上游密钥，以及待审批时的注册轮询信息
- 新版向导默认不再要求平台账号密码
- `quick-openclaw` 会自动生成 Runtime 标识和接入名称，你也可以通过命令行参数覆盖
- 这个目录已经加入 `.gitignore`
- 不要把生成文件发到代码仓库或聊天窗口

## 已知限制

当前脚本优先解决“可接入、可验证、可回传”，不是完整生产网关，因此有边界：

- 当前已经支持 SSE 类型流式透传，包括 `stream=true` 和 `response_mode=streaming`
- 当前不支持 WebSocket 代理
- 当前更适合 HTTP JSON Agent，不适合非常重的双向长连接协议
- 如果上游请求体结构非常特殊，需要你手动补字段映射

## 推荐验证方法

接好后，按这个顺序验证：

1. 打开本地网关健康检查：
   - `http://127.0.0.1:9010/health`
2. 用一条普通请求打网关
3. 看平台里是否出现新的任务
4. 看安全事件里是否有对应记录
5. 再用一条明显的攻击样本打网关，确认是否会被拦截或标记可疑
