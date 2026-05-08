# Agent 接入保护脚本说明

这套脚本的目标不是“把一个地址填进平台就自动受保护”，而是帮你快速生成一个统一前置网关，让外部请求先经过防护平台，再决定是否转发到真实 Agent 或模型接口。

公开发布版只保留统一入口脚本：

- `connect_agent_gateway.cmd`
- `connect_agent_gateway.sh`

不再附带其他专用包装脚本。

## 适用场景

- 自研 HTTP JSON Agent
- OpenAI 兼容聊天接口
- Dify / Chatflow / Workflow 类 HTTP API
- Coze、FastGPT、OpenWebUI、Langflow、RAGFlow 等兼容 HTTP 接入
- 其他需要“前置授权 + 审计回传”的 Agent 服务

## 这套脚本会做什么

脚本通过中文交互帮助你完成以下步骤：

1. 采集保护平台地址与一次性注册码 `Enrollment Token`
2. 采集 Runtime 显示名称和类型
3. 采集上游 Agent 地址，例如 `http://AGENT_HOST:4567`
4. 采集本地监听地址，以及业务侧最终访问的网关地址
5. 根据接入类型生成字段映射
6. 自动发起 Runtime 注册
7. 自动轮询管理员审批结果
8. 将 `runtime_key` / `runtime_secret` 落地到本地配置
9. 生成 Windows / Linux 的启动脚本
10. 可直接启动一个前置网关

运行链路如下：

```text
调用方 -> 前置防护网关 -> 保护平台建任务
                    -> 保护平台前置授权
                    -> 放行时转发到真实 Agent
                    -> 将真实结果回传平台
```

## 使用方式

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

## 常用命令

查看当前支持的接入预设：

```powershell
.\connect_agent_gateway.cmd presets
```

```bash
sh ./connect_agent_gateway.sh presets
```

导出平台模板：

```powershell
.\connect_agent_gateway.cmd template --preset coze --output .\tools\agent_gateway\templates\coze-template.json
.\connect_agent_gateway.cmd template --write-all
```

```bash
sh ./connect_agent_gateway.sh template --preset dify_like --output ./tools/agent_gateway/templates/dify_like-template.json
sh ./connect_agent_gateway.sh template --write-all
```

校验已有配置：

```powershell
.\connect_agent_gateway.cmd validate --config .\tools\agent_gateway\generated\<profile>.json
```

```bash
sh ./connect_agent_gateway.sh validate --config ./tools/agent_gateway/generated/<profile>.json
```

直接启动已有网关：

```powershell
.\connect_agent_gateway.cmd run --config .\tools\agent_gateway\generated\<profile>.json
```

```bash
sh ./connect_agent_gateway.sh run --config ./tools/agent_gateway/generated/<profile>.json
```

## 当前内置预设

目前脚本已经内置以下接入预设，用于减少手工字段映射：

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

## 高级字段映射

很多 Agent 的请求体字段名不一样，因此脚本支持手工映射：

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

## 生成文件位置

脚本会在下面目录生成本地配置和启动脚本：

```text
tools/agent_gateway/generated/
```

默认会生成：

- `xxx.json`
- `run-xxx.cmd`
- `run-xxx.sh`

说明：

- 配置文件会包含 Runtime Key / Secret、上游密钥以及待审批时的注册轮询信息。
- 新版向导默认不再要求平台账号密码。
- 这个目录已经加入 `.gitignore`。
- 不要把生成文件提交到仓库或公开发送。

## 已知限制

当前脚本优先解决“可接入、可验证、可回传”，不是完整生产网关，因此仍有边界：

- 已支持 SSE 类型流式透传，包括 `stream=true` 和 `response_mode=streaming`
- 当前不支持 WebSocket 代理接入
- 更适合 HTTP JSON Agent，不适合非常重的双向长连接协议
- 如果上游请求体结构非常特殊，需要手工补字段映射

## 推荐验证方法

接好后，按这个顺序验证：

1. 打开本地网关健康检查：
   - `http://127.0.0.1:9010/health`
2. 用一条普通请求打网关
3. 看平台里是否出现新的任务
4. 看安全事件里是否有对应记录
5. 再用一条高风险样本请求打网关，确认是否会被拦截或标记可疑
