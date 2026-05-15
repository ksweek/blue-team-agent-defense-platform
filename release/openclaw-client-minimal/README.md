# OpenClaw Client Minimal

这是给远端 OpenClaw 机器准备的最小客户端目录，只保留接入保护平台所需的内容。

它只负责这几件事：
- 用短期激活码换一次长期 Runtime 凭据
- 启动本地 OpenClaw 安全桥接器
- 把聊天、工具调用、MCP 调用转发到平台做审查
- 支持远程 Skill 扫描

它不包含完整平台，不带前端、不带数据库、不带后端 API 服务，也不带任何本地生成过的凭据。

## 最小目录

```text
openclaw-client-minimal/
|-- connect_openclaw_control.cmd
|-- connect_openclaw_control.sh
|-- requirements-openclaw-client.txt
|-- backend/
|   `-- app/
|       |-- core/
|       |-- db/
|       |-- services/
|       |-- __init__.py
|       `-- models.py
`-- tools/
    |-- openclaw_control_connect.py
    |-- openclaw_control_bridge.py
    `-- agent_gateway/
        |-- agent_gateway_cli.py
        `-- generated/
```

## 每个文件是干什么的

- `connect_openclaw_control.cmd` / `connect_openclaw_control.sh`
  - 客户端启动入口
  - 优先复用当前虚拟环境里的 Python
- `tools/openclaw_control_connect.py`
  - 首次接入时输入平台地址、OpenClaw 地址、gateway token、激活码
  - 换取长期 Runtime 凭据并写到本地
- `tools/openclaw_control_bridge.py`
  - 本地桥接器
  - OpenClaw 的聊天、工具调用、MCP 交互都会先过这里
- `tools/agent_gateway/agent_gateway_cli.py`
  - Runtime 激活、凭据校验、平台通信共用逻辑
- `backend/app/services/skill_scan.py`
  - 远程 Skill 扫描逻辑入口

## 安装依赖

只需要安装精简依赖：

```powershell
pip install -r requirements-openclaw-client.txt
```

## 运行前需要准备

- 远端机器上的 OpenClaw 已经运行
- 你知道 OpenClaw 的 HTTP 控制台地址
  - 例如 `http://192.168.137.140:18789`
- 你知道 OpenClaw 的 `gateway.auth.token`
- 远端机器能访问你的平台后端
  - 例如 `http://192.168.137.1:8000`
- 平台里已经创建好了对应的 OpenClaw 目标
- 平台里已经给这个目标生成了短期激活码

## 首次接入

Windows:

```powershell
.\connect_openclaw_control.cmd
```

Linux / macOS:

```bash
sh ./connect_openclaw_control.sh
```

首次运行按提示输入：

- 平台地址
- OpenClaw 控制台地址
- OpenClaw gateway token
- 平台生成的短期激活码
- 本地桥接访问地址 `access_host`
- 本地桥接监听端口 `listen_port`

首次成功后，本地会生成长期 Runtime 配置，保存到：

```text
tools/agent_gateway/generated/
```

这个目录在发布包里默认是空的，属于正常现象。后续再次运行会直接复用这里的配置，不需要重新输入激活码。

## 正确访问方式

脚本启动后会输出一个桥接地址，形如：

```text
http://192.168.137.140:19090/?gatewayUrl=ws://192.168.137.140:19090&token=<gateway-token>
```

后续必须打开这个桥接地址，不能直接打开原始 OpenClaw 地址。只有这样，OpenClaw 的聊天、工具调用和 MCP 流量才会先进入平台审查。

## 这个目录故意没带什么

- `frontend/`
- 平台后端 API 服务
- 数据库
- 平台 `.env`
- 任意本地生成的 `generated/*.json` 凭据
- 测试脚本、测试报告、开发用文档

## 适用范围

如果你的目标只是把另一台机器上的 OpenClaw 接入当前平台，这个目录就够了。

如果你还要在远端机器上做本地开发、调试、跑完整测试，应该直接带完整仓库，不要用这个精简包。
