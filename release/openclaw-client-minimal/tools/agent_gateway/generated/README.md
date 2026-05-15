# Generated Client Runtime Configs

这个目录保留给 OpenClaw 最小客户端在首次接入后写入本地配置使用。

公开发布包默认保持为空，不包含：

- 激活后下发的 Runtime 长期凭据
- 本地绑定成功后的运行配置
- 任意用户机器上的真实接入信息

首次运行 `connect_openclaw_control.cmd` 或 `connect_openclaw_control.sh` 后，
客户端会在这里生成并复用自己的本地配置文件。
