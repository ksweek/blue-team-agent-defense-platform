# minimal_openclaw_connect

This folder is a minimal OpenClaw client connector package. Copy this whole folder to the machine that runs OpenClaw, then use the CMD scripts inside this folder. You do not need to type the long Python command during a demo.

## Files

- `start_openclaw_protection.cmd`: recommended demo entrypoint.
- `connect_openclaw_to_platform.cmd`: same connector with prompts and advanced argument passthrough.
- `install_dependencies.cmd`: installs Python dependencies for the connector.
- `openclaw_connect_config.cmd.example`: optional prefilled demo config template.
- `tools/openclaw_control_connect.py`: activation-code client flow.
- `tools/openclaw_control_bridge.py`: local HTTP/WebSocket bridge that protects OpenClaw traffic.

## First Use

1. Make sure Python 3.10+ is installed on the OpenClaw client machine.
2. Run:

```cmd
install_dependencies.cmd
```

3. In the platform, create or select the protected OpenClaw target and generate an activation code for that target.
4. Run:

```cmd
start_openclaw_protection.cmd
```

5. Enter:

- Platform base URL, for example `http://127.0.0.1:8000`
- OpenClaw URL, for example `http://192.168.137.140:18789`
- OpenClaw gateway token
- Platform activation code
- Local bridge host/port, default `0.0.0.0:19090`
- Browser access host, default `127.0.0.1`

After startup, open the local bridge URL printed by the script, usually:

```text
http://127.0.0.1:19090
```

Do not open the raw OpenClaw URL directly during protection testing. The browser must go through the local bridge.

## Demo Prefill

For a smoother demo, copy:

```cmd
copy openclaw_connect_config.cmd.example openclaw_connect_config.cmd
```

Edit `openclaw_connect_config.cmd`, then run:

```cmd
start_openclaw_protection.cmd
```

The script loads `openclaw_connect_config.cmd` automatically.

## Reuse

The activation code is required only the first time. After the connector exchanges it for long-term runtime credentials, later runs can reuse the saved local config under:

```text
tools\agent_gateway\generated\
```

To force a fresh activation, run:

```cmd
start_openclaw_protection.cmd --new
```

## Expected Block Message

When a protected rule blocks an OpenClaw action, OpenClaw should receive:

```text
触发防护规则已拦截
```

That confirms the request reached the platform protection path instead of bypassing it.
