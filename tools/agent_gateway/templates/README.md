# Agent Gateway Templates

这里存放常见平台的专用映射模板：

- `coze-template.json`
- `dify_like-template.json`
- `fastgpt-template.json`
- `openwebui-template.json`

这些文件不是最终生产配置，而是给你两类用途：

1. 直接查看某个平台常用的字段映射方式
2. 把其中的 `mapping` 段复制进你生成的网关配置里

如果要重新生成这些模板：

```powershell
python .\tools\agent_gateway\agent_gateway_cli.py template --write-all
```
