# 贡献指南

本仓库是面向公开发布整理后的版本，贡献时优先保证可运行性、配置清晰度和文档同步。

## 提交前原则

- 改动应围绕以下方向之一：
  - 缺陷修复
  - 功能补齐
  - 仓库规范化
  - 文档与部署说明更新
- 不要提交本地运行产物：
  - `.env`
  - `backend/data/*.db`
  - `backend/data/reports/`
  - `backend/data/system_actions/`
  - `tools/agent_gateway/generated/*.json`
- 不要把默认密码、真实 API Key、长期 Runtime 凭据、敏感日志写入代码或文档。

## 本地开发建议

1. 复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

2. 启动本地环境：

```powershell
.\start.ps1
```

3. 如只需要接入向导，直接使用：

```powershell
.\connect_agent_gateway.cmd
```

## 代码与文档要求

- 后端改动需要同时检查路由、服务层、数据模型或持久化影响。
- 前端改动需要同时检查构建是否通过、页面文案是否准确、接口字段是否同步。
- 如果新增接口、环境变量或脚本，至少同步更新一个入口文档：
  - `README.md`
  - `backend/README.md`
  - `frontend/README.md`
  - `docs/README.md`

## Pull Request 建议内容

- 变更目标：为什么需要这次修改
- 影响范围：后端 / 前端 / 文档 / 部署
- 验证方式：说明实际启动、构建或联调步骤
- 风险说明：是否影响默认配置、数据结构或运行链路

## 变更约束

- 对外发布版中不要重新加入测试脚本、测试缓存、原始样本源或额外的包装脚本。
- 如果确实需要新增公开文档，请优先放在 `docs/platform/`。
