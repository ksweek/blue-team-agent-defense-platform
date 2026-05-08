# 贡献指南

本仓库是一个可运行的 AI/Agent 防护平台原型，贡献时优先保证可运行性、可验证性和文档同步，而不是单纯增加界面或演示内容。

## 提交前原则

- 先确认改动属于以下之一：
  - 缺口补齐
  - 缺陷修复
  - 仓库规范化
  - 文档与测试对齐
- 不要把本地运行产物提交进来：
  - `.env`
  - `run_logs/`
  - `backend/data/*.db`
  - `backend/data/reports/`
  - `backend/data/system_actions/`
- 不要把默认密码、真实 API Key、测试令牌、敏感日志放入代码或文档。

## 本地开发建议

1. 复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

2. 安装依赖并启动本地环境：

```powershell
.\start.ps1
```

3. 对于只验证仓库完整性，优先运行统一校验脚本：

```powershell
.\scripts\validate.ps1
```

Unix 环境：

```bash
sh ./scripts/validate.sh
```

## 代码与文档要求

- 后端改动需要同时考虑：
  - 路由
  - 服务层
  - 数据模型或持久化影响
  - README / docs 是否需要更新
- 前端改动需要同时考虑：
  - 构建是否通过
  - 页面中文文案是否准确
  - 是否引入了新的前端静态映射，能否改成后端元数据驱动
- 如果新增接口、环境变量或脚本，必须同步更新至少一个入口文档：
  - `README.md`
  - `backend/README.md`
  - `frontend/README.md`
  - `docs/README.md`

## Pull Request 建议内容

- 变更目标：为什么需要这次修改
- 影响范围：后端 / 前端 / 数据 / 文档 / 部署
- 验证结果：列出实际跑过的命令
- 风险说明：是否影响已有数据、默认配置或运行链路

## 最低验证要求

默认情况下，请至少完成：

```powershell
.\scripts\validate.ps1
```

如果只改某一侧：

```powershell
.\scripts\validate.ps1 -BackendOnly
.\scripts\validate.ps1 -FrontendOnly
```

## Issue 与设计变更

- 缺陷修复请提供最小复现路径。
- 功能增强请明确：
  - 使用场景
  - 接口变化
  - 是否需要迁移
  - 是否需要新增权限、审计或脱敏逻辑
- 对生产链路有影响的改动，不要只给 UI 方案，必须说明真实执行面如何落地。
