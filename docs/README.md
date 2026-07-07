# 文档总览

对外发布版文档按两个维度整理：

- `platform/`：平台定位、工程设计、接口设计、接入方案
- `testing/`：AI 联调、攻击样本、使用说明与评估方法

## 当前状态

截至 `2026-06-20`，平台文档已按当前代码同步到统一 Gateway、Runtime 注册/授权/心跳/完成回传、MCP Ticket、Redis 缓存、安全加固、样本批量任务、报告导出与 Docker Compose 部署路径。

后端测试当前收集 `57` 项，完整执行结果为 `56 passed, 1 failed, 4 warnings`；唯一失败来自本地 SQLite 在 100 并发写入下触发 `database is locked`。生产级并发验证请使用 PostgreSQL + Redis。

## 仓库协作

- [项目首页](../README.md)
- [贡献指南](../CONTRIBUTING.md)
- [安全策略](../SECURITY.md)
- [后端说明](../backend/README.md)
- [前端说明](../frontend/README.md)

## Platform

- [蓝队防御管理平台完整方案](./platform/蓝队防御管理平台完整方案.md)
- [蓝队防御平台工程设计](./platform/蓝队防御平台工程设计.md)
- [蓝队防御平台接口设计文档](./platform/蓝队防御平台接口设计文档.md)
- [统一代理入口实施方案](./platform/统一代理入口实施方案.md)
- [Agent 接入保护脚本说明](./platform/Agent接入保护脚本说明.md)

## Deployment

- [Docker One-Click Deployment](./deployment/docker-quick-start.md)

## Testing

- [AI 联调与可行性评估指南](./testing/AI联调与可行性评估指南.md)
- [AI 攻击测试样本集](./testing/AI攻击测试样本集.md)
- [攻击集使用说明](./testing/攻击集使用说明.md)
