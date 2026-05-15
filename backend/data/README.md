# Runtime Data Layout

`backend/data/` 用于本地运行时产生的数据与示例资源。

公开仓库中默认只保留以下内容：

- `demo_skills/`
  - 用于 Skill 扫描、信任管理和演示联调的最小样例技能
- 空目录占位
  - `backups/`
  - `reports/`
  - `system_actions/`

以下内容不应进入版本库：

- 本地 SQLite 数据库
- 运行中生成的备份文件
- 报告导出物
- 系统动作快照
- 任意包含敏感请求、响应、凭据或会话内容的运行产物

首次运行时，平台会按需在这些目录下生成对应文件。
