# GitHub AI 攻击集整理目录

该目录根据 [AI攻击测试样本集.md](../../docs/testing/AI攻击测试样本集.md) 进行本地化整理，分为两层：

- `raw/`
  - 从 GitHub 下载的原始文件
- `curated/`
  - 统一后的 JSONL 样本索引
  - 章节化样本包
  - 策略配置索引
  - 来源清单与汇总统计

## 当前已整理来源

- `verazuo/jailbreak_llms`
  - `jailbreak_prompts_2023_12_25.csv`
  - `forbidden_question_set.csv`
- `cyberark/FuzzyAI`
  - `adv_prompts.txt`
  - `adv_suffixes.txt`
  - `pandoras_prompts.txt`
  - `harmful_behaviors.csv`
  - `persuasion_taxonomy.jsonl`
- `promptfoo/promptfoo`
  - `redteam-rag`
  - `redteam-coding-agent`
  - `redteam-bestOfN-strategy`
  - `redteam-xstest`
  - `redteam-indirect-web-pwn`
- `NVIDIA/garak`
  - `goodside.py`
  - `web_injection.py`
  - `leakreplay.py`
  - `promptinject.py`
- `preambleai/prompt-injector`
  - `benchmark-integration.ts`
  - `agent-framework-testing.ts`
  - `ai-red-teaming.ts`
  - `application-specific-testing.ts`
  - `all-attack-payloads.json`
  - `payload-manager.ts`
  - `prompt-injection-dataset.ts`
- `JailbreakBench/jailbreakbench`
  - `llama2.json`
  - `vicuna.json`
  - `dataset.py`

## 构建整理索引

```powershell
python .\datasets\github_attack_sets\build_catalog.py
```

校验整理结果：

```powershell
python .\datasets\github_attack_sets\validate_catalog.py
```

命令行检索样本：

```powershell
python .\datasets\github_attack_sets\query_catalog.py summary
python .\datasets\github_attack_sets\query_catalog.py list --section 05_indirect_prompt_injection.jsonl --limit 10
```

输出文件：

- `curated/github_attack_catalog.jsonl`
- `curated/section_index.json`
- `curated/by_section/*.jsonl`
- `curated/focused_packs/*.jsonl`
- `curated/focused_pack_index.json`
- `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_single_turn.jsonl`
- `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_multi_turn.jsonl`
- `curated/promptfoo_strategy_index.json`
- `curated/source_manifest.json`
- `curated/catalog_summary.json`

## 当前状态

基于当前本地原始文件，已经整理出 `4692` 条可直接用于联调的条目。

已补齐的重点章节：

- `04_protected_paths_skills_plugins.jsonl`
  - `41` 条
  - 其中 `25` 条已经单独收敛到 `curated/focused_packs/04_mcp_plugin_chain_cross_plugin.jsonl`
  - 又进一步拆成：
    - `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_single_turn.jsonl`：`11` 条
    - `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_multi_turn.jsonl`：`14` 条
  - 主要来自 `prompt-injector` 的 `function-calling` / `cross-plugin` / `mcp-injection` / `mcp-tool-chain` / `plugin-abuse` / `mcp-protocol`
  - 在原始 GitHub payload 之外，额外补了本地可跑的细化场景：`schema-smuggling` / `alias-bypass` / `role-borrowing` / `summary-laundering` / `auth-hop` / `server-message-smuggling` / `shadow-approval` / `capability-spoof` / `session-rebind`
  - 同时补入 `promptfoo` 的 coding-agent 保护资源场景和 RAG `rbac` 访问控制样本
- `05_indirect_prompt_injection.jsonl`
  - `19` 条
  - 主要来自 `NVIDIA/garak` 的 `goodside` / `web_injection`，以及 `prompt-injector` 的 `indirect-injection`
- `06_multi_turn_context_pollution.jsonl`
  - `11` 条
  - 主要来自 `prompt-injector` 的 `memory-injection`、`chain-poisoning`、`workflow-hijacking`、`multi-stage`
- `07_output_leakage_and_redaction.jsonl`
  - `25` 条
  - 主要来自 `NVIDIA/garak` 的 `web_injection` / `leakreplay` / `goodside`，以及 `prompt-injector` 的模型提取、训练数据泄露、数据外传测试

需要注意的来源特性：

- `JailbreakBench/jailbreakbench`
  - 当前本地只作为“模型特定噪声变体池”使用
  - 已筛出一小批 obfuscated prompt 变体补到总目录中
  - 不把它当成 `04/05/06/07` 四章的主样本源

## 统一字段

`github_attack_catalog.jsonl` 中已经补充了适合自动化联调的统一字段：

- `source_repo`
- `source_file`
- `source_family`
- `attack_family`
- `mapped_section`
- `risk_level`
- `attack_stage`
- `expected_behavior`

## 建议用途

- 把 `github_attack_catalog.jsonl` 作为自动化红队输入源
- 把 `curated/by_section/*.jsonl` 作为与 `AI攻击测试样本集.md` 一一对应的章节化样本包
- 把 `curated/focused_packs/04_mcp_plugin_chain_cross_plugin.jsonl` 作为 MCP / plugin-chain / cross-plugin 的专项回归包
- 把 `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_single_turn.jsonl` 接到无状态、每条请求独立的联调 runner
- 把 `curated/focused_packs/04_mcp_plugin_chain_cross_plugin_multi_turn.jsonl` 接到有状态、同一会话保留上下文的 agent runner
- 把 `section_index.json` 作为章节维度的统计和筛选入口
- 把 `focused_pack_index.json` 作为专项包入口
- 把 `promptfoo_strategy_index.json` 作为攻击策略参考清单
- 对照 `AI攻击测试样本集.md` 继续做本地样本扩展和人工归类
