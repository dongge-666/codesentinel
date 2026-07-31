# P4 完成报告：契约与确定性门禁内核

## 最终结论

- 状态：`已完成`
- 完成日期：2026-07-30
- 验收结论：`通过`
- 阶段边界：只实现离线数据契约、证据资格、引用完整性、版本化
  Policy 和确定性 Gate 决策；未实现 Git Diff 读取、真实检测 Skill、
  LLM Agent、AgentTeams 业务协作、CLI 或报告持久化。

P4 已建立 CodeSentinel 的可信决策底座：Agent 负责提交结构化候选
事实，最终 `PASS / BLOCK / NEEDS_REVIEW / FAILED` 由不联网、不调用
模型的 Policy Engine 决定。该结果满足本阶段目标，但还不是可供
最终用户运行的完整 MVP。

## 交付物

| 交付物 | 位置 |
|---|---|
| 10 组冻结枚举 | `src/codesentinel/domain/enums.py` |
| 12 个公开 Pydantic Schema | `src/codesentinel/domain/models.py` |
| Policy 严格模型 | `src/codesentinel/policy/models.py` |
| 版本锁与 SHA-256 校验 | `src/codesentinel/policy/loader.py` |
| 引用、位置和 provenance 校验 | `src/codesentinel/policy/validation.py` |
| 纯内存确定性 Policy Engine | `src/codesentinel/policy/engine.py` |
| `mvp-1.0.0` 配置 | `src/codesentinel/policies/mvp-1.0.0.toml` |
| 契约测试 | `tests/domain/test_contracts.py` |
| 门禁与对抗性测试 | `tests/policy/test_policy_engine.py` |

12 个公开 Schema 为：

`ReviewRequest`、`CodeLocation`、`FileChange`、`DiffAnalysis`、
`RiskRoute`、`RiskMap`、`Evidence`、`Finding`、`CoverageRecord`、
`AgentArtifact`、`EvidenceConflict` 和 `GateDecision`。

## 契约边界

- 所有公开模型启用严格类型、`extra=forbid`、有限浮点和 UTC 校验。
- JSON 中的 array 在 Python 运行时统一为 tuple；嵌套模型也被冻结，
  避免通过 `.clear()` 或原地替换绕过已完成的 Schema 校验。
- 仓库内路径必须是无盘符、无反斜杠、无 `.`/`..`、无 ADS/空字符
  的相对 POSIX 路径。
- 12 个模型均支持 JSON 序列化/反序列化，生成的 JSON Schema 均
  禁止未声明字段。
- `GateDecision` 会校验状态与规则前缀、finding 分类集合互斥，以及
  classified finding 到 `evidence_index` 的引用闭包。
- `EvidenceConflict` 增加必填 `rule_ids`，从而可以机器表达和校验
  “1 个 finding + 1 条 Policy 规则”的冲突。

`ReviewRequest.repository_path` 在 P4 只校验“语法上为绝对路径”。
路径是否存在、是否为合法 Git 仓库属于 P5，未在本阶段越界实现。

## Policy 与证据信任边界

内置 Policy 采用四层防护：

1. 只允许版本 `mvp-1.0.0`；
2. 原始 TOML 必须匹配固定 SHA-256：
   `3d222b317b56a2d793776f3826c5f682d8b37902599246e57c8954cd25909852`；
3. Policy 的 B/N/P/F 规则语义、等级排序、E3 detector allowlist 和
   必需 Artifact 身份均经过精确校验，并使用深度不可变结构；
4. `PolicyEngine` 构造时再次完整反序列化校验，关闭 Pydantic
   `model_copy(update=...)` 的未校验绕过路径。

仅在 Artifact 中自报 `source=rule`、`level=E3`、`reproducible=true`
不会获得阻断资格。E3 还必须同时满足：

- ID 由内部 `verified_e3_evidence_ids` 注册；
- source、detector 和 version 位于当前 Policy allowlist；
- location 属于当前 Diff；
- Evidence 与 Finding 在同一 file/hunk/side 且行范围相交。

P4 只冻结这个信任接口。真正有权注册可信 E3 的本地确定性 Skill
runner 将在 P6 实现，证据校验与补证编排将在 P8 接入。

## 决策语义

优先级固定为：

1. 核心输入、Policy 或 Engine 不可用：`FAILED`；
2. 存在可信强阻断证据：`BLOCK`；
3. 没有强阻断，但覆盖、上下文、冲突或 Artifact 不完整：
   `NEEDS_REVIEW`；
4. 必需覆盖完整且没有 B/N 条件：`PASS`。

规则集合：

| 状态 | 规则 |
|---|---|
| PASS | P001 |
| BLOCK | B001 凭据、B002 命令/危险调用、B003 SQL 注入、B004 完整性异常叠加独立强信号 |
| NEEDS_REVIEW | N001～N008 |
| FAILED | F001 输入、F002 Policy、F003 Engine |

强阻断与非关键检查失败同时出现时，结果保持 `BLOCK`，并附带对应
N 规则和 `coverage_complete=false`。纯 LLM 证据最高 E1，多个 E2
不会被累加为 E3。

## 安全审计中关闭的问题

正常路径测试通过后，又使用对抗性输入复核并关闭了以下问题：

- 已通过摘要校验的 Policy 可被内存列表/字典修改；
- Schema 合法但语义被放宽的 Policy 可使 E1 错误 BLOCK；
- Agent 可自报 rule/static_tool E3；
- Finding 可引用另一位置的 E3 触发错误 BLOCK；
- `C:/...`、`C:relative` 和 Windows ADS 可伪装相对路径；
- unsupported、binary 或 unknown 文件范围可错误 PASS；
- completed Coverage 携带 `TIMEOUT` 可隐藏失败；
- 错 Agent、错 schema version 或多份必需 Artifact 可错误 PASS；
- 旧侧秘密叠加无关完整性错误可误触发 B004；
- duplicate Finding/Conflict 可把 N006 错误升级为 F003；
- 畸形 dataclass 时间/ID 可使 safe wrapper 再次抛异常；
- 已验证的公共 Schema 和 GateDecision 可通过可变 list 原地篡改。

这些修订均采用 fail-closed 原则：不能建立可信证明时不会发布 PASS。

## 验收证据

最终本地验收：

- Pytest：`144 passed`
- Ruff：`All checks passed`
- `pip check`：`No broken requirements found`
- 网络与模型调用：`0`
- 真实 API Key 使用：`0`
- 隔离 wheel 冒烟：构建成功，安装到临时 target 后确认从该 target
  导入，并成功加载 `mvp-1.0.0`、3 条 B 规则和 8 条 N 规则
- 临时 wheel/安装目录：验证后已删除，可由源码重新构建

验收项逐条结果：

| 计划验收项 | 结果 |
|---|---|
| 合法 Schema JSON round-trip | 通过 |
| 未声明字段拒绝 | 通过 |
| 纯 LLM E1 不能 BLOCK | 通过 |
| mandatory 非 completed 不能 PASS | 通过 |
| 相同输入/Policy 决策一致 | 连续 100 次一致 |
| 四种状态均有规则测试 | 通过 |
| 全阶段离线 | 通过 |

## 客观评价

P4 完成顺利，而且实际可靠性高于最初验收下限。核心价值不在于代码
量，而在于把“多 Agent 都能发表意见”和“谁有权决定门禁”明确
分离，并为后续创新主线“风险自适应路由 + 证据协议 + 确定性裁决”
建立了可测试的机器契约。这对初赛材料中的可信性、可解释性和消融
实验都有直接价值。

但目前仍不能证明 CodeSentinel 能审查真实 PR：还没有 Git 输入、
真实检测、DeepSeek 结构化 Agent、完整本地闭环和 AgentTeams 业务
轨迹。因此项目总体仍处于底座阶段，不能把 P4 描述成可提交 MVP。

## 下一阶段

下一阶段是 P5“Git Diff 输入与 Artifact 基础”。P5 只能在参赛者
明确批准后开始；本阶段不会自动继续。
