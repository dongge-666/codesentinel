# P3 完成报告：AgentTeams 网关切换与四角色冒烟

## 最终结论

- 状态：`已完成`
- 完成日期：2026-07-30
- 验收结论：`通过`
- 阶段边界：只验证 AgentTeams、CoPaw、Higress AI Gateway 与
  DeepSeek 的运行链路；未实现 CodeSentinel 业务逻辑，也未声称已经
  完成 Manager 向三个 Worker 的真实审查协作。

P3 已证明一套 DeepSeek API Key 可以由网关统一托管，并供一个
Manager 和三个 Worker 以独立网关消费者身份调用
`deepseek-v4-pro`。四个运行时均完成真实模型请求，两路并发通过，
真实上游 Key 未进入 Manager 或 Worker。

## 配置结果

为避免破坏原有 Ollama 回退链路，本阶段没有修改默认 Provider 或
默认 Route，而是新增了专用资源：

| 配置项 | 结果 |
|---|---|
| Provider | `codesentinel-deepseek` |
| Provider 协议 | `openai/v1` |
| 上游地址 | `https://api.deepseek.com/v1` |
| 专用 Route | `codesentinel-deepseek-v4-pro` |
| 模型匹配 | `EQUAL deepseek-v4-pro` |
| 允许消费者 | Manager + 3 Worker，共 4 个 |
| 鉴权 | 开启 |
| Fallback | 关闭 |
| 默认 `openai-compat` Provider | 保留且未修改 |
| 默认 `default-ai-route` | 保留且未修改 |

专用路由创建后完成了一次真实网关探测：

- HTTP：`200`
- 返回模型：`deepseek-v4-pro`
- 内容标记：匹配
- 耗时：约 `1.141 s`

## AgentTeams 与运行时状态

控制面状态和 CoPaw 有效模型 API 均已核验，不能仅凭资源对象中的
模型字段判定成功。

| 资源 | AgentTeams 状态 | Runtime | CoPaw 有效模型 |
|---|---|---|---|
| `manager/default` | Running | CoPaw | `deepseek-v4-pro` |
| `worker/cs-diff-analyzer` | Running | CoPaw | `deepseek-v4-pro` |
| `worker/cs-security-scanner` | Running | CoPaw | `deepseek-v4-pro` |
| `worker/cs-quality-reviewer` | Running | CoPaw | `deepseek-v4-pro` |

三个 Worker 在控制面模型更新后，运行时仍短暂保留旧模型。完成必要
重启并再次查询 `/api/models/active?scope=effective` 后，三个
Worker 才全部实际加载新模型。这个差异已经纳入后续验收规范。

## 四角色真实调用

调用路径为：

`CoPaw 角色进程 -> 独立网关消费者凭证 -> Higress AI Gateway -> DeepSeek`

| 运行时角色 | HTTP | 内容校验 | 错误事件 | 耗时 |
|---|---:|---|---|---:|
| Manager（Gate Arbiter 运行槽位） | 200 | 通过 | 无 | 3.714 s |
| Diff Analyzer | 200 | 通过 | 无 | 3.137 s |
| Security Scanner | 200 | 通过 | 无 | 2.555 s |
| Quality Reviewer | 200 | 通过 | 无 | 2.397 s |

Security Scanner 与 Quality Reviewer 同时启动：

- 并发数：`2`
- 总墙钟时间：`3.082 s`
- 两个进程退出码：均为 `0`

因此，当前单 Key 配置没有阻塞 P3 所需的最小两路并发。该结果只
证明最小并发可用，不等于已经完成高负载、速率限制或成本压力测试。

## 可见轨迹

四次调用分别生成并持久化了一条 CoPaw Console 会话：

| 角色 | Session ID | 最终状态 |
|---|---|---|
| Manager | `codesentinel-p3-manager-1785418700` | idle |
| Diff Analyzer | `codesentinel-p3-diff-analyzer-1785418731` | idle |
| Security Scanner | `codesentinel-p3-security-scanner-1785418756` | idle |
| Quality Reviewer | `codesentinel-p3-quality-reviewer-1785418756` | idle |

Element/Matrix 本地入口已在浏览器中验证可访问。上述四条是各运行时
的 CoPaw Console 冒烟轨迹，不应描述成 Manager 已经通过 Matrix
派发并汇总三个 Worker；后者仍属于 P10。

## 本地入口与动态端口

最终健康检查中，Controller、Manager 和三个 Worker 容器均处于
Running。绕过宿主系统代理后，本地入口结果如下：

| 入口 | 本次端口快照 | HTTP |
|---|---:|---:|
| Higress Console | 18001 | 200 |
| Element/Matrix | 18088 | 200 |
| Manager CoPaw | 18888 | 200 |
| Diff Worker CoPaw | 10652 | 200 |
| Security Worker CoPaw | 15050 | 200 |
| Quality Worker CoPaw | 12229 | 200 |

Worker 使用动态宿主端口。模型协调期间容器重建后，端口已不同于
P3 开始时的快照。后续脚本必须通过 `docker port <container>`
发现当前端口，不得硬编码本表中的端口。

宿主设置了 HTTP 代理时，直接请求 localhost 曾返回代理侧 `502`；
使用 `curl --noproxy 127.0.0.1` 后得到真实的本地健康状态。

## 密钥隔离审计

真实 DeepSeek Key 的允许边界是：

1. Git 忽略的本地 `.env`；
2. Controller/Higress 专用 Provider 的受控存储。

审计结果：

| 检查 | 结果 |
|---|---:|
| `.env` 被 Git 忽略 | 是 |
| 扫描的项目文本文件 | 21 |
| 项目文件真实 Key 命中 | 0 |
| 扫描的角色容器 | 4 |
| 扫描的角色运行配置 | 8 |
| Manager/Worker 环境、配置、日志命中 | 0 |

Manager 与 Worker 只持有各自的网关消费者凭证，不持有真实
DeepSeek Key。控制台审计只输出 Provider/Route 的名称、字段名和
Token 数量，不输出 Token 内容。

## Dify 与回归结果

- Dify 运行容器数：`0`
- 13 个 Dify 容器仍为 Exited
- P3 未执行 `docker compose down`，未删除 Volume
- Pytest：`18 passed`
- Ruff：`passed`
- `pip check`：`No broken requirements found`

## 回退方案

若后续需要回退：

1. 通过 Controller CLI 将 Manager 和三个 Worker 的模型改回
   `qwen2.5:7b`；
2. 等待控制面状态更新，并重启必要的 Worker；
3. 必须以各 CoPaw 的有效模型 API 复核运行面，而非只看资源表；
4. 确认没有 DeepSeek 流量后，先删除专用 Route，再删除专用
   Provider；
5. 保留 Controller 数据 Volume、Manager 工作区和所有 Dify
   Volume，不执行重装。

默认 Ollama Provider/Route 在本阶段未被覆盖，因此具备明确回退
基础。

## 问题、处理与遗留风险

### 已解决

- PowerShell CRLF 使第一次传入 Key 带有传输换行：脚本增加内存内
  换行归一化，失败创建由陷阱自动回滚，第二次配置成功。
- Worker 控制面显示新模型但运行面仍是旧模型：执行必要重启，并以
  CoPaw 有效模型 API 重新验收。
- Docker 动态端口变化：改为从 `docker port` 获取实际映射。
- 系统代理干扰 localhost 健康检查：绕过代理后复核真实状态。
- 完整日志审计首次出现双流缓冲等待：改为并行读取 stdout/stderr
  后审计通过。

### 非阻塞遗留项

- Manager 当前仍是通用 AgentTeams Manager 身份；Gate Arbiter
  业务提示、任务模板和结构化裁决将在 P10 接入。
- 本阶段只做角色进程冒烟，没有 PR Diff、Artifact、Policy Engine
  或门禁三态；这些从 P4 开始实现。
- CoPaw 当前 `max_input_length` 仍为 `131072`。它足以完成 P3
  和早期 MVP，但在大 Diff 场景前应结合截断策略、分片策略和模型
  实际限制重新评审。
- Worker 宿主端口是动态值，不是稳定公开契约。
- 还没有速率限制、失败重试、成本上限和长时间稳定性数据。

## 客观评价

P3 达到了自身全部验收条件，结论为“顺利完成”。较有价值的地方
不只是 API 请求成功，而是同时验证了网关托管、四个独立消费者、
控制面与运行面一致性、两路并发、轨迹持久化、Key 隔离和回退
基础。

但 P3 仍然只是基础设施预检，不构成可提交的 CodeSentinel MVP，
也不能证明已满足比赛要求的真实多 Agent 协作。对“顺利进入初赛”
这一核心目标而言，P3 显著降低了后续集成风险，但项目价值需要在
P4～P13 的确定性门禁、证据链、真实协作和量化评测中建立。

下一阶段应为 P4“契约与确定性门禁内核”，等待参赛者明确批准后
再开始。

## 参考

- [AgentTeams v1.1.2 Release](https://github.com/agentscope-ai/AgentTeams/releases/tag/v1.1.2)
- [AgentTeams v1.1.2 Architecture](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/docs/architecture.md)
- [AgentTeams v1.1.2 Manager Guide](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/docs/manager-guide.md)
- [AgentTeams v1.1.2 Worker Guide](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/docs/worker-guide.md)
- [Higress AI Proxy](https://higress.cn/en/docs/latest/plugins/ai/api-provider/ai-proxy/)
