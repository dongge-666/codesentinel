# Project documentation

Public architecture, security, evaluation, and operating documentation will
be added incrementally as the corresponding implementation stages complete.

The competition planning documents currently remain in the parent workspace
so that the implementation repository starts with only reviewed public
content.

Completed phase reports:

- [P1 repository and security baseline](progress/P1-repository-security-baseline.md)
- [P2 DeepSeek API preflight](progress/P2-deepseek-api-preflight.md)
- [P3 AgentTeams DeepSeek smoke](progress/P3-agentteams-deepseek-smoke.md)
- [P4 contract and deterministic policy kernel](progress/P4-contract-policy-kernel.md)
- [P5 read-only Git Diff input and Artifact Store](progress/P5-git-diff-artifacts.md)
- [P6 deterministic security Skills](progress/P6-deterministic-security-skills.md)
- [P7 DeepSeek Provider and structured Agents](progress/P7-deepseek-structured-agents.md)
- [P8 risk routing, evidence assurance, and targeted recheck](progress/P8-risk-evidence-recheck.md)
- [P9 local reference runner and CLI](progress/P9-local-reference-runner-cli.md)
- [R1 security detection correctness remediation](progress/R1-security-correctness.md)

Frozen implementation contracts:

- [P10 AgentTeams integration contract](design/P10-agentteams-contract.md)

Reviewed execution plans:

- [P10-3 Worker Skills deployment and structured-delivery plan](design/P10-3-worker-skills-plan.md)
  (`CONDITIONAL GO`; P10-3A and Gate A complete, Diff Canary blocked before dispatch)
- [P10-3B controlled Worker deployment and rollback plan](design/P10-3B-controlled-deployment-plan.md)
  (`CONDITIONAL GO`; Gate B retry requires R2 remediation and new approval)
- [R2 AgentTeams infrastructure remediation plan](design/R2-agentteams-infrastructure-remediation-plan.md)
  (`CONDITIONAL GO`; documentation/offline work only, live mutation not approved)

P10 subphase records:

- [P10-1 contract and runtime-plan freeze](progress/P10-1-contract-runtime-freeze.md)
- [P10-2 runtime-bundle compatibility slice](progress/P10-2-runtime-bundle-compatibility.md)
- [P10-3A Worker Skills offline implementation](progress/P10-3A-worker-skills-offline.md)
- [P10-3B Gate A readiness evidence](progress/P10-3B-gate-a-readiness.md)
- [P10-3B Diff Worker canary attempt 1](progress/P10-3B-diff-canary-attempt-1.md)
  (`BLOCKED` before task dispatch; fail-closed rollback completed)
