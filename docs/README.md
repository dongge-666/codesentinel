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
- [R2-1 offline transactional deployment guard](progress/R2-1-offline-deployment-guard.md)
- [R2-2 live read-only infrastructure preflight](progress/R2-2-live-read-only-preflight.md)
- [R2-3 bounded Manager quiescence window](progress/R2-3-bounded-manager-quiescence.md)
- [R2-4 Diff policy probe attempt 1](progress/R2-4-diff-policy-probe-attempt-1.md)
- [R2-4 policy canonicalization amendment](progress/R2-4-policy-canonicalization-amendment.md)
- [R2-4 Diff policy probe attempt 2](progress/R2-4-diff-policy-probe-attempt-2.md)
- [R2-5 zero-model Diff deployment and rollback proof](progress/R2-5-diff-deployment-rollback.md)
- [R2-6 evidence closure](progress/R2-6-evidence-closure.md)
- [R2 machine-readable execution evidence](progress/R2-execution-evidence.json)

Frozen implementation contracts:

- [P10 AgentTeams integration contract](design/P10-agentteams-contract.md)

Reviewed execution plans:

- [P10-3 Worker Skills deployment and structured-delivery plan](design/P10-3-worker-skills-plan.md)
  (`CONDITIONAL GO`; P10-3A, Gate A, and Diff Canary complete; Security pending Gate C)
- [P10-3B controlled Worker deployment and rollback plan](design/P10-3B-controlled-deployment-plan.md)
  (`CONDITIONAL GO`; Gate B Diff PASS, stopped before Security)
- [R2 AgentTeams infrastructure remediation plan](design/R2-agentteams-infrastructure-remediation-plan.md)
  (`COMPLETE`; R2-6 enabled the accepted Gate B Diff canary)

P10 subphase records:

- [P10-1 contract and runtime-plan freeze](progress/P10-1-contract-runtime-freeze.md)
- [P10-2 runtime-bundle compatibility slice](progress/P10-2-runtime-bundle-compatibility.md)
- [P10-3A Worker Skills offline implementation](progress/P10-3A-worker-skills-offline.md)
- [P10-3B Gate A readiness evidence](progress/P10-3B-gate-a-readiness.md)
- [P10-3B Diff Worker canary attempt 1](progress/P10-3B-diff-canary-attempt-1.md)
  (`BLOCKED` before task dispatch; fail-closed rollback completed)
- [P10-3B Diff Worker canary completion](progress/P10-3B-diff-canary-pass.md)
  (`PASS` for Diff only; stopped before Security)
- [P10-3B Diff Worker machine-readable evidence](progress/P10-3B-diff-canary-evidence.json)
