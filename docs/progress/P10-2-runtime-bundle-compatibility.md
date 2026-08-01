# P10-2 runtime-bundle compatibility slice

Date: 2026-08-01

Result: **PASS for P10-2**

P10 overall status: **in progress, not yet accepted**

## Scope completed

P10-2 implemented and verified only the compatibility boundary required by the
P10-1 contract:

- strict AgentTeams review-request, Worker-delivery, artifact-pointer, budget,
  and control-message models;
- canonical UTF-8 JSON and SHA-256 verification;
- duplicate-key, unsafe-path, deadline, correlation, assignment, and tampering
  rejection;
- deterministic, minimal `.pyz` runtime-bundle construction;
- zero-model execution in the existing Manager and Diff Worker CoPaw runtimes;
- real Manager-to-MinIO-to-Worker-to-MinIO-to-Manager artifact exchange;
- isolated Matrix custom-control-event round trip;
- exact temporary-runtime removal and P3/P9 baseline verification.

P10-2 did not register a real Agent task, invoke a semantic model, install a
Skill, dispatch all three Workers, or calculate a gate decision.

## Runtime bundle

The compatibility archive was:

- name: `codesentinel-agentteams-runtime-0.1.0.pyz`;
- size: `12107` bytes;
- SHA-256:
  `9a3c2c0a195c66302c5cfd46f9539017e9856f7b3ecf2f5a5a1bac2adac701af`;
- Python requirement: `>=3.11,<3.12`;
- Pydantic requirement: `>=2.13,<3`;
- P10 contract: `1.0.0`;
- source baseline: `3166d5c657460fcdf8490ff983764356afa9a78d`.

Two independent local builds produced byte-identical archives. The allow-list
contained only the AgentTeams compatibility modules, CodeSentinel package
metadata, entry point, manifest, and license. It contained no Provider,
security-scanner implementation, `.env`, credential, or model client.

The compatibility archive correctly reported `source_dirty=true` because P10-2
had not yet been committed. It is test evidence, not a deployable release.
P10-3 must rebuild from the accepted P10-2 commit and require
`source_dirty=false` before Skill deployment.

## Strict Fixture validation

The committed Fixture set contains:

- one canonical cloud-safe sanitized-diff artifact;
- one P10 review request with the frozen `4/8/1` budget;
- one zero-model Diff Worker delivery.

The following fail-closed checks were exercised:

- `cloud_safe=false`;
- domain-call budget changed from `4` to `5`;
- path traversal in an artifact reference;
- expired request deadline;
- input SHA-256 mismatch;
- non-canonical artifact JSON;
- duplicate JSON keys;
- Worker output SHA-256 mismatch;
- role/task assignment mismatch;
- data-plane fields in a Matrix control payload.

## Manager and Worker runtime evidence

The same archive loaded without installation in:

| Role | Python | Pydantic | Archive hash | Result |
|---|---|---|---|---|
| Gate Arbiter Manager | 3.11.15 | 2.13.4 | exact match | PASS |
| Diff Analyzer Worker | 3.11.15 | 2.13.4 | exact match | PASS |

Both roles validated the same request and delivery. Both independently
serialized the same control output with SHA-256
`438a164cfc24bd20d33d0c971102ac9f9cad9315f0e3a500c6fd1eb87f4df9b1`.

## MinIO data-plane evidence

The Manager uploaded the runtime bundle, manifest, request, canonical input,
Fixture delivery, and control evidence through the configured `hiclaw` MinIO
alias. The Diff Worker pulled them with its own storage identity, validated the
delivery, and uploaded a 283-byte structured result under its task workspace.
The Manager then pulled that result and verified:

- `ok=true`;
- operation `validate-delivery`;
- role `diff_analyzer`;
- correct review, trace, and task IDs;
- expected output SHA-256;
- `model_calls=0`.

The Worker result SHA-256 was
`267f14937048e7f0e014e5f743d564e4c22ce181117b1111854e84e1cecc85ef`.
MinIO evidence was retained; no shared evidence or volume was deleted.

## Matrix control-plane evidence

The Matrix payload was generated from an allow-listed control schema and was
`541` bytes. It contained identifiers, role, attempt, deadline, relative
artifact reference, and artifact SHA-256 only. It contained no patch, file
content, repository path, API key, access token, or secret.

To preserve the zero-model requirement, the Manager created a temporary
private room with zero invited Agents and sent a custom event of type
`com.codesentinel.compat.control.v1`, not an Agent chat message. Matrix returned
the same event content:

- event ID: `$Cc1plMIwKPDZ0MBPTrVKhZV3cNuPlQ6_usHwY_bGiXg`;
- body SHA-256:
  `420069592e9658e89b555d16e6aad4b77e83e0be12cf7e648c751b42e105dae7`;
- round-trip equality: `true`;
- invited Agents: `0`;
- model calls: `0`.

The Manager's token-usage file SHA-256 was identical before and after the
probe:
`dcce519e7a62e191b577b30ecc5c9bd9734b123cb24e2c1ae450668e1d7acd60`.

Tuwunel accepted `leave`, and a subsequent `/sync` confirmed the room was not
joined. Its optional `forget` request returned HTTP 400, so the evidence records
`room_forgotten=false`; no Agent remained in or was invited to the room. This is
a documented server-behavior limitation, not a model-call or active-room leak.

## Rollback and baseline evidence

- Manager and Diff Worker temporary runtime directories were removed by exact
  path.
- No package was installed into either CoPaw environment.
- No image, container configuration, gateway configuration, credential,
  restart policy, or volume was changed.
- All five AgentTeams containers remained `Up`.
- Manager and Diff Worker active-model endpoints remained HTTP 200 and reported
  `hiclaw-gateway` with `deepseek-v4-pro`.
- Dify running-container count remained `0`.
- P9 remained the executable fallback.

## Local verification

- P10-2 focused tests: `7 passed`;
- complete project suite: `226 passed`;
- Ruff: passed for the complete repository;
- `pip check`: no broken requirements;
- `git diff --check`: no whitespace errors;
- secret-pattern scan over the P10-2 source, Fixtures, and archive: zero matches.

## Acceptance assessment

| P10-2 entry gate | Result |
|---|---|
| Bundle loads in Manager and one Worker without installation | PASS |
| Fixture request and delivery pass strict schema/hash checks | PASS |
| Matrix carries control metadata and MinIO carries artifacts | PASS |
| Compatibility test makes no model call | PASS |
| Removing the temporary bundle restores the unchanged baseline | PASS |

P10-2 is complete. This result authorizes planning P10-3, but it does not prove
real Agent delegation, three-Worker collaboration, parallel execution, or the
competition's complete multi-agent requirement. P10-3 requires separate user
approval.
