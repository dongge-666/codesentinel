# P10-3A Worker Skills offline implementation

Date: 2026-08-01

Result: **PASS after strict remediation and independent offline re-audit**

P10-3 overall status: **in progress; deployment not started**

Source baseline: `993360734c38ad651f749bbca54cefe441288be1`

This report records offline implementation evidence only. It does not claim
that a Skill has been pushed, a finite task has been registered, a Worker model
has been called, or Manager orchestration has been completed.

## Scope completed

P10-3A implemented:

- one dependency-light source of truth for the P7/P10 Diff, Security, and
  Quality model payload contracts;
- immutable Worker assignment and role-isolated, cloud-safe context contracts;
- assignment/request/context correlation, digest, role, attempt, deadline, and
  exact input-lineage validation;
- strict role-selected parsing that rejects another role's payload;
- deterministic Worker evidence generation restricted to E1/LLM lineage;
- evidence-to-output binding over claim, line references, confidence, role,
  and input-artifact digest;
- deterministic output and delivery SHA-256 calculation;
- exactly-once atomic creation of authoritative `delivery.json`;
- a zero-model `build-delivery` operation in the minimal runtime archive;
- three role-isolated, versioned Worker Skill source packages;
- clean-commit deployment-binding templates and fixed package-local runtime
  verifiers for P10-3B;
- positive, tampering, role-confusion, evidence-overclaim, partial-write,
  package-isolation, and isolated-archive tests.

## Role packages

| Skill | Intended Worker | Role payload |
|---|---|---|
| `codesentinel-diff-review` | `cs-diff-analyzer` | `DiffSemanticPayload@1.0.0` |
| `codesentinel-security-review` | `cs-security-scanner` | `SecurityReviewPayload@1.0.0` |
| `codesentinel-quality-review` | `cs-quality-reviewer` | `QualityReviewPayload@1.0.0` |

Each package contains exactly `SKILL.md`, a source manifest, a deployment
binding template, two contract references, a valid example, one identical
shell wrapper, and one identical package-local runtime-binding verifier. No
package contains a bound runtime hash, API key, Provider, model client,
repository mount, or absolute host path.

The source templates are deliberately not deployable as-is. P10-3B must
materialize `deployment-manifest.json` from the accepted P10-3A commit and the
clean runtime bundle. A placeholder in a deployed package is a hard failure.

## Delivery integrity

The Worker model authors only `role-payload.json`. It cannot author correlation
IDs, role, attempt, input pointers, evidence level/source, evidence ID, output
hash, or gate status. The runtime derives those fields from the validated
request, immutable assignment, and hashed role context.

For a semantic delivery, the runtime requires:

- the payload type to match the assigned Worker role;
- model evidence to remain `E1` with source `llm`;
- every evidence input pointer to be declared by the delivery;
- evidence content hashes to bind summary, line references, confidence, role,
  and input lineage;
- evidence IDs to derive from their content hashes;
- semantic evidence to match the role output item by item;
- `output_sha256` to match canonical role output;
- the exact assignment attempt and completion no later than its deadline;
- all cited line references to derive from and belong to the assigned context;
- the destination to equal the assignment's delivery reference under the
  trusted artifact root, including rejection of a same-suffix cross-root path;
- the destination not to exist and its parent to be a real directory;
- temporary output to be removed if atomic replacement fails.

The P10-2 zero-model compatibility fixture remains valid with zero evidence;
live semantic deliveries with `model_usage.calls=1` require exact evidence.

## Strict self-audit and remediation

The first implementation was not accepted on test count alone. Adversarial
probes found that foreign input lineage, nonexistent line references, attempt
mismatch, post-deadline completion, arbitrary delivery destinations, relabeled
evidence IDs, caller-supplied runtime hashes, and failed deterministic security
coverage were insufficiently closed.

The remediation added a trusted assignment envelope, hashed role contexts,
stable line-reference derivation, exact two-input delivery lineage, deadline
and attempt enforcement, assignment-bound artifact-root writes, derived
evidence IDs, failed-coverage blocking, and a package-local deployment verifier.
Each original bypass now has an explicit fail-closed regression test. A second code-level review
also found that suffix-only destination checking still admitted an equivalent
path under another root; the writer now binds both the assignment reference and
the trusted artifact root, with a dedicated cross-root regression.

## Offline verification

| Check | Result |
|---|---|
| Existing and new Agent/P10 target tests | 44 passed |
| Named adversarial bypass replay | 8 passed; every invalid case rejected |
| Worker-delivery and Skill-package target tests | 18 passed |
| Full repository test suite | 244 passed |
| Ruff over `src` and `tests` | PASS |
| `pip check` in `agent_dev` | No broken requirements |
| Two independent runtime builds | Byte-identical |
| Isolated `.pyz` `build-delivery` | PASS; runtime model calls 0 |
| Three package-local verifier scripts | Compiled successfully |
| P10-3A changed-scope detect-secrets scan | 44 files; 2 digest-field candidates, 0 after deterministic `sha256`-line exclusion |
| `git diff --check` | PASS; Windows LF/CRLF notices are non-failing |
| Docker/Dify read-only check | Five AgentTeams containers running; no Dify container running |

The unfiltered changed-scope scan reported only `sha256` and `output_sha256` in
the deterministic Worker-delivery fixture. Their values were not printed.
Excluding lines explicitly named `sha256`, using the existing project scan
convention, returned zero records. This exclusion is not used for any other
field or file class.

## Preserved boundaries

- No AgentTeams container or Worker filesystem was changed.
- No Skill was copied to Manager, MinIO, or a Worker.
- No Matrix event or finite task was created.
- No DeepSeek or Manager/Worker model call was made.
- No gateway, API key, runtime, route, Dify state, or Docker topology changed.
- No Git commit or push was created.
- P9 remains the fallback.

## Remaining work and approval gate

The working tree is intentionally dirty during P10-3A, so temporary runtime
manifests correctly report `source_dirty=true`. This is acceptable offline but
forbids P10-3B deployment.

The next action is user review of this remediated slice. Only after separate
approval may P10-3A be committed and pushed. P10-3B then requires another
explicit approval and must rebuild from that clean commit, materialize exact
deployment manifests, execute the shell wrapper in the target Linux container,
and validate Diff, Security, and Quality sequentially within the frozen `4/8`
model-call limits.
