# R2-4 policy canonicalization amendment

Date: 2026-08-02

Result: **PASS offline; R2-4 retry may proceed under the approved bounded Loop**

The first R2-4 attempt proved that MinIO accepts the reviewed policy and then
reorders string arrays before policy readback. The original gate had only the
reviewed source hash, so it correctly stopped before attachment rather than
silently changing its acceptance rule.

This amendment adds two explicit, independently testable contracts:

| Contract | SHA-256 | Meaning |
|---|---|---|
| Reviewed source exact | `a4ba569aea81bb06c1ea38c58d1cde6c25467513bf86a250ea27153ccbf6362f` | Object keys sorted; all reviewed array order preserved |
| MinIO readback semantic | `02e7b1ccae93d69563f9a01b45bfd5929aa35fbcf3ac59b67ecec6abe695f148` | Object keys sorted; Statement order preserved; only string-only arrays sorted |

Server readback must satisfy both the semantic hash and complete normalized
object equality with the frozen source. Hash equality alone is not accepted.

The normalization cannot hide:

- new, removed, or duplicate actions;
- broader or additional resources;
- changed or removed conditions;
- extra or missing prefixes;
- reordered, added, or removed Statement objects;
- extra fields such as an unreviewed `Sid`.

Implementation lives in `codesentinel.agentteams.deploy_guard` and is reused by
the controlled live transaction. Focused verification passed:

- `45` R2 deployment-guard tests;
- explicit source/readback hash tests;
- MinIO reorder acceptance test;
- mutations for extra action, broader resource, removed condition, Statement
  reorder, duplicate action, and extra field;
- non-JSON rejection;
- Ruff on the changed module and tests.

This change does not grant a permission, create a policy, touch Docker state,
call a model, or relax the approved Diff-only policy. R2-4 retry remains bound
to the existing subject fingerprint, exact object prefix, positive/negative
capability matrix, 20-minute Heartbeat window, zero-call invariant, and exact
rollback targets.
