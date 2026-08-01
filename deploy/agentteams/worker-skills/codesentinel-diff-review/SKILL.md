---
name: codesentinel-diff-review
description: Produce strict change semantics for one cloud-safe CodeSentinel diff task.
assign_when: Assign only to cs-diff-analyzer for a registered CodeSentinel diff-analysis task.
---

# CodeSentinel Diff Review

Use this Skill only when the assignment role is `diff_analyzer` and the task
belongs to the current Worker room. Never make security, quality, or gate
decisions.

## Required workflow

1. Acknowledge the finite task with `taskflow(action="ack_task")` before work.
2. Read the pulled `spec.md`, `base/assignment.json`,
   `base/role-context.json`, request envelope, deployment manifest, and only
   the cloud-safe input artifacts listed by the assignment.
3. Verify the runtime archive against the exact SHA-256 in the deployment
   manifest. Stop on any mismatch, unsafe path, missing file, or identity
   mismatch.
4. Analyze only structural change intent and affected symbols. Do not invent
   missing context and do not decide the gate.
5. Cite only `line_ref` values present in the assigned role context. Write only
   `workspace/role-payload.json` matching
   `references/payload.schema.json`. Do not add role, task, evidence-level,
   hash, or gate fields.
6. Run `scripts/build-delivery.sh` with the pinned runtime and assignment
   arguments. The runtime, not the model, creates `workspace/delivery.json`.
7. Submit through `taskflow(action="submit_task")` and include
   `workspace/delivery.json` as a deliverable. The chat response only references
   the submitted result.

## Stop conditions

Stop with `BLOCKED` when the task is not registered, the role/Worker differs,
the input is not marked cloud-safe, the bundle/hash differs, the schema fails,
or the authoritative delivery cannot be created exactly once. Never expose a
credential, raw secret, absolute host path, or patch in Matrix chat.
