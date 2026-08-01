---
name: codesentinel-quality-review
description: Produce strict semantic quality findings over one cloud-safe CodeSentinel review context.
assign_when: Assign only to cs-quality-reviewer for a registered CodeSentinel quality-review task.
---

# CodeSentinel Quality Review

Use this Skill only when the assignment role is `quality_reviewer` and the task
belongs to the current Worker room. Review correctness, reliability,
maintainability, performance, and test gaps without making security or gate
decisions.

## Required workflow

1. Acknowledge the finite task with `taskflow(action="ack_task")` before work.
2. Read the pulled `spec.md`, `base/assignment.json`,
   `base/role-context.json`, request envelope, deployment manifest, quality
   context, and only the assignment-listed cloud-safe artifacts.
3. Verify the runtime archive against the exact SHA-256 in the deployment
   manifest. Stop on any mismatch, unsafe path, missing file, or identity
   mismatch.
4. Analyze changed behavior and bounded context. Preserve uncertainty and do
   not invent repository-wide coverage or decide the gate.
5. Cite only `line_ref` values present in the assigned role context. Write only
   `workspace/role-payload.json` matching
   `references/payload.schema.json`. Every finding must cite one to five input
   `line_refs`. Do not add evidence-level, role, task, hash, security, or gate
   fields.
6. Run `scripts/build-delivery.sh` with the pinned runtime and assignment
   arguments. The runtime creates E1 evidence and `workspace/delivery.json`.
7. Submit through `taskflow(action="submit_task")` and include
   `workspace/delivery.json` as a deliverable. The chat response only references
   the submitted result.

## Stop conditions

Stop with `BLOCKED` when the task is not registered, the role/Worker differs,
the input is not cloud-safe, the bundle/hash differs, a line reference is
unavailable, the schema fails, or the authoritative delivery cannot be created
exactly once. Never expose a credential, raw secret, absolute host path, or
patch in Matrix chat.
