# Diff Worker input contract

The authoritative task inputs are `base/assignment.json` and the exact
`role_context.ref` named by that assignment. The runtime validates both before
building a delivery.

The assignment must identify role `diff_analyzer`, Skill
`codesentinel-diff-review`, the immutable review input, the hashed role context,
attempt, deadline, and the exact `workspace/delivery.json` reference.

The role context must be cloud-safe and contain:

- the same `review_id` and role;
- unique source artifact IDs;
- unique lines with `line_ref`, repository-relative path, hunk, side, line
  number, content, and SHA-256;
- metadata containing diff hash, changed files, addition/deletion totals,
  unsupported files, and parser version.

Only `line_ref` values present in this context may be cited.
