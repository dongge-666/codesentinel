# Quality Worker input contract

The authoritative task inputs are `base/assignment.json` and the exact
`role_context.ref` named by that assignment. The runtime validates both before
building a delivery.

The assignment must identify role `quality_reviewer`, Skill
`codesentinel-quality-review`, the immutable review input, the hashed role
context, attempt, deadline, and the exact `workspace/delivery.json` reference.

The role context must be cloud-safe and contain:

- the same `review_id` and role;
- unique source artifact IDs;
- unique sanitized lines with stable `line_ref` values and content hashes;
- metadata containing the trusted diff SHA-256 and bounded Ruff summary.

Only `line_ref` values present in this context may be cited.
