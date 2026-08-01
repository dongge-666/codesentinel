# Security Worker input contract

The authoritative task inputs are `base/assignment.json` and the exact
`role_context.ref` named by that assignment. The runtime validates both before
building a delivery.

The assignment must identify role `security_scanner`, Skill
`codesentinel-security-review`, the immutable review input, the hashed role
context, attempt, deadline, and the exact `workspace/delivery.json` reference.

The role context must be cloud-safe and contain:

- the same `review_id` and role;
- unique Git-diff and deterministic-scan source artifact IDs;
- unique sanitized lines with stable `line_ref` values and content hashes;
- deterministic findings whose line references belong to the context;
- at least three unique deterministic coverage records;
- the trusted diff SHA-256.

Only `line_ref` values present in this context may be cited. Failed deterministic
coverage must retain its error code and must not be silently downgraded.
