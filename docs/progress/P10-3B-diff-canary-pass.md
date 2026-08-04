# P10-3B Diff Worker canary completion

Date: 2026-08-02

Result: **PASS for P10-3B-2 Diff Worker only**

P10-3B overall status: **in progress; stopped before Security pending Gate C**

## Scope and accepted claim

The accepted clean source revision was
`1d092bcc429f3fa25dd7ad7d62c6c7fc577a1cfe`. The run deployed only
`codesentinel-diff-review` to `cs-diff-analyzer`, registered one bounded finite
task, obtained one cloud-safe structural analysis, built the authoritative
delivery with the pinned runtime, and submitted it through the official
AgentTeams taskflow.

This proves a real Diff Worker canary and its deterministic artifact path. It
does not prove the Security or Quality canaries, three-Worker orchestration,
parallel execution, autonomous Manager decisions, or the final CodeSentinel
gate.

## Reproducible inputs

| Item | Accepted value |
|---|---|
| Source revision | `1d092bcc429f3fa25dd7ad7d62c6c7fc577a1cfe` |
| Runtime SHA-256 | `cafae83196efa7991c4144d1a64e4381cbe84552e37c99b0924299223427cfc6` |
| Diff Skill tree SHA-256 | `2ee58e1d2846021ec0e1c42fc1c3e182ae6b0328411c759b1d07546017c8015b` |
| Matrix candidate SHA-256 | `b8c36e9f356a2ea6f771f0e3dd69954b43ea6ef5edbffd305ff4ce548967e5c4` |
| Delivery output SHA-256 | `5fd649f0df14d26f199ad1935ef7a49a931e76be34e810704138e80dbf50ecd9` |
| Authoritative delivery SHA-256 | `a0144cfc2dc41e962796d50f087d54081a107e96b6322d4182834c5957e92333` |
| Submitted result SHA-256 | `cd3b27c6c6caff51ab47cf58721c037de481b42daff2878d909f5ffc4676bb69` |

The final machine-readable evidence is
[`P10-3B-diff-canary-evidence.json`](P10-3B-diff-canary-evidence.json), whose
SHA-256 is
`db6212d8772d99ed65ae015ebf9434bb43ff42b5509035ea47026514e56dba87`.

## Live execution evidence

- Heartbeat was disabled through the supported API and its scheduler-removal
  log was observed.
- Manager usage remained `127` at elapsed 0, 55, 110, and 130 seconds.
- The original Heartbeat JSON was restored; its SHA-256 remained
  `133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`,
  and the scheduler-reschedule log was observed.
- The official task acknowledgement reached `in_progress` and the official
  submission reached `submitted`, `synced=true`, and `verified=true`.
- Four Matrix tool-progress events were ignored as non-authoritative. Exactly
  one later Worker event matched the strict Diff payload contract and did not
  mention the Manager.
- The Manager independently pulled and validated the submitted delivery with
  `validate-assigned-delivery`; the validation used zero model calls.
- The Manager active-task count returned to zero.

## Budget and isolation

The accepted semantic task used one domain analysis and exactly two Diff
provider calls, the full approved Diff budget. Aggregate counters moved from
the original canary baseline `127/4/6/3` to `127/6/6/3` for
Manager/Diff/Security/Quality. Therefore:

- Manager delta: `0`;
- Diff provider-call delta: `2 / 2`;
- Security delta: `0`;
- Quality delta: `0`.

All four routes remained `hiclaw-gateway/deepseek-v4-pro`. Dify remained
stopped. Security and Quality Skills remained absent both remotely and
locally. No route, key, gateway, container, volume, or credential was changed.

## Fail-closed recovery findings

The bounded loop exposed controller and runtime-invocation defects without
spending more than the accepted model budget:

1. Direct taskflow invocation initially used the Worker container's default
   working directory. The call failed before model use and the transaction
   rolled back. The controller now pins the official CoPaw workspace.
2. The first Matrix observer treated a `read_file` progress event as a final
   response. The Skill and task state were rolled back while the same bounded
   Agent turn completed. The observer now ignores progress events and accepts
   only one strict JSON candidate.
3. The second provider-call counter settled after the initial rollback. A
   fresh stability check detected the delayed increment and froze the final
   budget at `2 / 2`; all later recovery steps used zero model calls.
4. The Worker system Python lacked Pydantic. No package or image was changed;
   the deterministic script was invoked with the existing CoPaw Python first
   on `PATH`.
5. The first submission used a relative deliverable path. AgentTeams rejected
   it before writing `result.md`. The corrected full
   `shared/tasks/<task>/workspace/delivery.json` path passed dry-run and real
   submission validation.

Every rejected iteration restored Heartbeat, removed only the exact Diff
Skill deployment, restored registry semantics, cleared the Manager active
task, preserved task evidence, and left all model counters within budget.

## Final state and next gate

On success the exact nine-file Diff Skill remains installed, as required for
the next controlled phase. Manager-visible, Worker-visible, and Worker-local
package hashes agree. The submitted task and authoritative artifacts remain
preserved. Security and Quality remain untouched.

The next permitted action is documentation review and a separate Gate C
decision. Do not start the Security Worker under the Diff approval or reuse
the exhausted Diff model budget.

## Post-run offline regression

After writing this report and the machine evidence:

- all `304` collected tests passed;
- Ruff passed over `src` and `tests`;
- Python compilation passed over `src` and `tests`;
- `pip check` reported no broken requirements;
- the evidence JSON parsed successfully; and
- `git diff --check` passed apart from expected Windows LF-to-CRLF notices.
