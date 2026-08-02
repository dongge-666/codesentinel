# R2-5 zero-model Diff deployment and rollback proof

Date: 2026-08-02

Result: **PASS on attempt 4; attempts 1-3 were rejected and recovered**

Accepted source revision:
`7f8b3a1589c00ba4fde182b13ed703692804f2bb`

R2-5 exercised only
`cs-diff-analyzer -> codesentinel-diff-review`. It created no finite task,
sent no Matrix event, and invoked no model.

## Accepted package and tools

- runtime bundle SHA-256:
  `5cb06f2f901db31e10fefc0eaa48522938c28643eaba563fbaebdc2b8ee6f718`;
- runtime manifest SHA-256:
  `3d55e436118d16a2f22ed749f612282d5d02562bc842b2f1f8f54b274ffd48f8`;
- Diff package: exactly nine allow-listed files;
- package tree SHA-256:
  `538ccad34fda714d5a7a89eba54cb7c68de8c79b926d11ccceae9e1453d8c3ab`;
- official push script SHA-256:
  `71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`;
- official `hiclaw-sync` SHA-256:
  `d8ae2686dd4e9ac4e48d377c7d1a3ca866d494f5f543e0aa5e7cb6ddcf8f85e4`.

The runtime was built twice from an isolated clean checkout. Both archives
and both manifests were byte-identical and reported `source_dirty=false`.
The package passed the repository guard locally, then passed the package-local
runtime-binding verifier and per-file hashing again in Manager staging.

## Accepted transaction

Attempt 4 completed the following sequence:

1. disabled Manager Heartbeat through the supported API;
2. observed scheduler removal and stable Manager total call count `125` at
   0, 55, 110, and 130 seconds;
3. materialized the exact nine-file package in the central Manager source;
4. invoked official `--add-skill --no-notify` for only the Diff mapping;
5. independently read and hashed all nine remote objects through both the
   Manager and Diff Worker storage identities;
6. invoked the installed official `hiclaw-sync` inside only the Diff Worker;
7. verified the Worker-local nine-file allow-list and hashes;
8. moved the verified Worker-local package to a revision-scoped recoverable
   backup;
9. invoked official exact `--remove-skill --no-notify`;
10. proved remote absence through Controller, Manager, and Worker views;
11. restored the registry preimage semantics and moved the central source to
    its recoverable backup;
12. restored Heartbeat and observed the reschedule log.

Manager, Diff, Security, and Quality total call counts were
`125/4/6/3` before deployment, after deployment, and after rollback.
All four routes remained `hiclaw-gateway/deepseek-v4-pro`.

## Rejected attempts and corrective action

The prior attempts are retained because a credible audit must show failures,
not erase them.

| Attempt | Disposition | Cause | Recovery |
|---|---|---|---|
| 1 | REJECTED | Registry writer appended literal `\\n`; Heartbeat matcher expected the wrong log phrase | Proved the exact two-byte suffix, atomically replaced it with `0a`, and independently proved registry semantic equality; all deployment targets had already been rolled back |
| 2 | REJECTED | A non-ASCII evidence-filter regex was decoded incorrectly by Windows PowerShell | Transaction failed closed; registry, remote, local, central source, policy, usage, and Heartbeat were restored |
| 3 | REJECTED | Online transaction passed, but retained table glyphs made the written evidence JSON independently unparsable | Transaction and rollback completed; evidence filtering was restricted to ASCII status lines and tested with a JSON round trip |
| 4 | ACCEPTED | No error | Full transaction, rollback, Heartbeat restoration, and independent JSON parsing passed |

Ignored evidence SHA-256 values:

- attempt 1: `e8dc8e25f4220f466162ffc9af2592452bc1ea014b1d8401c7f8d03a407e82dc`;
- attempt 2: `670e379afec22e5be1a589156e0d68c104cab7cb0989accd198263e04ba53ab6`;
- attempt 3: `9bafffce882a3a88452b3a124b564c10173407efb1c43a4714d9018605347518`;
- accepted attempt 4:
  `a3995ecc747e139053a3a1a0d701d3818c012be1dd19d396c65eb35f23a9ebfa`;
- accepted attempt 4 helper:
  `738fb9cc31354a06e86e2f8d9f353e768ee9813da3f160523f8d509fff2bf20e`.

## Accepted post-state

- Diff, Security, and Quality remote CodeSentinel Skill object counts: zero;
- all three Worker-local CodeSentinel Skill paths: absent;
- central Manager Diff Skill source: absent;
- registry Skill assignments: all null;
- registry semantic SHA-256:
  `994cd827cf265782b449661ae81a56c6f339be47eeef2e55cdfbca4d7615f05e`;
- active finite tasks: zero;
- Heartbeat enabled with original SHA-256
  `133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`;
- exactly five expected AgentTeams containers running and no Dify container;
- minimal Diff deployer policy remains the only intended persistent
  infrastructure addition.

R2-5 proves the deployment infrastructure path only. It does not claim a
semantic Worker delivery or satisfy the P10 Diff Canary by itself.
