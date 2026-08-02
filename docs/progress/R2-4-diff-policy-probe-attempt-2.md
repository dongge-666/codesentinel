# R2-4 Diff-only policy probe attempt 2

Date: 2026-08-02

Result: **PASS; R2-5 may proceed under the approved bounded Loop**

The second attempt used the reviewed source exact hash, MinIO semantic hash,
and complete normalized-object equality. It completed in `139.087` seconds.

## Policy evidence

- source exact SHA-256:
  `a4ba569aea81bb06c1ea38c58d1cde6c25467513bf86a250ea27153ccbf6362f`;
- readback semantic SHA-256:
  `02e7b1ccae93d69563f9a01b45bfd5929aa35fbcf3ac59b67ecec6abe695f148`;
- normalized readback equals the complete reviewed source: true;
- attachment users: `1`;
- attachment groups: `0`;
- attached subject fingerprint:
  `37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f`.

The reviewed policy remains attached for R2-5. `worker-default` remains
unchanged and attached to the same Manager identity.

## Capability matrix

The nonce-bound positive object used content SHA-256
`7fbcc89b145cc3d41927466300deb51c9dc1c43588b2d68eb6381e6d7fc958b9`.

| Capability | Result |
|---|---|
| Manager put inside exact Diff Skill prefix | PASS |
| Manager list exact probe prefix | PASS |
| Manager get with matching content hash | PASS |
| Diff Worker get with matching content hash | PASS |
| Manager exact delete | PASS |
| Independent post-delete absence | PASS |
| Security prefix list and put | DENIED as required |
| Quality prefix list and put | DENIED as required |
| Sibling Diff Skill list and put | DENIED as required |

Independent inspection found zero remaining probe objects.

## Heartbeat, task, and budget evidence

- Heartbeat removal and restoration scheduler logs were observed;
- original and restored Heartbeat SHA-256 both equal
  `133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`;
- Manager count at 0/65/130 seconds: `51 / 51 / 51`;
- before/after Manager, Diff, Security, Quality counts:
  `51/1/1/1 -> 51/1/1/1`;
- active tasks: `0`;
- all three registry Skill assignments: null;
- all protected Worker-local Skill paths: absent.

The ignored redacted result JSON SHA-256 is
`6c3073749ceeb52054c51bbfbc340b6e0fa21cc16affdb3136a5a9232dee9708`.
The ignored transaction helper SHA-256 is
`90895f8c04c9be5c60bf308133b828f216867e944acadb71af26ec43ec0743be`.

R2-4 is complete. This result does not authorize a semantic task or claim that
the Diff Skill deployment transaction has passed; that remains R2-5.
