# P5 Git Diff input and Artifact Store

Status: completed
Date: 2026-07-31

## Outcome

P5 adds a deterministic, read-only boundary from a user-selected local Git
worktree to a strict `GitDiffArtifact`. It performs no network, DeepSeek, or
AgentTeams operation and does not implement P6 security review skills.

The public API is under `codesentinel.gitdiff`:

- `GitDiffReader` validates and reads a Git comparison;
- `GitDiffArtifact` preserves parsed file, hunk, line, hash, and eligibility
  metadata;
- `ArtifactStore` writes the local input artifact, JSONL trace, and hash
  manifest below the CodeSentinel workspace.

## Supported input modes

- `base_revision` to `target_revision`: committed revision range;
- staged and unstaged together: base commit to current worktree;
- staged only: base commit to index;
- unstaged only: index to worktree.

Every named revision is syntax-checked and resolved to a commit object ID
before it is used by `git diff`. When `target_revision` is present, the
committed revision range takes precedence over worktree flags. Untracked files
are rejected explicitly in P5 rather than being silently ignored.

## Parsing and boundary behavior

- added, modified, deleted, and renamed files are represented by the frozen
  `FileChange` contract;
- unified hunks retain three context lines and map every source line to its
  old/new side line number;
- source indentation and empty lines are preserved;
- `.py` and `.pyi` are the only P5 analysis languages;
- binary bodies are not included and binary files are ineligible;
- unsupported files remain traceable but are ineligible;
- a diff over `max_changed_lines` is preserved in full, marked explicitly,
  and made ineligible rather than silently truncated;
- a separate 10 MiB absolute safety ceiling fails with a typed error;
- the SHA-256 diff hash is calculated over the exact Git output bytes.

## Security controls

- the requested path must be the exact resolved Git worktree root;
- Git is invoked with an argument list and never through a shell;
- option-like revisions and invalid commit objects are rejected;
- external diff drivers and text conversion are disabled;
- terminal prompting, pagers, and optional Git locks are disabled;
- no repository file is opened or symlink-followed outside Git's object/diff
  boundary;
- artifacts never contain the absolute repository path, only a name and
  one-way fingerprint;
- the Artifact Store verifies that the target fingerprint matches the input
  artifact and refuses to write within the reviewed repository;
- symlinked artifact directories, duplicate review directories, and unsafe
  review IDs are rejected;
- artifact files are atomically replaced and receive owner-only permissions
  where the operating system supports them.

P5 artifacts contain local source lines and therefore remain
`cloud_safe=false`. This is a deliberate fail-closed boundary: P6 must create
redacted, verified evidence before P7 can send any source-derived context to
DeepSeek.

## Verification

P5 adds 11 real-Git fixture tests. They create isolated temporary repositories
and cover:

- all four change types, spaces in paths, Python and non-Python files;
- binary exclusion and hunk line-number mapping;
- staged, unstaged, and combined worktree semantics;
- deterministic hashes and unchanged target state;
- more than 1000 changed lines without truncation;
- absolute byte ceiling, empty diff, invalid repository, revision injection,
  invalid mode, and repository-relative escape rejection;
- Artifact Store output location, JSONL ordering, hashes, duplicate runs,
  target mismatch, and target-repository write refusal.

Acceptance commands:

```powershell
D:\python\Anaconda\envs\agent_dev\python.exe -m pytest -q
D:\python\Anaconda\envs\agent_dev\python.exe -m ruff check src tests
D:\python\Anaconda\envs\agent_dev\python.exe -m pip check
```

## Resolved implementation issues

Two non-obvious Git/contract boundaries were found by the real fixture:

1. Git for Windows may leave spaces unquoted in `diff --git` headers and use
   a tab separator in `---/+++` metadata. Parsing now prioritizes explicit
   patch and rename metadata with a restricted header fallback.
2. The P4 contract base strips surrounding string whitespace, which is safe
   for identifiers but unsafe for source code. `DiffLine` overrides that one
   setting so Python indentation and empty content remain exact.

## Deliberate P5 limitations

- no untracked-file ingestion;
- no secret detection or masking;
- no cloud-safe prompt payload;
- no security or quality finding generation;
- no CLI, Markdown review report, LLM call, or AgentTeams business workflow.

These limitations belong to P6 through P10 and must not be presented as
implemented in the preliminary submission.
