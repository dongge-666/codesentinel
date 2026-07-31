"""Read-only local Git boundary used by the CodeSentinel MVP."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

from codesentinel.domain import ReviewRequest

from .errors import (
    DiffModeError,
    DiffSizeLimitError,
    EmptyDiffError,
    GitCommandError,
    RepositoryValidationError,
    RevisionValidationError,
)
from .models import DiffSource, GitDiffArtifact, ParsedFileDiff, utc_now
from .parser import parse_unified_diff

_SAFE_REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@~^+/-]{0,254}")
_SAFE_REVIEW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
DEFAULT_MAX_DIFF_BYTES = 10 * 1024 * 1024


class GitDiffReader:
    """Validate and parse a local Git diff without acquiring optional Git locks."""

    def __init__(
        self,
        *,
        git_executable: str = "git",
        timeout_seconds: float = 30.0,
        max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_diff_bytes <= 0:
            raise ValueError("max_diff_bytes must be positive")
        self._git_executable = git_executable
        self._timeout_seconds = timeout_seconds
        self._max_diff_bytes = max_diff_bytes

    def _run(self, repository: Path | None, arguments: list[str]) -> bytes:
        command = [self._git_executable, "--no-pager"]
        if repository is not None:
            command.extend(["-C", str(repository)])
        command.extend(["-c", "core.quotepath=false", *arguments])
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_PAGER": "cat",
            }
        )
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
                env=environment,
                creationflags=creation_flags,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitCommandError("read-only Git command could not complete") from exc
        if completed.returncode != 0:
            raise GitCommandError(
                f"read-only Git command failed with exit code {completed.returncode}"
            )
        return completed.stdout

    def validate_repository(self, requested_path: str) -> Path:
        candidate = Path(requested_path)
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryValidationError("repository path does not exist") from exc
        if not resolved.is_dir():
            raise RepositoryValidationError("repository path must be a directory")
        try:
            output = self._run(resolved, ["rev-parse", "--show-toplevel"])
        except GitCommandError as exc:
            raise RepositoryValidationError("path is not a Git worktree") from exc
        top_level_text = output.decode("utf-8", errors="strict").strip()
        try:
            top_level = Path(top_level_text).resolve(strict=True)
        except (OSError, RuntimeError, UnicodeError) as exc:
            raise RepositoryValidationError("Git returned an invalid worktree root") from exc
        if top_level != resolved:
            raise RepositoryValidationError(
                "repository_path must name the Git worktree root, not a subdirectory"
            )
        return resolved

    def resolve_revision(self, repository: Path, revision: str) -> str:
        if _SAFE_REVISION.fullmatch(revision) is None or revision.startswith("-"):
            raise RevisionValidationError("revision contains unsupported characters")
        try:
            output = self._run(
                repository,
                [
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    "--end-of-options",
                    f"{revision}^{{commit}}",
                ],
            )
        except GitCommandError as exc:
            raise RevisionValidationError("revision is missing or not commit-like") from exc
        object_id = output.decode("ascii", errors="strict").strip().lower()
        if _OBJECT_ID.fullmatch(object_id) is None:
            raise RevisionValidationError("Git returned an invalid commit object ID")
        return object_id

    @staticmethod
    def _diff_arguments(
        request: ReviewRequest,
        base_oid: str,
        target_oid: str | None,
    ) -> tuple[DiffSource, list[str]]:
        common = [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--full-index",
            "--find-renames=50%",
            "--unified=3",
            "--submodule=short",
        ]
        if target_oid is not None:
            return DiffSource.REVISION_RANGE, [*common, base_oid, target_oid, "--"]
        if request.include_staged and request.include_unstaged:
            return DiffSource.WORKTREE, [*common, base_oid, "--"]
        if request.include_staged:
            return DiffSource.STAGED, [*common, "--cached", base_oid, "--"]
        if request.include_unstaged:
            return DiffSource.UNSTAGED, [*common, "--"]
        raise DiffModeError("at least one of staged or unstaged must be selected")

    def read(self, request: ReviewRequest, *, review_id: str) -> GitDiffArtifact:
        """Return a complete local-only artifact for the selected Git comparison."""

        if _SAFE_REVIEW_ID.fullmatch(review_id) is None:
            raise DiffModeError("review_id is not safe for artifact paths")
        if request.include_untracked:
            raise DiffModeError("untracked files are outside the P5 diff boundary")
        repository = self.validate_repository(request.repository_path)
        base_oid = self.resolve_revision(repository, request.base_revision)
        target_oid = (
            self.resolve_revision(repository, request.target_revision)
            if request.target_revision is not None
            else None
        )
        source, arguments = self._diff_arguments(request, base_oid, target_oid)
        raw_diff = self._run(repository, arguments)
        if not raw_diff:
            raise EmptyDiffError("selected Git comparison contains no changes")
        if len(raw_diff) > self._max_diff_bytes:
            raise DiffSizeLimitError(
                f"diff is {len(raw_diff)} bytes; limit is {self._max_diff_bytes} bytes"
            )
        decoded_diff = raw_diff.decode("utf-8", errors="replace")
        files = parse_unified_diff(decoded_diff)
        additions = sum(item.change.additions for item in files)
        deletions = sum(item.change.deletions for item in files)
        changed_lines = additions + deletions
        if changed_lines > request.max_changed_lines:
            files = tuple(
                ParsedFileDiff(
                    change=item.change,
                    hunks=item.hunks,
                    analysis_eligible=False,
                    exclusion_reason="changed_line_limit",
                )
                if item.analysis_eligible
                else item
                for item in files
            )
        binary_files = tuple(
            item.change.new_path or item.change.old_path
            for item in files
            if item.change.is_binary
        )
        unsupported_files = tuple(
            item.change.new_path or item.change.old_path
            for item in files
            if item.change.language == "unknown" and not item.change.is_binary
        )
        repository_identity = os.path.normcase(str(repository))
        return GitDiffArtifact(
            review_id=review_id,
            repository_name=repository.name,
            repository_fingerprint=hashlib.sha256(
                repository_identity.encode("utf-8")
            ).hexdigest(),
            source=source,
            base_revision=request.base_revision,
            base_oid=base_oid,
            target_revision=request.target_revision,
            target_oid=target_oid,
            diff_hash=hashlib.sha256(raw_diff).hexdigest(),
            raw_diff_bytes=len(raw_diff),
            files=files,
            total_additions=additions,
            total_deletions=deletions,
            changed_lines=changed_lines,
            max_changed_lines=request.max_changed_lines,
            exceeds_changed_line_limit=changed_lines > request.max_changed_lines,
            binary_files=binary_files,
            unsupported_files=unsupported_files,
            created_at=utc_now(),
        )
