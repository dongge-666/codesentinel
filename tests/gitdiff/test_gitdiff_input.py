from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from codesentinel.domain import ChangeType, ReviewRequest
from codesentinel.gitdiff import (
    ArtifactBoundaryError,
    ArtifactStore,
    DiffLineKind,
    DiffModeError,
    DiffParseError,
    DiffSizeLimitError,
    DiffSource,
    EmptyDiffError,
    GitDiffReader,
    RepositoryValidationError,
    RevisionValidationError,
)
from codesentinel.gitdiff.parser import parse_unified_diff


def run_git(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    return completed.stdout.strip()


def write_text(repository: Path, relative_path: str, content: str) -> None:
    destination = repository / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8", newline="\n")


def initialize_repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main", str(path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    run_git(path, "config", "user.name", "CodeSentinel Fixture")
    run_git(path, "config", "user.email", "fixture@users.noreply.github.com")
    return path.resolve()


@pytest.fixture
def revision_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = initialize_repository(tmp_path / "target-repository")
    write_text(repository, "app.py", "def value():\n    return 1\n")
    write_text(repository, "remove.py", "TO_REMOVE = True\n")
    write_text(repository, "old_name.py", "RENAMED = True\n")
    write_text(repository, "notes.md", "before\n")
    write_text(repository, "pkg/hello world.py", "MESSAGE = 'before'\n")
    (repository / "image.bin").write_bytes(b"\x00before\xff")
    run_git(repository, "add", "--all")
    run_git(repository, "commit", "-m", "base")
    base_oid = run_git(repository, "rev-parse", "HEAD")

    write_text(
        repository,
        "app.py",
        "def value():\n    return 2\n\ndef added():\n    return 3\n",
    )
    write_text(repository, "new.py", "NEW_VALUE = 1\n")
    (repository / "remove.py").unlink()
    run_git(repository, "mv", "old_name.py", "renamed.py")
    write_text(repository, "notes.md", "after\n")
    write_text(repository, "pkg/hello world.py", "MESSAGE = 'after'\n")
    (repository / "image.bin").write_bytes(b"\x00after\xfe")
    run_git(repository, "add", "--all")
    run_git(repository, "commit", "-m", "target")
    target_oid = run_git(repository, "rev-parse", "HEAD")
    return repository, base_oid, target_oid


def revision_request(repository: Path, base_oid: str, target_oid: str) -> ReviewRequest:
    return ReviewRequest(
        repository_path=str(repository),
        base_revision=base_oid,
        target_revision=target_oid,
    )


def test_revision_range_parses_all_change_types_and_special_files(
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    artifact = GitDiffReader().read(
        revision_request(repository, base_oid, target_oid),
        review_id="revision-case",
    )

    changes = {
        item.change.new_path or item.change.old_path: item for item in artifact.files
    }
    assert changes["new.py"].change.change_type is ChangeType.ADDED
    assert changes["remove.py"].change.change_type is ChangeType.DELETED
    assert changes["renamed.py"].change.change_type is ChangeType.RENAMED
    assert changes["renamed.py"].change.old_path == "old_name.py"
    assert changes["app.py"].change.change_type is ChangeType.MODIFIED
    assert changes["pkg/hello world.py"].change.language == "python", repr(
        changes["pkg/hello world.py"].change
    )
    assert changes["image.bin"].change.is_binary is True
    assert changes["image.bin"].analysis_eligible is False
    assert changes["image.bin"].exclusion_reason == "binary"
    assert changes["notes.md"].exclusion_reason == "unsupported_language"
    assert artifact.binary_files == ("image.bin",)
    assert artifact.unsupported_files == ("notes.md",)
    assert artifact.source is DiffSource.REVISION_RANGE
    assert artifact.cloud_safe is False
    assert artifact.target_oid == target_oid


def test_hunk_line_numbers_map_old_and_new_sides(
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    artifact = GitDiffReader().read(
        revision_request(repository, base_oid, target_oid),
        review_id="line-map",
    )
    app = next(item for item in artifact.files if item.change.new_path == "app.py")
    lines = tuple(line for hunk in app.hunks for line in hunk.lines)
    removed = next((line for line in lines if line.content == "    return 1"), None)
    replacement = next((line for line in lines if line.content == "    return 2"), None)
    added_function = next((line for line in lines if line.content == "def added():"), None)

    assert removed is not None, repr(lines)
    assert replacement is not None, repr(lines)
    assert added_function is not None, repr(lines)

    assert removed.kind is DiffLineKind.DELETION
    assert (removed.old_line, removed.new_line) == (2, None)
    assert replacement.kind is DiffLineKind.ADDITION
    assert (replacement.old_line, replacement.new_line) == (None, 2)
    assert (added_function.old_line, added_function.new_line) == (None, 4)


def test_reader_is_deterministic_and_does_not_modify_target(
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    request = revision_request(repository, base_oid, target_oid)
    before = {
        "head": run_git(repository, "rev-parse", "HEAD"),
        "tree": run_git(repository, "rev-parse", "HEAD^{tree}"),
        "status": run_git(repository, "status", "--porcelain=v1"),
    }
    first = GitDiffReader().read(request, review_id="stable-one")
    second = GitDiffReader().read(request, review_id="stable-two")
    after = {
        "head": run_git(repository, "rev-parse", "HEAD"),
        "tree": run_git(repository, "rev-parse", "HEAD^{tree}"),
        "status": run_git(repository, "status", "--porcelain=v1"),
    }

    assert before == after
    assert first.diff_hash == second.diff_hash
    assert tuple(item.change for item in first.files) == tuple(
        item.change for item in second.files
    )


def test_staged_unstaged_and_combined_modes_are_distinct(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "working-tree")
    write_text(repository, "app.py", "VALUE = 1\n")
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "base")
    write_text(repository, "app.py", "VALUE = 2\n")
    run_git(repository, "add", "app.py")
    write_text(repository, "app.py", "VALUE = 3\n")
    reader = GitDiffReader()

    staged = reader.read(
        ReviewRequest(
            repository_path=str(repository),
            include_staged=True,
            include_unstaged=False,
        ),
        review_id="staged",
    )
    unstaged = reader.read(
        ReviewRequest(
            repository_path=str(repository),
            include_staged=False,
            include_unstaged=True,
        ),
        review_id="unstaged",
    )
    combined = reader.read(
        ReviewRequest(repository_path=str(repository)),
        review_id="combined",
    )

    def additions(artifact: object) -> tuple[str, ...]:
        return tuple(
            line.content
            for item in artifact.files  # type: ignore[attr-defined]
            for hunk in item.hunks
            for line in hunk.lines
            if line.kind is DiffLineKind.ADDITION
        )

    assert staged.source is DiffSource.STAGED
    assert additions(staged) == ("VALUE = 2",)
    assert unstaged.source is DiffSource.UNSTAGED
    assert additions(unstaged) == ("VALUE = 3",)
    assert combined.source is DiffSource.WORKTREE
    assert additions(combined) == ("VALUE = 3",)


def test_large_diff_is_complete_and_explicitly_over_limit(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "large-diff")
    write_text(repository, "large.py", "BASE = True\n")
    run_git(repository, "add", "large.py")
    run_git(repository, "commit", "-m", "base")
    write_text(
        repository,
        "large.py",
        "\n".join(f"VALUE_{index} = {index}" for index in range(1002)) + "\n",
    )
    artifact = GitDiffReader().read(
        ReviewRequest(repository_path=str(repository), max_changed_lines=1000),
        review_id="large",
    )
    parsed_lines = sum(len(hunk.lines) for hunk in artifact.files[0].hunks)

    assert artifact.changed_lines == 1003
    assert parsed_lines == 1003
    assert artifact.exceeds_changed_line_limit is True
    assert artifact.files[0].analysis_eligible is False
    assert artifact.files[0].exclusion_reason == "changed_line_limit"
    assert artifact.raw_diff_bytes > 0


def test_absolute_diff_byte_limit_fails_instead_of_truncating(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "byte-limit")
    write_text(repository, "app.py", "VALUE = 1\n")
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "base")
    write_text(repository, "app.py", "VALUE = '" + ("x" * 1000) + "'\n")

    with pytest.raises(DiffSizeLimitError):
        GitDiffReader(max_diff_bytes=100).read(
            ReviewRequest(repository_path=str(repository)),
            review_id="too-many-bytes",
        )


def test_repository_revision_and_mode_boundaries(tmp_path: Path) -> None:
    non_repository = tmp_path / "not-a-repository"
    non_repository.mkdir()
    with pytest.raises(RepositoryValidationError):
        GitDiffReader().read(
            ReviewRequest(repository_path=str(non_repository.resolve())),
            review_id="not-repo",
        )

    repository = initialize_repository(tmp_path / "boundary-repository")
    write_text(repository, "app.py", "VALUE = 1\n")
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "base")
    (repository / "subdirectory").mkdir()
    with pytest.raises(RepositoryValidationError):
        GitDiffReader().read(
            ReviewRequest(repository_path=str((repository / "subdirectory").resolve())),
            review_id="subdirectory",
        )
    with pytest.raises(RevisionValidationError):
        GitDiffReader().read(
            ReviewRequest(repository_path=str(repository), base_revision="--output=escape"),
            review_id="option-injection",
        )
    with pytest.raises(RevisionValidationError):
        GitDiffReader().read(
            ReviewRequest(repository_path=str(repository), base_revision="missing-branch"),
            review_id="missing-revision",
        )
    with pytest.raises(DiffModeError):
        GitDiffReader().read(
            ReviewRequest(repository_path=str(repository), include_untracked=True),
            review_id="untracked",
        )
    with pytest.raises(DiffModeError):
        GitDiffReader().read(
            ReviewRequest(
                repository_path=str(repository),
                include_staged=False,
                include_unstaged=False,
            ),
            review_id="no-mode",
        )
    with pytest.raises(EmptyDiffError):
        GitDiffReader().read(
            ReviewRequest(
                repository_path=str(repository),
                base_revision="HEAD",
                target_revision="HEAD",
            ),
            review_id="empty",
        )


def test_parser_rejects_repository_escape_path() -> None:
    malicious_patch = """diff --git a/../../escape.py b/../../escape.py
index 1111111..2222222 100644
--- a/../../escape.py
+++ b/../../escape.py
@@ -1 +1 @@
-SAFE = True
+SAFE = False
"""
    with pytest.raises(DiffParseError):
        parse_unified_diff(malicious_patch)


def test_artifact_store_writes_jsonl_outside_target(
    tmp_path: Path,
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    artifact = GitDiffReader().read(
        revision_request(repository, base_oid, target_oid),
        review_id="persisted-run",
    )
    workspace = tmp_path / "codesentinel-workspace"
    workspace.mkdir()
    before_status = run_git(repository, "status", "--porcelain=v1")
    persisted = ArtifactStore(workspace).persist(
        artifact,
        target_repository=repository,
    )
    after_status = run_git(repository, "status", "--porcelain=v1")

    assert persisted.run_directory.is_relative_to(workspace.resolve())
    assert not persisted.run_directory.is_relative_to(repository)
    assert before_status == after_status == ""
    serialized = json.loads(persisted.diff_artifact_path.read_text(encoding="utf-8"))
    assert serialized["diff_hash"] == artifact.diff_hash
    assert serialized["cloud_safe"] is False
    assert str(repository) not in persisted.diff_artifact_path.read_text(encoding="utf-8")
    trace_lines = persisted.trace_path.read_text(encoding="utf-8").splitlines()
    trace = tuple(json.loads(line) for line in trace_lines)
    assert [event["sequence"] for event in trace] == [1, 2, 3]
    assert [event["event_type"] for event in trace] == [
        "review_created",
        "diff_parsed",
        "artifact_persisted",
    ]
    assert hashlib.sha256(persisted.trace_path.read_bytes()).hexdigest() == (
        persisted.trace_hash
    )
    with pytest.raises(ArtifactBoundaryError):
        ArtifactStore(workspace).persist(artifact, target_repository=repository)


def test_artifact_store_refuses_to_write_inside_reviewed_repository(
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    artifact = GitDiffReader().read(
        revision_request(repository, base_oid, target_oid),
        review_id="unsafe-output",
    )
    with pytest.raises(ArtifactBoundaryError):
        ArtifactStore(repository).persist(artifact, target_repository=repository)


def test_artifact_store_rejects_mismatched_repository(
    tmp_path: Path,
    revision_repository: tuple[Path, str, str],
) -> None:
    repository, base_oid, target_oid = revision_repository
    artifact = GitDiffReader().read(
        revision_request(repository, base_oid, target_oid),
        review_id="mismatched-target",
    )
    different_repository = initialize_repository(tmp_path / "different-repository")
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ArtifactBoundaryError):
        ArtifactStore(workspace).persist(
            artifact,
            target_repository=different_repository,
        )
