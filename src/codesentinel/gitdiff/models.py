"""Strict, serializable contracts for P5 Git input artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from codesentinel.domain.models import ContractModel, FileChange

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class DiffSource(StrEnum):
    """The exact Git comparison used to create the artifact."""

    REVISION_RANGE = "revision_range"
    WORKTREE = "worktree"
    STAGED = "staged"
    UNSTAGED = "unstaged"


class DiffLineKind(StrEnum):
    """Unified-diff line kinds that participate in line-number mapping."""

    CONTEXT = "context"
    ADDITION = "addition"
    DELETION = "deletion"


class DiffLine(ContractModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    kind: DiffLineKind
    content: str
    old_line: int | None = Field(default=None, ge=1)
    new_line: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def line_numbers_must_match_kind(self) -> Self:
        if self.kind is DiffLineKind.CONTEXT:
            if self.old_line is None or self.new_line is None:
                raise ValueError("context lines require old_line and new_line")
        elif self.kind is DiffLineKind.ADDITION:
            if self.old_line is not None or self.new_line is None:
                raise ValueError("addition lines require only new_line")
        elif self.old_line is None or self.new_line is not None:
            raise ValueError("deletion lines require only old_line")
        return self


class DiffHunk(ContractModel):
    hunk_id: NonEmptyStr
    header: NonEmptyStr
    old_start: int = Field(ge=0)
    old_count: int = Field(ge=0)
    new_start: int = Field(ge=0)
    new_count: int = Field(ge=0)
    lines: tuple[DiffLine, ...]

    @model_validator(mode="after")
    def declared_counts_must_match_lines(self) -> Self:
        observed_old = sum(
            line.kind in {DiffLineKind.CONTEXT, DiffLineKind.DELETION}
            for line in self.lines
        )
        observed_new = sum(
            line.kind in {DiffLineKind.CONTEXT, DiffLineKind.ADDITION}
            for line in self.lines
        )
        if observed_old != self.old_count or observed_new != self.new_count:
            raise ValueError("hunk ranges must match parsed diff lines")
        return self


class ParsedFileDiff(ContractModel):
    change: FileChange
    hunks: tuple[DiffHunk, ...]
    analysis_eligible: bool
    exclusion_reason: Literal[
        "binary",
        "unsupported_language",
        "changed_line_limit",
    ] | None = None

    @model_validator(mode="after")
    def file_metadata_must_match_hunks(self) -> Self:
        hunk_ids = tuple(hunk.hunk_id for hunk in self.hunks)
        if self.change.hunk_ids != hunk_ids:
            raise ValueError("FileChange hunk_ids must match parsed hunks")
        additions = sum(
            line.kind is DiffLineKind.ADDITION
            for hunk in self.hunks
            for line in hunk.lines
        )
        deletions = sum(
            line.kind is DiffLineKind.DELETION
            for hunk in self.hunks
            for line in hunk.lines
        )
        if not self.change.is_binary and (
            self.change.additions != additions or self.change.deletions != deletions
        ):
            raise ValueError("text file totals must match parsed hunks")
        if self.analysis_eligible == (self.exclusion_reason is not None):
            raise ValueError("eligible files must not have an exclusion reason")
        if self.change.is_binary and self.exclusion_reason != "binary":
            raise ValueError("binary files must be excluded as binary")
        return self


class GitDiffArtifact(ContractModel):
    """Local-only P5 artifact; raw source is never cloud-safe before P6."""

    schema_name: Literal["GitDiffArtifact"] = "GitDiffArtifact"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    repository_name: NonEmptyStr
    repository_fingerprint: NonEmptyStr
    source: DiffSource
    base_revision: NonEmptyStr
    base_oid: NonEmptyStr
    target_revision: NonEmptyStr | None
    target_oid: NonEmptyStr | None
    diff_hash: NonEmptyStr
    raw_diff_bytes: int = Field(ge=1)
    files: tuple[ParsedFileDiff, ...] = Field(min_length=1)
    total_additions: int = Field(ge=0)
    total_deletions: int = Field(ge=0)
    changed_lines: int = Field(ge=0)
    max_changed_lines: int = Field(ge=1)
    exceeds_changed_line_limit: bool
    binary_files: tuple[NonEmptyStr, ...]
    unsupported_files: tuple[NonEmptyStr, ...]
    context_lines: Literal[3] = 3
    parser_version: Literal["p5-1.0.0"] = "p5-1.0.0"
    cloud_safe: Literal[False] = False
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("created_at must use UTC")
        return value.astimezone(UTC)

    @field_validator("binary_files", "unsupported_files")
    @classmethod
    def path_lists_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("path lists must not contain duplicates")
        return value

    @model_validator(mode="after")
    def totals_and_boundaries_must_be_consistent(self) -> Self:
        changes = tuple(item.change for item in self.files)
        if self.total_additions != sum(item.additions for item in changes):
            raise ValueError("total_additions must equal file totals")
        if self.total_deletions != sum(item.deletions for item in changes):
            raise ValueError("total_deletions must equal file totals")
        if self.changed_lines != self.total_additions + self.total_deletions:
            raise ValueError("changed_lines must equal additions plus deletions")
        if self.exceeds_changed_line_limit != (
            self.changed_lines > self.max_changed_lines
        ):
            raise ValueError("changed-line limit flag is inconsistent")
        binary = tuple(
            item.change.new_path or item.change.old_path
            for item in self.files
            if item.change.is_binary
        )
        unsupported = tuple(
            item.change.new_path or item.change.old_path
            for item in self.files
            if item.change.language == "unknown" and not item.change.is_binary
        )
        if self.binary_files != binary or self.unsupported_files != unsupported:
            raise ValueError("binary and unsupported path indexes must match files")
        if self.source is DiffSource.REVISION_RANGE:
            if self.target_revision is None or self.target_oid is None:
                raise ValueError("revision ranges require a resolved target")
        elif self.target_revision is not None or self.target_oid is not None:
            raise ValueError("worktree sources must not contain a target revision")
        return self


class TraceEvent(ContractModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: NonEmptyStr
    review_id: NonEmptyStr
    sequence: int = Field(ge=1)
    event_type: Literal["review_created", "diff_parsed", "artifact_persisted"]
    status: Literal["success", "failed"]
    occurred_at: datetime
    details: dict[str, str | int | bool | None]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("occurred_at must use UTC")
        return value.astimezone(UTC)


def utc_now() -> datetime:
    """Return an aware UTC timestamp through one injectable boundary."""

    return datetime.now(UTC)
