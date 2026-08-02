"""Minimal, role-isolated, cloud-safe P7 Agent contexts."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from codesentinel.domain import CoverageStatus
from codesentinel.domain.models import ContractModel, FileChange
from codesentinel.gitdiff import GitDiffArtifact
from codesentinel.skills.security import SanitizedDiffView, SecurityScanResult
from codesentinel.skills.security.base import content_hash, stable_id
from codesentinel.skills.security.common import SourceLine, iter_source_lines

from .models import AgentContextLine, DeterministicFindingSummary, ProviderErrorCode

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_REDACTION_TOKEN = re.compile(r"<REDACTED:[A-Z0-9_]+:([0-9a-f]{12})>")


class ContextBuildError(ValueError):
    def __init__(self, code: ProviderErrorCode, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class CoverageSummary(ContractModel):
    skill_name: NonEmptyStr
    skill_version: NonEmptyStr
    status: CoverageStatus
    error_code: NonEmptyStr | None


class DiffAnalyzerContext(ContractModel):
    schema_name: Literal["DiffAnalyzerContext"] = "DiffAnalyzerContext"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    input_artifact_ids: tuple[NonEmptyStr, ...] = Field(min_length=1)
    diff_hash: NonEmptyStr
    files: tuple[FileChange, ...] = Field(min_length=1)
    lines: tuple[AgentContextLine, ...] = Field(min_length=1)
    total_additions: int = Field(ge=0)
    total_deletions: int = Field(ge=0)
    changed_lines: int = Field(ge=0)
    unsupported_files: tuple[NonEmptyStr, ...]
    parser_version: NonEmptyStr

    @model_validator(mode="after")
    def totals_must_match_files(self) -> Self:
        if self.total_additions != sum(item.additions for item in self.files):
            raise ValueError("total_additions must match file metadata")
        if self.total_deletions != sum(item.deletions for item in self.files):
            raise ValueError("total_deletions must match file metadata")
        if self.changed_lines != self.total_additions + self.total_deletions:
            raise ValueError("changed_lines must match additions plus deletions")
        _require_unique_line_refs(self.lines)
        return self

    @classmethod
    def from_artifacts(
        cls,
        artifact: GitDiffArtifact,
        sanitized: SanitizedDiffView,
    ) -> DiffAnalyzerContext:
        _validate_sanitized_boundary(artifact, sanitized)
        lines = _context_lines(sanitized)
        if not lines:
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "The sanitized diff has no eligible Python lines.",
            )
        return cls(
            review_id=artifact.review_id,
            input_artifact_ids=(_git_artifact_id(artifact),),
            diff_hash=artifact.diff_hash,
            files=tuple(item.change for item in artifact.files),
            lines=lines,
            total_additions=artifact.total_additions,
            total_deletions=artifact.total_deletions,
            changed_lines=artifact.changed_lines,
            unsupported_files=artifact.unsupported_files,
            parser_version=artifact.parser_version,
        )


class SecurityReviewerContext(ContractModel):
    schema_name: Literal["SecurityReviewerContext"] = "SecurityReviewerContext"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    input_artifact_ids: tuple[NonEmptyStr, ...] = Field(min_length=2)
    diff_hash: NonEmptyStr
    lines: tuple[AgentContextLine, ...] = Field(min_length=1)
    deterministic_findings: tuple[DeterministicFindingSummary, ...]
    deterministic_coverage: tuple[CoverageSummary, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def references_must_be_local(self) -> Self:
        valid_refs = {line.line_ref for line in self.lines}
        if any(
            line_ref not in valid_refs
            for finding in self.deterministic_findings
            for line_ref in finding.line_refs
        ):
            raise ValueError("deterministic summaries must reference local context lines")
        _require_unique_line_refs(self.lines)
        return self

    @classmethod
    def from_scan(
        cls,
        artifact: GitDiffArtifact,
        scan: SecurityScanResult,
    ) -> SecurityReviewerContext:
        if scan.review_id != artifact.review_id:
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "Security scan review_id does not match the Git artifact.",
            )
        _validate_sanitized_boundary(artifact, scan.sanitized_diff)
        lines = _context_lines(scan.sanitized_diff)
        if not lines:
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "The sanitized security context has no eligible Python lines.",
            )
        line_refs_by_location = {
            (line.file_path, line.hunk_id, line.side, line.line_number): line.line_ref
            for line in lines
        }
        evidence_by_id = {item.evidence_id: item for item in scan.evidence}
        summaries = []
        for finding in scan.findings:
            refs = tuple(
                line_refs_by_location[key]
                for location in finding.locations
                if (
                    key := (
                        location.file_path,
                        location.hunk_id,
                        location.side,
                        location.start_line,
                    )
                )
                in line_refs_by_location
            )
            if not refs:
                continue
            levels = tuple(
                dict.fromkeys(
                    evidence_by_id[evidence_id].level.value
                    for evidence_id in finding.evidence_ids
                    if evidence_id in evidence_by_id
                )
            )
            summaries.append(
                DeterministicFindingSummary(
                    finding_id=finding.finding_id,
                    category=finding.category,
                    severity=finding.severity,
                    title=finding.title,
                    claim=finding.claim,
                    line_refs=refs,
                    evidence_levels=levels,
                )
            )
        coverage = tuple(
            CoverageSummary(
                skill_name=item.skill_name,
                skill_version=item.skill_version,
                status=item.status,
                error_code=item.error_code,
            )
            for item in scan.coverage
        )
        return cls(
            review_id=artifact.review_id,
            input_artifact_ids=(
                _git_artifact_id(artifact),
                stable_id("security-scan", artifact.diff_hash, scan.schema_version),
            ),
            diff_hash=artifact.diff_hash,
            lines=lines,
            deterministic_findings=tuple(summaries),
            deterministic_coverage=coverage,
        )


class QualityReviewerContext(ContractModel):
    schema_name: Literal["QualityReviewerContext"] = "QualityReviewerContext"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    input_artifact_ids: tuple[NonEmptyStr, ...] = Field(min_length=1)
    diff_hash: NonEmptyStr
    lines: tuple[AgentContextLine, ...] = Field(min_length=1)
    ruff_summary: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=2000),
    ]

    @model_validator(mode="after")
    def line_refs_must_be_unique(self) -> Self:
        _require_unique_line_refs(self.lines)
        return self

    @classmethod
    def from_artifacts(
        cls,
        artifact: GitDiffArtifact,
        sanitized: SanitizedDiffView,
        *,
        ruff_summary: str,
    ) -> QualityReviewerContext:
        _validate_sanitized_boundary(artifact, sanitized)
        lines = _context_lines(sanitized)
        if not lines:
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "The sanitized quality context has no eligible Python lines.",
            )
        return cls(
            review_id=artifact.review_id,
            input_artifact_ids=(_git_artifact_id(artifact),),
            diff_hash=artifact.diff_hash,
            lines=lines,
            ruff_summary=ruff_summary,
        )


def _validate_sanitized_boundary(
    artifact: GitDiffArtifact,
    sanitized: SanitizedDiffView,
) -> None:
    if sanitized.review_id != artifact.review_id:
        raise ContextBuildError(
            ProviderErrorCode.CONTEXT_INVALID,
            "Sanitized diff review_id does not match the Git artifact.",
        )
    if sanitized.source_diff_hash != artifact.diff_hash:
        raise ContextBuildError(
            ProviderErrorCode.CONTEXT_INVALID,
            "Sanitized diff hash does not match the Git artifact.",
        )
    if not sanitized.cloud_safe:
        raise ContextBuildError(
            ProviderErrorCode.CONTEXT_UNSAFE,
            "The diff is not approved for cloud model use.",
        )
    expected_lines = iter_source_lines(
        artifact,
        python_only=True,
        include_context=True,
        include_deletions=True,
    )
    expected_keys = tuple(_source_line_key(item) for item in expected_lines)
    actual_keys = tuple(_sanitized_line_key(item) for item in sanitized.lines)
    if actual_keys != expected_keys:
        raise ContextBuildError(
            ProviderErrorCode.CONTEXT_INVALID,
            "Sanitized diff line provenance does not match the Git artifact.",
        )
    applied_redaction_ids = tuple(
        dict.fromkeys(
            redaction_id for line in sanitized.lines for redaction_id in line.redaction_ids
        )
    )
    if applied_redaction_ids != sanitized.redaction_ids:
        raise ContextBuildError(
            ProviderErrorCode.CONTEXT_INVALID,
            "Sanitized diff redaction lineage is inconsistent.",
        )
    for source_line, sanitized_line in zip(expected_lines, sanitized.lines, strict=True):
        if sanitized_line.source_content_hash != content_hash(source_line.content):
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "Sanitized diff source hash does not match the Git artifact.",
            )
        if sanitized_line.content_hash != content_hash(sanitized_line.content):
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "Sanitized diff content hash is invalid.",
            )
        if sanitized_line.redaction_ids:
            if not _is_redaction_only(source_line.content, sanitized_line.content):
                raise ContextBuildError(
                    ProviderErrorCode.CONTEXT_INVALID,
                    "Sanitized diff contains an invalid redaction transformation.",
                )
        elif sanitized_line.content != source_line.content:
            raise ContextBuildError(
                ProviderErrorCode.CONTEXT_INVALID,
                "Unredacted sanitized content differs from the Git artifact.",
            )


def _git_artifact_id(artifact: GitDiffArtifact) -> str:
    return stable_id("git-diff", artifact.review_id, artifact.diff_hash)


def _context_lines(sanitized: SanitizedDiffView) -> tuple[AgentContextLine, ...]:
    return tuple(
        AgentContextLine(
            line_ref=stable_id(
                "line",
                sanitized.source_diff_hash,
                item.file_path,
                item.hunk_id,
                item.side,
                item.line_number,
                item.content_hash,
            ),
            file_path=item.file_path,
            hunk_id=item.hunk_id,
            kind=item.kind,
            side=item.side,
            line_number=item.line_number,
            content=item.content,
            content_hash=item.content_hash,
        )
        for item in sanitized.lines
    )


def _source_line_key(line: SourceLine) -> tuple[str, str, object, str, int]:
    return (line.file_path, line.hunk_id, line.kind, line.side, line.line_number)


def _sanitized_line_key(line) -> tuple[str, str, object, str, int]:
    return (line.file_path, line.hunk_id, line.kind, line.side, line.line_number)


def _is_redaction_only(source: str, sanitized: str) -> bool:
    matches = tuple(_REDACTION_TOKEN.finditer(sanitized))
    if not matches:
        return False
    pattern_parts: list[str] = []
    prefixes: list[str] = []
    cursor = 0
    for match in matches:
        pattern_parts.append(re.escape(sanitized[cursor : match.start()]))
        pattern_parts.append("(.+?)")
        prefixes.append(match.group(1))
        cursor = match.end()
    pattern_parts.append(re.escape(sanitized[cursor:]))
    source_match = re.fullmatch("".join(pattern_parts), source, flags=re.DOTALL)
    if source_match is None:
        return False
    return all(
        hashlib.sha256(value.encode("utf-8")).hexdigest().startswith(prefix)
        for value, prefix in zip(source_match.groups(), prefixes, strict=True)
    )


def _require_unique_line_refs(lines: tuple[AgentContextLine, ...]) -> None:
    refs = tuple(line.line_ref for line in lines)
    if len(refs) != len(set(refs)):
        raise ValueError("Agent context line_refs must be unique")
