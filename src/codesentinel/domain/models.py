"""Pydantic v2 implementations of the twelve frozen CodeSentinel schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .enums import (
    ChangeType,
    CoverageStatus,
    EvidenceLevel,
    EvidenceSource,
    FindingStatus,
    GateStatus,
    RiskCategory,
    Severity,
    SkillStatus,
)

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
ShortSummary = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1000),
]
RelativePath = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
SystemRiskCategories = frozenset({RiskCategory.SCOPE_LIMIT, RiskCategory.TOOL_FAILURE})


def _require_unique(
    values: tuple[str, ...],
    field_name: str,
) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return values


def _validate_relative_posix_path(value: str) -> str:
    windows_path = PureWindowsPath(value)
    if (
        "\\" in value
        or value.startswith("/")
        or "//" in value
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ":" in value
        or "\x00" in value
    ):
        raise ValueError("path must be a repository-relative POSIX path")
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts) or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError("path must not contain empty, current, or parent segments")
    return value


def _validate_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware UTC")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError("datetime must use UTC")
    return value.astimezone(UTC)


class ContractModel(BaseModel):
    """Shared strictness for every public and nested contract."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class ReviewRequest(ContractModel):
    repository_path: NonEmptyStr
    base_revision: NonEmptyStr = "HEAD"
    target_revision: NonEmptyStr | None = None
    include_staged: bool = True
    include_unstaged: bool = True
    include_untracked: bool = False
    max_changed_lines: int = Field(default=1000, ge=1, le=5000)
    policy_version: NonEmptyStr = "mvp-1.0.0"
    request_source: Literal["local_cli"] = "local_cli"

    @field_validator("repository_path")
    @classmethod
    def repository_path_must_be_absolute(cls, value: str) -> str:
        if not (Path(value).is_absolute() or PureWindowsPath(value).is_absolute()):
            raise ValueError("repository_path must be absolute")
        return value


class CodeLocation(ContractModel):
    file_path: RelativePath
    start_line: int = Field(gt=0)
    end_line: int = Field(gt=0)
    side: Literal["old", "new"]
    hunk_id: NonEmptyStr
    snippet_hash: NonEmptyStr

    @field_validator("file_path")
    @classmethod
    def file_path_must_be_relative_posix(cls, value: str) -> str:
        return _validate_relative_posix_path(value)

    @model_validator(mode="after")
    def end_line_must_follow_start_line(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class FileChange(ContractModel):
    file_id: NonEmptyStr
    old_path: RelativePath | None
    new_path: RelativePath | None
    change_type: ChangeType
    language: Literal["python", "unknown"]
    additions: int = Field(ge=0)
    deletions: int = Field(ge=0)
    is_binary: bool
    content_hash: NonEmptyStr
    hunk_ids: tuple[NonEmptyStr, ...]

    @field_validator("old_path", "new_path")
    @classmethod
    def paths_must_be_relative_posix(cls, value: str | None) -> str | None:
        return None if value is None else _validate_relative_posix_path(value)

    @field_validator("hunk_ids")
    @classmethod
    def hunk_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_unique(value, "hunk_ids")

    @model_validator(mode="after")
    def paths_must_match_change_type(self) -> Self:
        if self.change_type is ChangeType.ADDED:
            if self.old_path is not None or self.new_path is None:
                raise ValueError("added files require new_path and forbid old_path")
        elif self.change_type is ChangeType.DELETED:
            if self.old_path is None or self.new_path is not None:
                raise ValueError("deleted files require old_path and forbid new_path")
        elif self.change_type is ChangeType.MODIFIED:
            if (
                self.old_path is None
                or self.new_path is None
                or self.old_path != self.new_path
            ):
                raise ValueError("modified files require identical old_path and new_path")
        elif self.change_type is ChangeType.RENAMED:
            if (
                self.old_path is None
                or self.new_path is None
                or self.old_path == self.new_path
            ):
                raise ValueError("renamed files require distinct old_path and new_path")
        return self


class DiffAnalysis(ContractModel):
    review_id: NonEmptyStr
    diff_hash: NonEmptyStr
    files: tuple[FileChange, ...] = Field(min_length=1)
    total_additions: int = Field(ge=0)
    total_deletions: int = Field(ge=0)
    changed_lines: int = Field(ge=0)
    summary: ShortSummary
    change_intents: tuple[NonEmptyStr, ...]
    affected_symbols: tuple[NonEmptyStr, ...]
    truncated: bool
    unsupported_files: tuple[RelativePath, ...]
    parser_version: NonEmptyStr

    @field_validator("change_intents", "affected_symbols", "unsupported_files")
    @classmethod
    def string_lists_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "list")

    @field_validator("unsupported_files")
    @classmethod
    def unsupported_paths_must_be_relative_posix(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(_validate_relative_posix_path(item) for item in value)

    @model_validator(mode="after")
    def totals_and_ids_must_be_consistent(self) -> Self:
        file_ids = [item.file_id for item in self.files]
        if len(file_ids) != len(set(file_ids)):
            raise ValueError("file_id must be unique within a review")
        hunk_ids = [hunk_id for item in self.files for hunk_id in item.hunk_ids]
        if len(hunk_ids) != len(set(hunk_ids)):
            raise ValueError("hunk_id must be unique within a review")
        if self.total_additions != sum(item.additions for item in self.files):
            raise ValueError("total_additions must equal the sum of file additions")
        if self.total_deletions != sum(item.deletions for item in self.files):
            raise ValueError("total_deletions must equal the sum of file deletions")
        if self.changed_lines != self.total_additions + self.total_deletions:
            raise ValueError("changed_lines must equal additions plus deletions")
        return self


class RiskRoute(ContractModel):
    route_id: NonEmptyStr
    category: RiskCategory
    severity_hint: Severity
    locations: tuple[CodeLocation, ...] = Field(min_length=1)
    required_skills: tuple[NonEmptyStr, ...] = Field(min_length=1)
    reason: NonEmptyStr
    mandatory: bool
    route_source: Literal["rule", "llm", "hybrid"]

    @field_validator("required_skills")
    @classmethod
    def required_skills_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "required_skills")


class SkippedCandidate(ContractModel):
    skill: NonEmptyStr
    reason: NonEmptyStr


class RiskMap(ContractModel):
    review_id: NonEmptyStr
    routes: tuple[RiskRoute, ...]
    always_on_skills: tuple[NonEmptyStr, ...] = Field(min_length=1)
    planned_skill_count: int = Field(ge=1)
    skipped_candidates: tuple[SkippedCandidate, ...]
    model_used: bool

    @field_validator("always_on_skills")
    @classmethod
    def always_on_skills_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "always_on_skills")

    @model_validator(mode="after")
    def plan_must_be_consistent(self) -> Self:
        route_ids = [route.route_id for route in self.routes]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("route_id must be unique within a review")
        if "detect_secret" not in self.always_on_skills:
            raise ValueError("always_on_skills must contain detect_secret")
        planned_skills = set(self.always_on_skills)
        for route in self.routes:
            planned_skills.update(route.required_skills)
        if self.planned_skill_count != len(planned_skills):
            raise ValueError("planned_skill_count must equal the unique planned skills")
        return self


class Evidence(ContractModel):
    evidence_id: NonEmptyStr
    level: EvidenceLevel
    source: EvidenceSource
    detector_name: NonEmptyStr
    detector_version: NonEmptyStr
    summary: NonEmptyStr
    location: CodeLocation | None = None
    reproducible: bool
    confidence: float = Field(ge=0, le=1)
    artifact_ref: RelativePath | None = None
    content_hash: NonEmptyStr
    created_at: datetime

    @field_validator("artifact_ref")
    @classmethod
    def artifact_ref_must_be_relative_posix(cls, value: str | None) -> str | None:
        return None if value is None else _validate_relative_posix_path(value)

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @model_validator(mode="after")
    def level_must_match_source_and_reproducibility(self) -> Self:
        if self.source is EvidenceSource.LLM and self.level not in {
            EvidenceLevel.E0,
            EvidenceLevel.E1,
        }:
            raise ValueError("LLM evidence cannot exceed E1")
        if self.level is EvidenceLevel.E3:
            if not self.reproducible:
                raise ValueError("E3 evidence must be reproducible")
            if self.source is not EvidenceSource.SYSTEM and self.location is None:
                raise ValueError("non-system E3 evidence must have a location")
        return self


class Finding(ContractModel):
    finding_id: NonEmptyStr
    category: RiskCategory
    title: NonEmptyStr
    claim: NonEmptyStr
    severity: Severity
    status: FindingStatus
    locations: tuple[CodeLocation, ...]
    evidence_ids: tuple[NonEmptyStr, ...]
    confidence: float = Field(ge=0, le=1)
    recommendation: NonEmptyStr
    agent_id: NonEmptyStr
    fingerprint: NonEmptyStr

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "evidence_ids")

    @model_validator(mode="after")
    def risk_and_status_must_have_support(self) -> Self:
        if self.category not in SystemRiskCategories and not self.locations:
            raise ValueError("non-system findings require at least one location")
        if self.status in {FindingStatus.CONFIRMED, FindingStatus.SUSPECTED}:
            if not self.evidence_ids:
                raise ValueError("confirmed and suspected findings require evidence")
        return self


class CoverageRecord(ContractModel):
    coverage_id: NonEmptyStr
    skill_name: NonEmptyStr
    skill_version: NonEmptyStr
    status: CoverageStatus
    mandatory: bool
    route_ids: tuple[NonEmptyStr, ...]
    files_checked: tuple[RelativePath, ...]
    reason: NonEmptyStr
    error_code: NonEmptyStr | None
    duration_ms: int = Field(ge=0)

    @field_validator("route_ids", "files_checked")
    @classmethod
    def coverage_lists_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "coverage list")

    @field_validator("files_checked")
    @classmethod
    def files_checked_must_be_relative_posix(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(_validate_relative_posix_path(item) for item in value)

    @model_validator(mode="after")
    def failures_must_have_error_codes(self) -> Self:
        if self.status is CoverageStatus.FAILED and self.error_code is None:
            raise ValueError("failed coverage requires error_code")
        if self.status is not CoverageStatus.FAILED and self.error_code is not None:
            raise ValueError("only failed coverage may contain error_code")
        return self


class AgentArtifact(ContractModel):
    artifact_id: NonEmptyStr
    review_id: NonEmptyStr
    agent_id: NonEmptyStr
    agent_role: NonEmptyStr
    schema_name: NonEmptyStr
    schema_version: NonEmptyStr = "1.0.0"
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage: tuple[CoverageRecord, ...] = Field(min_length=1)
    summary: ShortSummary
    input_artifact_ids: tuple[NonEmptyStr, ...]
    model_name: NonEmptyStr | None
    prompt_version: NonEmptyStr | None
    started_at: datetime
    completed_at: datetime
    status: SkillStatus

    @field_validator("input_artifact_ids")
    @classmethod
    def input_artifact_ids_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "input_artifact_ids")

    @field_validator("started_at", "completed_at")
    @classmethod
    def artifact_times_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @model_validator(mode="after")
    def artifact_must_be_internally_consistent(self) -> Self:
        for field_name, values in (
            ("finding_id", [item.finding_id for item in self.findings]),
            ("evidence_id", [item.evidence_id for item in self.evidence]),
            ("coverage_id", [item.coverage_id for item in self.coverage]),
            ("fingerprint", [item.fingerprint for item in self.findings]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique within an artifact")
        if self.artifact_id in self.input_artifact_ids:
            raise ValueError("an artifact cannot reference itself")
        if (self.model_name is None) != (self.prompt_version is None):
            raise ValueError("model_name and prompt_version must both be set or both be null")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        local_evidence_ids = {item.evidence_id for item in self.evidence}
        dangling = {
            evidence_id
            for finding in self.findings
            for evidence_id in finding.evidence_ids
            if evidence_id not in local_evidence_ids
        }
        if dangling:
            raise ValueError("finding evidence_ids must reference evidence in the artifact")
        return self


ConflictType = Literal[
    "contradiction",
    "severity_mismatch",
    "location_mismatch",
    "coverage_gap",
]


class EvidenceConflict(ContractModel):
    conflict_id: NonEmptyStr
    finding_ids: tuple[NonEmptyStr, ...] = Field(min_length=1)
    rule_ids: tuple[NonEmptyStr, ...]
    type: ConflictType
    description: NonEmptyStr
    requires_recheck: bool
    resolved: bool = False
    resolution: NonEmptyStr | None

    @field_validator("finding_ids", "rule_ids")
    @classmethod
    def reference_ids_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "conflict reference IDs")

    @model_validator(mode="after")
    def resolution_must_match_status(self) -> Self:
        if len(self.finding_ids) + len(self.rule_ids) < 2:
            raise ValueError(
                "conflicts require two findings or one finding plus a rule"
            )
        if self.resolved and self.resolution is None:
            raise ValueError("resolved conflicts require resolution")
        if not self.resolved and self.resolution is not None:
            raise ValueError("unresolved conflicts cannot contain resolution")
        return self


class EvidenceIndexEntry(ContractModel):
    finding_id: NonEmptyStr
    evidence_ids: tuple[NonEmptyStr, ...]

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "evidence_ids")


class GateDecision(ContractModel):
    review_id: NonEmptyStr
    status: GateStatus
    policy_version: NonEmptyStr = "mvp-1.0.0"
    matched_rule_ids: tuple[NonEmptyStr, ...] = Field(min_length=1)
    blocking_finding_ids: tuple[NonEmptyStr, ...]
    review_finding_ids: tuple[NonEmptyStr, ...]
    warning_finding_ids: tuple[NonEmptyStr, ...]
    coverage_complete: bool
    unresolved_conflict_ids: tuple[NonEmptyStr, ...]
    reason_summary: NonEmptyStr
    manual_actions: tuple[NonEmptyStr, ...]
    evidence_index: tuple[EvidenceIndexEntry, ...]
    trace_id: NonEmptyStr
    decided_at: datetime

    @field_validator(
        "matched_rule_ids",
        "blocking_finding_ids",
        "review_finding_ids",
        "warning_finding_ids",
        "unresolved_conflict_ids",
        "manual_actions",
    )
    @classmethod
    def decision_lists_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_unique(value, "decision list")

    @field_validator("decided_at")
    @classmethod
    def decided_at_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @model_validator(mode="after")
    def fields_must_match_status(self) -> Self:
        indexed_findings = [item.finding_id for item in self.evidence_index]
        if len(indexed_findings) != len(set(indexed_findings)):
            raise ValueError("evidence_index finding_id values must be unique")
        decision_buckets = (
            set(self.blocking_finding_ids),
            set(self.review_finding_ids),
            set(self.warning_finding_ids),
        )
        if any(
            left & right
            for index, left in enumerate(decision_buckets)
            for right in decision_buckets[index + 1 :]
        ):
            raise ValueError("blocking, review, and warning finding IDs must be disjoint")
        classified_findings = set().union(*decision_buckets)
        if classified_findings - set(indexed_findings):
            raise ValueError("every classified finding must appear in evidence_index")
        if self.status is GateStatus.PASS:
            if self.matched_rule_ids != ("P001",):
                raise ValueError("PASS must match only P001")
            if not self.coverage_complete:
                raise ValueError("PASS requires complete coverage")
            if (
                self.blocking_finding_ids
                or self.review_finding_ids
                or self.unresolved_conflict_ids
                or self.manual_actions
            ):
                raise ValueError("PASS cannot contain blocking, review, conflict, or manual IDs")
        elif self.status is GateStatus.BLOCK:
            if not any(rule_id.startswith("B") for rule_id in self.matched_rule_ids):
                raise ValueError("BLOCK requires a B rule")
            if any(
                not rule_id.startswith(("B", "N"))
                for rule_id in self.matched_rule_ids
            ):
                raise ValueError("BLOCK may contain only B and N rules")
            if not self.blocking_finding_ids:
                raise ValueError("BLOCK requires at least one blocking finding")
        elif self.status is GateStatus.NEEDS_REVIEW:
            if any(
                not rule_id.startswith("N") for rule_id in self.matched_rule_ids
            ):
                raise ValueError("NEEDS_REVIEW may contain only N rules")
            if self.blocking_finding_ids:
                raise ValueError("NEEDS_REVIEW cannot contain blocking findings")
            if not self.manual_actions:
                raise ValueError("NEEDS_REVIEW requires at least one manual action")
        elif self.status is GateStatus.FAILED:
            if any(
                not rule_id.startswith("F") for rule_id in self.matched_rule_ids
            ):
                raise ValueError("FAILED may contain only F rules")
            if self.coverage_complete or self.blocking_finding_ids:
                raise ValueError("FAILED cannot claim complete coverage or blocking findings")
        return self
