"""Cloud-safe, role-isolated context artifacts for AgentTeams Workers."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from .models import Sha256
from .role_models import NonEmptyStr, RoleName, RolePayloadModel, SeverityValue
from .serialization import canonical_json_bytes

LineReference = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
RelativePath = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
EvidenceLevelValue = Literal["E0", "E1", "E2", "E3"]
RiskCategoryValue = Literal[
    "secret",
    "sql_injection",
    "command_injection",
    "dangerous_call",
    "auth_boundary",
    "logic",
    "exception_handling",
    "performance",
    "test_gap",
    "scope_limit",
    "tool_failure",
]


def _validate_relative_path(value: str) -> str:
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
        raise ValueError("context path must be repository-relative POSIX")
    path = PurePosixPath(value)
    if path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("context path contains an unsafe segment")
    return value


class WorkerContextLine(RolePayloadModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    line_ref: LineReference
    file_path: RelativePath
    hunk_id: NonEmptyStr
    kind: Literal["context", "addition", "deletion"]
    side: Literal["old", "new"]
    line_number: int = Field(ge=1)
    content: str
    content_hash: Sha256

    @field_validator("file_path")
    @classmethod
    def file_path_must_be_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @model_validator(mode="after")
    def content_hash_must_match_content(self) -> WorkerContextLine:
        if hashlib.sha256(self.content.encode("utf-8")).hexdigest() != self.content_hash:
            raise ValueError("context line content_hash does not match content")
        return self


class DiffContextMetadata(RolePayloadModel):
    diff_hash: Sha256
    changed_files: tuple[RelativePath, ...] = Field(min_length=1)
    total_additions: int = Field(ge=0)
    total_deletions: int = Field(ge=0)
    unsupported_files: tuple[RelativePath, ...]
    parser_version: NonEmptyStr

    @field_validator("changed_files", "unsupported_files")
    @classmethod
    def paths_must_be_safe_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("context paths must be unique")
        return tuple(_validate_relative_path(item) for item in value)


class DeterministicFindingContext(RolePayloadModel):
    finding_id: NonEmptyStr
    category: RiskCategoryValue
    severity: SeverityValue
    title: NonEmptyStr
    claim: NonEmptyStr
    line_refs: tuple[LineReference, ...] = Field(min_length=1, max_length=10)
    evidence_levels: tuple[EvidenceLevelValue, ...] = Field(min_length=1, max_length=4)

    @field_validator("line_refs", "evidence_levels")
    @classmethod
    def tuple_values_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("context tuple values must be unique")
        return value


class DeterministicCoverageContext(RolePayloadModel):
    skill_name: NonEmptyStr
    skill_version: NonEmptyStr
    status: Literal["completed", "skipped", "failed", "not_applicable"]
    error_code: NonEmptyStr | None

    @model_validator(mode="after")
    def failure_must_match_error_code(self) -> DeterministicCoverageContext:
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed deterministic coverage requires error_code")
        if self.status != "failed" and self.error_code is not None:
            raise ValueError("only failed deterministic coverage may have error_code")
        return self


class SecurityContextMetadata(RolePayloadModel):
    diff_hash: Sha256
    deterministic_findings: tuple[DeterministicFindingContext, ...]
    deterministic_coverage: tuple[DeterministicCoverageContext, ...] = Field(min_length=3)

    @field_validator("deterministic_coverage")
    @classmethod
    def coverage_skills_must_be_unique(
        cls,
        value: tuple[DeterministicCoverageContext, ...],
    ) -> tuple[DeterministicCoverageContext, ...]:
        names = tuple(item.skill_name for item in value)
        if len(names) != len(set(names)):
            raise ValueError("deterministic coverage skills must be unique")
        return value


class QualityContextMetadata(RolePayloadModel):
    diff_hash: Sha256
    ruff_summary: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=2000),
    ]


ROLE_CONTEXT_MODELS: dict[RoleName, type[RolePayloadModel]] = {
    "diff_analyzer": DiffContextMetadata,
    "security_scanner": SecurityContextMetadata,
    "quality_reviewer": QualityContextMetadata,
}


class RoleContextArtifact(RolePayloadModel):
    schema_name: Literal["CodeSentinelAgentTeamsRoleContext"] = (
        "CodeSentinelAgentTeamsRoleContext"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    role: RoleName
    source_artifact_ids: tuple[NonEmptyStr, ...] = Field(min_length=1)
    lines: tuple[WorkerContextLine, ...] = Field(min_length=1)
    metadata: dict[str, object] = Field(min_length=1)
    cloud_safe: Literal[True]

    @model_validator(mode="after")
    def context_must_match_role_and_local_lines(self) -> RoleContextArtifact:
        if len(self.source_artifact_ids) != len(set(self.source_artifact_ids)):
            raise ValueError("source_artifact_ids must be unique")
        expected_source_count = 2 if self.role == "security_scanner" else 1
        if len(self.source_artifact_ids) != expected_source_count:
            raise ValueError("source artifact count does not match Worker role")
        line_refs = tuple(line.line_ref for line in self.lines)
        if len(line_refs) != len(set(line_refs)):
            raise ValueError("role context line_refs must be unique")
        parsed = self.parsed_metadata()
        diff_hash = getattr(parsed, "diff_hash")
        for line in self.lines:
            material = "\0".join(
                str(part)
                for part in (
                    diff_hash,
                    line.file_path,
                    line.hunk_id,
                    line.side,
                    line.line_number,
                    line.content_hash,
                )
            )
            expected_ref = (
                f"line-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
            )
            if line.line_ref != expected_ref:
                raise ValueError("context line_ref does not derive from trusted line data")
        if isinstance(parsed, SecurityContextMetadata):
            coverage_names = {item.skill_name for item in parsed.deterministic_coverage}
            if coverage_names != {
                "detect_secret",
                "detect_injection",
                "detect_dangerous_call",
            }:
                raise ValueError("security context lacks the frozen deterministic coverage")
            valid_refs = set(line_refs)
            if any(
                line_ref not in valid_refs
                for finding in parsed.deterministic_findings
                for line_ref in finding.line_refs
            ):
                raise ValueError("deterministic findings reference a foreign context line")
        return self

    def parsed_metadata(self) -> RolePayloadModel:
        model = ROLE_CONTEXT_MODELS[self.role]
        return model.model_validate_json(canonical_json_bytes(self.metadata))

    @property
    def allowed_line_refs(self) -> frozenset[str]:
        return frozenset(line.line_ref for line in self.lines)
