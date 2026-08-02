"""Strict P6 contracts shared by deterministic security Skills."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from codesentinel.domain import (
    CoverageRecord,
    Evidence,
    EvidenceLevel,
    Finding,
    SkillStatus,
)
from codesentinel.domain.models import ContractModel
from codesentinel.gitdiff import DiffLineKind

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class SkillErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    CONTEXT_INSUFFICIENT = "CONTEXT_INSUFFICIENT"
    TIMEOUT = "TIMEOUT"
    TOOL_ERROR = "TOOL_ERROR"
    MODEL_ERROR = "MODEL_ERROR"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    POLICY_ERROR = "POLICY_ERROR"


class SkillManifest(ContractModel):
    name: Literal["detect_secret", "detect_injection", "detect_dangerous_call"]
    version: Literal["1.0.0", "1.1.0"] = "1.0.0"
    purpose: NonEmptyStr
    owner_agent: Literal["security-scanner"] = "security-scanner"
    allowed_stage: Literal["reviews_running"] = "reviews_running"
    input_schema: Literal["GitDiffArtifact@1.0.0"] = "GitDiffArtifact@1.0.0"
    output_schema: Literal["SecuritySkillResult@1.0.0"] = (
        "SecuritySkillResult@1.0.0"
    )
    trigger: NonEmptyStr
    dependencies: tuple[NonEmptyStr, ...]
    permissions: tuple[Literal["provided_diff_only", "temporary_local_file"], ...]
    deterministic: Literal[True] = True
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    max_retries: Literal[0] = 0
    cancellable: Literal[True] = True
    failure_behavior: Literal["emit_e0_and_failed_coverage"] = (
        "emit_e0_and_failed_coverage"
    )
    safety: NonEmptyStr
    reuse: NonEmptyStr
    rollback_version: Literal["none-initial-release"] = "none-initial-release"

    @field_validator("dependencies", "permissions")
    @classmethod
    def tuple_values_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("manifest tuple values must be unique")
        return value


class RedactionRecord(ContractModel):
    redaction_id: NonEmptyStr
    file_path: NonEmptyStr
    hunk_id: NonEmptyStr
    side: Literal["old", "new"]
    line_number: int = Field(ge=1)
    secret_type: NonEmptyStr
    secret_fingerprint: NonEmptyStr
    masked_content: str

    @model_validator(mode="after")
    def masked_content_must_not_embed_fingerprint(self) -> Self:
        if self.secret_fingerprint in self.masked_content:
            raise ValueError("masked content must not contain the full secret fingerprint")
        return self


class SanitizedDiffLine(ContractModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    file_path: NonEmptyStr
    hunk_id: NonEmptyStr
    kind: DiffLineKind
    side: Literal["old", "new"]
    line_number: int = Field(ge=1)
    content: str
    source_content_hash: Sha256
    content_hash: Sha256
    redaction_ids: tuple[NonEmptyStr, ...] = ()

    @field_validator("redaction_ids")
    @classmethod
    def line_redaction_ids_must_be_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("line redaction_ids must be unique")
        return value

    @model_validator(mode="after")
    def hashes_and_redaction_state_must_match(self) -> Self:
        if hashlib.sha256(self.content.encode("utf-8")).hexdigest() != self.content_hash:
            raise ValueError("content_hash must match sanitized line content")
        if not self.redaction_ids and self.source_content_hash != self.content_hash:
            raise ValueError("unredacted line content must match its source hash")
        if self.redaction_ids and self.source_content_hash == self.content_hash:
            raise ValueError("redacted line content must differ from its source")
        return self


class SanitizedDiffView(ContractModel):
    schema_name: Literal["SanitizedDiffView"] = "SanitizedDiffView"
    schema_version: Literal["1.1.0"] = "1.1.0"
    review_id: NonEmptyStr
    source_diff_hash: NonEmptyStr
    lines: tuple[SanitizedDiffLine, ...]
    redaction_ids: tuple[NonEmptyStr, ...]
    cloud_safe: bool
    reason: NonEmptyStr

    @field_validator("redaction_ids")
    @classmethod
    def redaction_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("redaction_ids must be unique")
        return value

    @model_validator(mode="after")
    def unsafe_views_must_not_expose_source_lines(self) -> Self:
        if not self.cloud_safe and self.lines:
            raise ValueError("unsafe sanitized views must not expose source lines")
        line_keys = tuple(
            (item.file_path, item.hunk_id, item.side, item.line_number)
            for item in self.lines
        )
        if len(line_keys) != len(set(line_keys)):
            raise ValueError("sanitized line locations must be unique")
        if self.cloud_safe:
            applied_ids = tuple(
                dict.fromkeys(
                    redaction_id
                    for item in self.lines
                    for redaction_id in item.redaction_ids
                )
            )
            if self.redaction_ids != applied_ids:
                raise ValueError("view redaction_ids must match exposed line redactions")
        return self


class SecuritySkillResult(ContractModel):
    schema_name: Literal["SecuritySkillResult"] = "SecuritySkillResult"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    manifest: SkillManifest
    status: SkillStatus
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage: CoverageRecord
    verified_e3_evidence_ids: tuple[NonEmptyStr, ...]
    redactions: tuple[RedactionRecord, ...]
    started_at: datetime
    completed_at: datetime

    @field_validator("started_at", "completed_at")
    @classmethod
    def times_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Skill timestamps must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("Skill timestamps must use UTC")
        return value.astimezone(UTC)

    @field_validator("verified_e3_evidence_ids")
    @classmethod
    def verified_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("verified E3 IDs must be unique")
        return value

    @model_validator(mode="after")
    def result_must_be_internally_consistent(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.coverage.skill_name != self.manifest.name:
            raise ValueError("coverage skill_name must match the manifest")
        if self.coverage.skill_version != self.manifest.version:
            raise ValueError("coverage skill_version must match the manifest")
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("evidence IDs must be unique")
        finding_ids = {item.finding_id for item in self.findings}
        if len(finding_ids) != len(self.findings):
            raise ValueError("finding IDs must be unique")
        fingerprints = {item.fingerprint for item in self.findings}
        if len(fingerprints) != len(self.findings):
            raise ValueError("finding fingerprints must be unique")
        if any(
            evidence_id not in evidence_by_id
            for finding in self.findings
            for evidence_id in finding.evidence_ids
        ):
            raise ValueError("findings must reference result evidence")
        for evidence_id in self.verified_e3_evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None or evidence.level is not EvidenceLevel.E3:
                raise ValueError("verified E3 IDs must reference E3 evidence")
        if self.status is SkillStatus.FAILED:
            if self.findings or self.verified_e3_evidence_ids:
                raise ValueError("failed Skills cannot publish findings or verified E3")
            if not any(item.level is EvidenceLevel.E0 for item in self.evidence):
                raise ValueError("failed Skills require E0 evidence")
        return self


class SecurityScanResult(ContractModel):
    schema_name: Literal["SecurityScanResult"] = "SecurityScanResult"
    schema_version: Literal["1.1.0"] = "1.1.0"
    review_id: NonEmptyStr
    status: SkillStatus
    skill_results: tuple[SecuritySkillResult, ...] = Field(min_length=3, max_length=3)
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage: tuple[CoverageRecord, ...] = Field(min_length=3, max_length=3)
    verified_e3_evidence_ids: tuple[NonEmptyStr, ...]
    redactions: tuple[RedactionRecord, ...]
    sanitized_diff: SanitizedDiffView

    @model_validator(mode="after")
    def aggregate_must_match_skill_results(self) -> Self:
        names = tuple(item.manifest.name for item in self.skill_results)
        expected = ("detect_secret", "detect_injection", "detect_dangerous_call")
        if names != expected:
            raise ValueError("security Skill order and membership are frozen")
        if self.coverage != tuple(item.coverage for item in self.skill_results):
            raise ValueError("aggregate coverage must match Skill results")
        if self.findings != tuple(
            finding for item in self.skill_results for finding in item.findings
        ):
            raise ValueError("aggregate findings must match Skill results")
        if self.evidence != tuple(
            proof for item in self.skill_results for proof in item.evidence
        ):
            raise ValueError("aggregate evidence must match Skill results")
        if self.redactions != tuple(
            redaction for item in self.skill_results for redaction in item.redactions
        ):
            raise ValueError("aggregate redactions must match Skill results")
        expected_verified = tuple(
            evidence_id
            for item in self.skill_results
            for evidence_id in item.verified_e3_evidence_ids
        )
        if self.verified_e3_evidence_ids != expected_verified:
            raise ValueError("aggregate verified E3 IDs must match Skill results")
        statuses = {item.status for item in self.skill_results}
        expected_status = (
            SkillStatus.FAILED
            if SkillStatus.FAILED in statuses
            else SkillStatus.PARTIAL
            if statuses & {SkillStatus.PARTIAL, SkillStatus.SKIPPED}
            else SkillStatus.SUCCESS
        )
        if self.status is not expected_status:
            raise ValueError("aggregate status must match Skill results")
        if self.sanitized_diff.review_id != self.review_id:
            raise ValueError("sanitized diff review_id must match the scan")
        evidence_ids = {item.evidence_id for item in self.evidence}
        if set(self.verified_e3_evidence_ids) - evidence_ids:
            raise ValueError("verified E3 registry must reference aggregate evidence")
        return self
