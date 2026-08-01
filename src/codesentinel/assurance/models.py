"""Strict P8 contracts for routing, evidence assurance, and targeted recheck."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from codesentinel.domain import (
    CodeLocation,
    CoverageRecord,
    Evidence,
    EvidenceConflict,
    Finding,
    FindingStatus,
    GateDecision,
    RiskCategory,
    RiskMap,
    Severity,
)
from codesentinel.domain.models import ContractModel


class SemanticRiskHint(ContractModel):
    """An untrusted semantic routing hint; it never controls evidence level."""

    category: RiskCategory
    severity_hint: Severity
    locations: tuple[CodeLocation, ...] = Field(min_length=1, max_length=5)
    reason: str = Field(min_length=1, max_length=500)


class SkillPlanEntry(ContractModel):
    skill_name: str = Field(min_length=1)
    planned: bool
    mandatory: bool
    route_ids: tuple[str, ...]
    reason: str = Field(min_length=1)

    @field_validator("route_ids")
    @classmethod
    def route_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("route_ids must be unique")
        return value

    @model_validator(mode="after")
    def skipped_entries_are_explicit(self) -> SkillPlanEntry:
        if not self.planned and (self.mandatory or self.route_ids):
            raise ValueError("skipped Skills cannot be mandatory or reference routes")
        return self


class RiskRoutingResult(ContractModel):
    schema_name: Literal["RiskRoutingResult"] = "RiskRoutingResult"
    schema_version: Literal["1.0.0"] = "1.0.0"
    risk_map: RiskMap
    skill_plan: tuple[SkillPlanEntry, ...] = Field(min_length=1)
    semantic_status: Literal["not_requested", "success", "failed"]
    semantic_failure_reason: str | None = None

    @model_validator(mode="after")
    def plan_must_match_risk_map(self) -> RiskRoutingResult:
        names = tuple(entry.skill_name for entry in self.skill_plan)
        if len(names) != len(set(names)):
            raise ValueError("skill_plan names must be unique")
        planned = {entry.skill_name for entry in self.skill_plan if entry.planned}
        expected = set(self.risk_map.always_on_skills)
        for route in self.risk_map.routes:
            expected.update(route.required_skills)
        if planned != expected:
            raise ValueError("skill_plan must match the RiskMap")
        if self.semantic_status == "failed" and self.semantic_failure_reason is None:
            raise ValueError("failed semantic routing requires a reason")
        if self.semantic_status != "failed" and self.semantic_failure_reason is not None:
            raise ValueError("only failed semantic routing may have a failure reason")
        return self


class CanonicalFinding(ContractModel):
    canonical_id: str = Field(min_length=1)
    normalized_fingerprint: str = Field(min_length=1)
    member_finding_ids: tuple[str, ...] = Field(min_length=1)
    selected: Finding


class CanonicalEvidence(ContractModel):
    canonical_id: str = Field(min_length=1)
    member_evidence_ids: tuple[str, ...] = Field(min_length=1)
    selected: Evidence


class ValidationIssue(ContractModel):
    code: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class EvidenceValidationReport(ContractModel):
    schema_name: Literal["EvidenceValidationReport"] = "EvidenceValidationReport"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: str = Field(min_length=1)
    canonical_findings: tuple[CanonicalFinding, ...]
    canonical_evidence: tuple[CanonicalEvidence, ...]
    conflicts: tuple[EvidenceConflict, ...]
    issues: tuple[ValidationIssue, ...]
    valid_finding_ids: tuple[str, ...]
    invalid_finding_ids: tuple[str, ...]
    valid_evidence_ids: tuple[str, ...]
    invalid_evidence_ids: tuple[str, ...]


class RecheckTarget(ContractModel):
    target_id: str = Field(min_length=1)
    finding_ids: tuple[str, ...]
    conflict_ids: tuple[str, ...]
    skill_names: tuple[str, ...]
    route_ids: tuple[str, ...]
    locations: tuple[CodeLocation, ...]
    reason: str = Field(min_length=1)

    @field_validator("finding_ids", "conflict_ids", "skill_names", "route_ids")
    @classmethod
    def target_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("recheck target references must be unique")
        return value

    @model_validator(mode="after")
    def target_must_be_bounded(self) -> RecheckTarget:
        if not (self.finding_ids or self.conflict_ids or self.skill_names):
            raise ValueError("a recheck target must identify a finding, conflict, or Skill")
        if self.finding_ids and not self.locations:
            raise ValueError("finding rechecks require exact locations")
        return self


class RecheckRequest(ContractModel):
    schema_name: Literal["RecheckRequest"] = "RecheckRequest"
    schema_version: Literal["1.0.0"] = "1.0.0"
    request_id: str = Field(min_length=1)
    review_id: str = Field(min_length=1)
    attempt: Literal[1] = 1
    targets: tuple[RecheckTarget, ...] = Field(min_length=1, max_length=20)
    original_evidence_ids: tuple[str, ...]

    @model_validator(mode="after")
    def request_references_must_be_unique(self) -> RecheckRequest:
        target_ids = tuple(item.target_id for item in self.targets)
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("recheck target IDs must be unique")
        if len(self.original_evidence_ids) != len(set(self.original_evidence_ids)):
            raise ValueError("original_evidence_ids must be unique")
        return self


class FindingEvidenceAppend(ContractModel):
    finding_id: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids must be unique")
        return value


class ConflictResolution(ContractModel):
    conflict_id: str = Field(min_length=1)
    resolution: str = Field(min_length=1)


class FindingResolution(ContractModel):
    finding_id: str = Field(min_length=1)
    status: FindingStatus
    resolution: str = Field(min_length=1)


class RecheckResult(ContractModel):
    schema_name: Literal["RecheckResult"] = "RecheckResult"
    schema_version: Literal["1.0.0"] = "1.0.0"
    request_id: str = Field(min_length=1)
    review_id: str = Field(min_length=1)
    attempt: Literal[1] = 1
    status: Literal["success", "failed", "timed_out"]
    additional_evidence: tuple[Evidence, ...] = ()
    evidence_links: tuple[FindingEvidenceAppend, ...] = ()
    finding_resolutions: tuple[FindingResolution, ...] = ()
    conflict_resolutions: tuple[ConflictResolution, ...] = ()
    coverage_updates: tuple[CoverageRecord, ...] = ()
    verified_e3_evidence_ids: tuple[str, ...] = ()
    failure_reason: str | None = None

    @model_validator(mode="after")
    def result_status_must_match_payload(self) -> RecheckResult:
        if self.status == "success" and self.failure_reason is not None:
            raise ValueError("successful recheck cannot have a failure reason")
        if self.status != "success":
            if self.failure_reason is None:
                raise ValueError("failed recheck requires a failure reason")
            if (
                self.additional_evidence
                or self.evidence_links
                or self.finding_resolutions
                or self.conflict_resolutions
                or self.coverage_updates
            ):
                raise ValueError("failed recheck cannot publish evidence or resolutions")
        for label, values in (
            (
                "additional evidence IDs",
                tuple(item.evidence_id for item in self.additional_evidence),
            ),
            (
                "evidence-link finding IDs",
                tuple(item.finding_id for item in self.evidence_links),
            ),
            (
                "finding-resolution IDs",
                tuple(item.finding_id for item in self.finding_resolutions),
            ),
            (
                "conflict-resolution IDs",
                tuple(item.conflict_id for item in self.conflict_resolutions),
            ),
            (
                "coverage-update Skills",
                tuple(item.skill_name for item in self.coverage_updates),
            ),
            ("verified E3 IDs", self.verified_e3_evidence_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self


class RecheckOutcome(ContractModel):
    schema_name: Literal["RecheckOutcome"] = "RecheckOutcome"
    schema_version: Literal["1.0.0"] = "1.0.0"
    initial_decision: GateDecision
    request: RecheckRequest | None
    final_decision: GateDecision
    attempts: int = Field(ge=0, le=1)
    exhausted: bool
    appended_evidence_ids: tuple[str, ...]
