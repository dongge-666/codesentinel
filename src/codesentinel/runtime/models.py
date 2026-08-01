"""Strict P9 contracts for the local reference runner and its audit trail."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from codesentinel.domain import GateDecision, GateStatus
from codesentinel.domain.models import ContractModel


class RunStage(StrEnum):
    DIFF = "diff"
    SECRET_BOUNDARY = "secret_boundary"
    DIFF_ANALYSIS = "diff_analysis"
    RISK_ROUTING = "risk_routing"
    SECURITY_SKILLS = "security_skills"
    SECURITY_REVIEW = "security_review"
    QUALITY_REVIEW = "quality_review"
    EVIDENCE_ASSURANCE = "evidence_assurance"
    RECHECK = "recheck"
    POLICY = "policy"
    PERSISTENCE = "persistence"


class TraceStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class RunError(ContractModel):
    error_code: str = Field(min_length=1)
    stage: RunStage
    message: str = Field(min_length=1, max_length=1000)
    retryable: bool


class ReviewTraceEvent(ContractModel):
    schema_name: Literal["ReviewTraceEvent"] = "ReviewTraceEvent"
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: str = Field(min_length=1)
    review_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    stage: RunStage
    actor: str = Field(min_length=1)
    status: TraceStatus
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0)
    artifact_refs: tuple[str, ...]
    error_code: str | None = None
    details: dict[str, str | int | float | bool | None]

    @field_validator("started_at", "completed_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("trace timestamps must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("trace timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def event_must_be_consistent(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("trace completion must not precede start")
        if self.status is TraceStatus.FAILED and self.error_code is None:
            raise ValueError("failed trace events require an error code")
        if self.status is not TraceStatus.FAILED and self.error_code is not None:
            raise ValueError("only failed trace events may contain an error code")
        return self


class RunMetrics(ContractModel):
    duration_ms: int = Field(ge=0)
    changed_files: int = Field(ge=0)
    changed_lines: int = Field(ge=0)
    planned_skills: int = Field(ge=1)
    completed_skills: int = Field(ge=0)
    skipped_skills: int = Field(ge=0)
    failed_skills: int = Field(ge=0)
    model_calls: int = Field(ge=0, le=4)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)


EXIT_CODE_BY_STATUS = {
    GateStatus.PASS: 0,
    GateStatus.BLOCK: 1,
    GateStatus.NEEDS_REVIEW: 2,
    GateStatus.FAILED: 3,
}


class ReviewReport(ContractModel):
    schema_name: Literal["CodeSentinelReviewReport"] = "CodeSentinelReviewReport"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    status: GateStatus
    exit_code: int = Field(ge=0, le=3)
    decision: GateDecision
    initial_gate_status: GateStatus
    recheck_attempts: int = Field(ge=0, le=1)
    recheck_exhausted: bool
    errors: tuple[RunError, ...]
    metrics: RunMetrics
    started_at: datetime
    completed_at: datetime
    reference_runner: Literal[True] = True
    agentteams_business_runtime: Literal[False] = False

    @field_validator("started_at", "completed_at")
    @classmethod
    def report_times_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("report timestamps must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("report timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def report_must_match_decision(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("report completion must not precede start")
        if self.review_id != self.decision.review_id:
            raise ValueError("report and decision review IDs must match")
        if self.trace_id != self.decision.trace_id:
            raise ValueError("report and decision trace IDs must match")
        if self.status is not self.decision.status:
            raise ValueError("report status must match the GateDecision")
        if self.exit_code != EXIT_CODE_BY_STATUS[self.status]:
            raise ValueError("exit_code must match the gate status")
        return self
