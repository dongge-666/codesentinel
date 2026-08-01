"""Strict P7 contracts for model calls and structured Agent execution."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from codesentinel.agentteams.role_models import DiffSemanticPayload as DiffSemanticPayload
from codesentinel.agentteams.role_models import QualityFindingDraft as QualityFindingDraft
from codesentinel.agentteams.role_models import QualityReviewPayload as QualityReviewPayload
from codesentinel.agentteams.role_models import SecurityFindingDraft as SecurityFindingDraft
from codesentinel.agentteams.role_models import SecurityReviewPayload as SecurityReviewPayload
from codesentinel.domain import (
    AgentArtifact,
    DiffAnalysis,
    RiskCategory,
    Severity,
    SkillStatus,
)
from codesentinel.domain.models import ContractModel
from codesentinel.gitdiff import DiffLineKind

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
AgentId = Literal["diff-analyzer", "security-scanner", "quality-reviewer"]


class ProviderErrorCode(StrEnum):
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
    RATE_LIMIT = "RATE_LIMIT"
    TIMEOUT = "TIMEOUT"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    EMPTY_RESPONSE = "EMPTY_RESPONSE"
    TRUNCATED_RESPONSE = "TRUNCATED_RESPONSE"
    INVALID_JSON = "INVALID_JSON"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    CONTEXT_UNSAFE = "CONTEXT_UNSAFE"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    OUTPUT_CONTRACT_ERROR = "OUTPUT_CONTRACT_ERROR"


class ModelCallStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"


class CallPurpose(StrEnum):
    INITIAL = "initial"
    NETWORK_RETRY = "network_retry"
    SCHEMA_REPAIR = "schema_repair"


class ModelCallRecord(ContractModel):
    schema_name: Literal["ModelCallRecord"] = "ModelCallRecord"
    schema_version: Literal["1.0.0"] = "1.0.0"
    call_id: NonEmptyStr
    review_id: NonEmptyStr
    agent_id: AgentId
    prompt_version: NonEmptyStr
    target_schema: NonEmptyStr
    requested_model: NonEmptyStr
    response_model: NonEmptyStr | None
    status: ModelCallStatus
    purpose: CallPurpose
    attempt: int = Field(ge=1, le=4)
    review_call_index: int = Field(ge=1, le=4)
    failure_code: ProviderErrorCode | None
    latency_ms: int = Field(ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    prompt_cache_hit_tokens: int | None = Field(default=None, ge=0)
    prompt_cache_miss_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    pricing_version: NonEmptyStr
    request_hash: NonEmptyStr
    response_hash: NonEmptyStr | None
    started_at: datetime
    completed_at: datetime

    @field_validator("started_at", "completed_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("call timestamps must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("call timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def status_fields_must_be_consistent(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.status is ModelCallStatus.SUCCESS:
            if self.failure_code is not None or self.response_hash is None:
                raise ValueError("successful calls require a response hash and no error")
        elif self.failure_code is None:
            raise ValueError("failed calls require a failure code")
        if self.prompt_tokens is not None:
            known_cache_tokens = (
                (self.prompt_cache_hit_tokens or 0)
                + (self.prompt_cache_miss_tokens or 0)
            )
            if known_cache_tokens > self.prompt_tokens:
                raise ValueError("cache token counts cannot exceed prompt tokens")
        if (
            self.total_tokens is not None
            and self.prompt_tokens is not None
            and self.completion_tokens is not None
            and self.total_tokens != self.prompt_tokens + self.completion_tokens
        ):
            raise ValueError("total_tokens must match prompt and completion tokens")
        return self


class AgentRunResult(ContractModel):
    schema_name: Literal["AgentRunResult"] = "AgentRunResult"
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_id: NonEmptyStr
    agent_id: AgentId
    status: SkillStatus
    target_schema: NonEmptyStr
    output: DiffAnalysis | AgentArtifact | None
    calls: tuple[ModelCallRecord, ...]
    context_hash: NonEmptyStr
    failure_code: ProviderErrorCode | None
    failure_message: NonEmptyStr | None

    @model_validator(mode="after")
    def output_must_match_agent_and_status(self) -> Self:
        if self.status is SkillStatus.SUCCESS:
            if self.output is None or self.failure_code is not None:
                raise ValueError("successful Agent runs require output and no failure")
        else:
            if self.status is not SkillStatus.FAILED:
                raise ValueError("P7 Agent runs support only success or failed")
            if self.output is not None or self.failure_code is None:
                raise ValueError("failed Agent runs require a failure and no output")
        if (self.failure_code is None) != (self.failure_message is None):
            raise ValueError("failure code and message must both be set or both be null")
        if any(
            call.review_id != self.review_id or call.agent_id != self.agent_id
            for call in self.calls
        ):
            raise ValueError("call records must belong to this Agent run")
        call_ids = tuple(call.call_id for call in self.calls)
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("call IDs must be unique within an Agent run")
        if self.agent_id == "diff-analyzer":
            if self.output is not None and not isinstance(self.output, DiffAnalysis):
                raise ValueError("Diff Analyzer must return DiffAnalysis")
        elif self.output is not None:
            if not isinstance(self.output, AgentArtifact):
                raise ValueError("review Agents must return AgentArtifact")
            if self.output.agent_id != self.agent_id:
                raise ValueError("AgentArtifact identity must match its runner")
        return self


class AgentContextLine(ContractModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    line_ref: NonEmptyStr
    file_path: NonEmptyStr
    hunk_id: NonEmptyStr
    kind: DiffLineKind
    side: Literal["old", "new"]
    line_number: int = Field(ge=1)
    content: str
    content_hash: NonEmptyStr


class DeterministicFindingSummary(ContractModel):
    finding_id: NonEmptyStr
    category: RiskCategory
    severity: Severity
    title: NonEmptyStr
    claim: NonEmptyStr
    line_refs: tuple[NonEmptyStr, ...]
    evidence_levels: tuple[Literal["E0", "E1", "E2", "E3"], ...]
