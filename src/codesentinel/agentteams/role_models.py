"""Dependency-light role payloads shared by P7 and AgentTeams Workers."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

ROLE_PAYLOAD_VERSION = "1.0.0"

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Summary = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1000),
]
SeverityValue = Literal["critical", "high", "medium", "low", "info"]
SecurityCategory = Literal[
    "secret",
    "sql_injection",
    "command_injection",
    "dangerous_call",
    "auth_boundary",
]
QualityCategory = Literal[
    "auth_boundary",
    "logic",
    "exception_handling",
    "performance",
    "test_gap",
]
RoleName = Literal["diff_analyzer", "security_scanner", "quality_reviewer"]


class RolePayloadModel(BaseModel):
    """Strict base for model-authored, non-authoritative role payloads."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class DiffSemanticPayload(RolePayloadModel):
    summary: Summary
    change_intents: tuple[NonEmptyStr, ...] = Field(max_length=20)
    affected_symbols: tuple[NonEmptyStr, ...] = Field(max_length=50)

    @field_validator("change_intents", "affected_symbols")
    @classmethod
    def semantic_lists_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("semantic list values must be unique")
        return value


class SecurityFindingDraft(RolePayloadModel):
    category: SecurityCategory
    severity: SeverityValue
    title: NonEmptyStr
    claim: NonEmptyStr
    recommendation: NonEmptyStr
    confidence: float = Field(ge=0, le=1)
    line_refs: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=5)

    @field_validator("line_refs")
    @classmethod
    def line_refs_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("line_refs must be unique")
        return value


class QualityFindingDraft(RolePayloadModel):
    category: QualityCategory
    severity: SeverityValue
    title: NonEmptyStr
    claim: NonEmptyStr
    recommendation: NonEmptyStr
    confidence: float = Field(ge=0, le=1)
    line_refs: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=5)

    @field_validator("line_refs")
    @classmethod
    def line_refs_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("line_refs must be unique")
        return value


class SecurityReviewPayload(RolePayloadModel):
    findings: tuple[SecurityFindingDraft, ...] = Field(max_length=10)
    summary: Summary


class QualityReviewPayload(RolePayloadModel):
    findings: tuple[QualityFindingDraft, ...] = Field(max_length=10)
    summary: Summary


RolePayload: TypeAlias = (
    DiffSemanticPayload | SecurityReviewPayload | QualityReviewPayload
)

ROLE_PAYLOAD_MODELS: dict[RoleName, type[RolePayloadModel]] = {
    "diff_analyzer": DiffSemanticPayload,
    "security_scanner": SecurityReviewPayload,
    "quality_reviewer": QualityReviewPayload,
}

ROLE_SCHEMA_NAMES: dict[RoleName, str] = {
    "diff_analyzer": "DiffSemanticPayload",
    "security_scanner": "SecurityReviewPayload",
    "quality_reviewer": "QualityReviewPayload",
}


def role_payload_model(role: RoleName) -> type[RolePayloadModel]:
    """Return the only payload contract permitted for a Worker role."""

    return ROLE_PAYLOAD_MODELS[role]
