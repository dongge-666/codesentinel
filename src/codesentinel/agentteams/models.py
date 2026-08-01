"""Strict P10 request, delivery, and control-plane contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .serialization import canonical_json_bytes, sha256_hex

CONTRACT_VERSION = "1.0.0"
AGENTTEAMS_RUNTIME = "agentteams-v1.1.2"
BUNDLE_VERSION = "0.1.0"

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    ),
]
Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]
SharedArtifactPath = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=8, max_length=512),
]
PolicyVersion = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9.-]*$",
    ),
]
WorkerRole = Literal["diff_analyzer", "security_scanner", "quality_reviewer"]
DeliveryStatus = Literal[
    "SUCCESS",
    "SUCCESS_WITH_NOTES",
    "REVISION_NEEDED",
    "BLOCKED",
]


def _validate_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware UTC")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError("datetime must use UTC")
    return value.astimezone(UTC)


def _validate_shared_path(value: str) -> str:
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
        raise ValueError("artifact ref must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.as_posix() != value or not value.startswith("shared/"):
        raise ValueError("artifact ref must start with shared/")
    if any(
        part in {"", ".", ".."}
        or part.startswith(".")
        or not all(
            character.isascii()
            and (character.isalnum() or character in "-_.")
            for character in part
        )
        for part in path.parts
    ):
        raise ValueError("artifact ref contains an unsafe path segment")
    return value


class AgentTeamsContractModel(BaseModel):
    """Shared strictness for P10 transport models."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class AgentTeamsBudget(AgentTeamsContractModel):
    max_domain_model_calls: Literal[4] = 4
    max_total_model_calls: Literal[8] = 8
    max_reserved_repair_or_recheck_calls: Literal[1] = 1


class ArtifactPointer(AgentTeamsContractModel):
    ref: SharedArtifactPath
    sha256: Sha256

    @field_validator("ref")
    @classmethod
    def ref_must_be_safe(cls, value: str) -> str:
        return _validate_shared_path(value)


class ReviewRequestEnvelope(AgentTeamsContractModel):
    schema_name: Literal["CodeSentinelAgentTeamsReviewRequest"]
    schema_version: Literal[CONTRACT_VERSION]
    review_id: Identifier
    trace_id: Identifier
    root_task_id: Identifier
    input_artifact_ref: SharedArtifactPath
    input_sha256: Sha256
    policy_version: PolicyVersion
    runtime: Literal[AGENTTEAMS_RUNTIME]
    budget: AgentTeamsBudget
    deadline_at: datetime
    cloud_safe: Literal[True]

    @field_validator("input_artifact_ref")
    @classmethod
    def input_ref_must_be_safe(cls, value: str) -> str:
        return _validate_shared_path(value)

    @field_validator("deadline_at")
    @classmethod
    def deadline_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @model_validator(mode="after")
    def input_ref_must_belong_to_review(self) -> Self:
        expected = (
            f"shared/projects/codesentinel/reviews/{self.review_id}/input/"
        )
        if not self.input_artifact_ref.startswith(expected):
            raise ValueError("input artifact ref does not belong to review")
        return self

    def assert_admissible(self, *, now: datetime) -> None:
        now = _validate_utc(now)
        if self.deadline_at <= now:
            raise ValueError("review request deadline has expired")


class ModelUsage(AgentTeamsContractModel):
    calls: int = Field(ge=0, le=1)


class WorkerDeliveryEnvelope(AgentTeamsContractModel):
    schema_name: Literal["CodeSentinelAgentTeamsWorkerDelivery"]
    schema_version: Literal[CONTRACT_VERSION]
    review_id: Identifier
    trace_id: Identifier
    task_id: Identifier
    parent_task_id: Identifier
    role: WorkerRole
    attempt: int = Field(ge=1, le=2)
    status: DeliveryStatus
    input_artifacts: tuple[ArtifactPointer, ...] = Field(min_length=1)
    output: dict[str, object] = Field(min_length=1)
    evidence: tuple[dict[str, object], ...]
    started_at: datetime
    finished_at: datetime
    model_usage: ModelUsage
    output_sha256: Sha256

    @field_validator("started_at", "finished_at")
    @classmethod
    def times_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @model_validator(mode="after")
    def delivery_must_be_internally_consistent(self) -> Self:
        refs = [item.ref for item in self.input_artifacts]
        if len(refs) != len(set(refs)):
            raise ValueError("input artifact refs must be unique")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if sha256_hex(canonical_json_bytes(self.output)) != self.output_sha256:
            raise ValueError("output_sha256 does not match canonical output")
        return self


class ControlMessage(AgentTeamsContractModel):
    schema_name: Literal["CodeSentinelAgentTeamsControlMessage"] = (
        "CodeSentinelAgentTeamsControlMessage"
    )
    schema_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    event_type: Literal["ASSIGNMENT"] = "ASSIGNMENT"
    review_id: Identifier
    trace_id: Identifier
    task_id: Identifier
    parent_task_id: Identifier
    role: WorkerRole
    attempt: int = Field(ge=1, le=2)
    input_artifact: ArtifactPointer
    deadline_at: datetime

    @field_validator("deadline_at")
    @classmethod
    def deadline_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    def to_matrix_text(self) -> str:
        content = canonical_json_bytes(self).decode("utf-8")
        if len(content.encode("utf-8")) > 4096:
            raise ValueError("control message exceeds Matrix size boundary")
        return content
