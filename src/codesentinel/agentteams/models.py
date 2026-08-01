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

from .role_models import (
    DiffSemanticPayload,
    QualityReviewPayload,
    SecurityReviewPayload,
    role_payload_model,
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
EvidenceSummary = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1000),
]
LineReference = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
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
WorkerSkillName = Literal[
    "codesentinel-diff-review",
    "codesentinel-security-review",
    "codesentinel-quality-review",
]
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


def worker_evidence_content_hash(
    *,
    role: WorkerRole,
    summary: str,
    line_refs: tuple[str, ...],
    confidence: float | None,
    input_artifact: ArtifactPointer,
) -> str:
    """Bind semantic evidence to role, content, confidence, and input lineage."""

    return sha256_hex(
        canonical_json_bytes(
            {
                "confidence": confidence,
                "input_artifact": input_artifact.model_dump(mode="json"),
                "line_refs": line_refs,
                "role": role,
                "summary": summary,
            }
        )
    )


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


class WorkerAssignmentEnvelope(AgentTeamsContractModel):
    schema_name: Literal["CodeSentinelAgentTeamsWorkerAssignment"] = (
        "CodeSentinelAgentTeamsWorkerAssignment"
    )
    schema_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    review_id: Identifier
    trace_id: Identifier
    task_id: Identifier
    parent_task_id: Identifier
    role: WorkerRole
    attempt: int = Field(ge=1, le=2)
    skill_name: WorkerSkillName
    skill_version: Literal["1.0.0"] = "1.0.0"
    review_input: ArtifactPointer
    role_context: ArtifactPointer
    deadline_at: datetime
    delivery_ref: SharedArtifactPath

    @field_validator("deadline_at")
    @classmethod
    def deadline_must_be_utc(cls, value: datetime) -> datetime:
        return _validate_utc(value)

    @field_validator("delivery_ref")
    @classmethod
    def delivery_ref_must_be_safe(cls, value: str) -> str:
        return _validate_shared_path(value)

    @model_validator(mode="after")
    def assignment_must_be_role_scoped(self) -> Self:
        expected_skill = {
            "diff_analyzer": "codesentinel-diff-review",
            "security_scanner": "codesentinel-security-review",
            "quality_reviewer": "codesentinel-quality-review",
        }[self.role]
        if self.skill_name != expected_skill:
            raise ValueError("assignment Skill does not match Worker role")
        expected_context = f"shared/tasks/{self.task_id}/base/role-context.json"
        if self.role_context.ref != expected_context:
            raise ValueError("role context does not belong to the assigned task")
        expected_delivery = f"shared/tasks/{self.task_id}/workspace/delivery.json"
        if self.delivery_ref != expected_delivery:
            raise ValueError("delivery ref does not belong to the assigned task")
        return self

    def assert_admissible(self, *, now: datetime) -> None:
        now = _validate_utc(now)
        if self.deadline_at <= now:
            raise ValueError("Worker assignment deadline has expired")


class ModelUsage(AgentTeamsContractModel):
    calls: int = Field(ge=0, le=1)


class WorkerEvidence(AgentTeamsContractModel):
    evidence_id: Identifier
    level: Literal["E0", "E1"]
    source: Literal["llm"]
    summary: EvidenceSummary
    line_refs: tuple[LineReference, ...] = Field(max_length=5)
    confidence: float | None = Field(default=None, ge=0, le=1)
    input_artifact: ArtifactPointer
    content_hash: Sha256

    @field_validator("line_refs")
    @classmethod
    def line_refs_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence line_refs must be unique")
        return value


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
    evidence: tuple[WorkerEvidence, ...]
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
        output_model = role_payload_model(self.role)
        parsed_output = output_model.model_validate_json(canonical_json_bytes(self.output))
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique")
        if any(
            item.input_artifact not in self.input_artifacts for item in self.evidence
        ):
            raise ValueError("evidence must reference a declared input artifact")
        for item in self.evidence:
            expected_hash = worker_evidence_content_hash(
                role=self.role,
                summary=item.summary,
                line_refs=item.line_refs,
                confidence=item.confidence,
                input_artifact=item.input_artifact,
            )
            if item.content_hash != expected_hash:
                raise ValueError("evidence content_hash does not match its content")
            if item.evidence_id != f"evidence-{item.content_hash[:20]}":
                raise ValueError("evidence_id does not derive from content_hash")
        if self.model_usage.calls == 1:
            if isinstance(parsed_output, DiffSemanticPayload):
                expected_evidence = ((parsed_output.summary, (), None),)
            elif isinstance(
                parsed_output,
                (SecurityReviewPayload, QualityReviewPayload),
            ):
                expected_evidence = (
                    tuple(
                        (finding.claim, finding.line_refs, finding.confidence)
                        for finding in parsed_output.findings
                    )
                    if parsed_output.findings
                    else ((parsed_output.summary, (), None),)
                )
            else:  # pragma: no cover - closed by role_payload_model
                raise TypeError("unsupported role payload")
            actual_evidence = tuple(
                (item.summary, item.line_refs, item.confidence) for item in self.evidence
            )
            if actual_evidence != expected_evidence:
                raise ValueError("semantic evidence does not match the role output")
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
