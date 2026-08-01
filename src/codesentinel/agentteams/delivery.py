"""Deterministic construction and atomic persistence of Worker deliveries."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .assignment import (
    validate_assignment_against_request,
    validate_context_against_assignment,
    validate_context_allows_semantic_delivery,
)
from .context_models import RoleContextArtifact
from .models import (
    ArtifactPointer,
    DeliveryStatus,
    ModelUsage,
    ReviewRequestEnvelope,
    WorkerAssignmentEnvelope,
    WorkerDeliveryEnvelope,
    WorkerEvidence,
    WorkerRole,
    worker_evidence_content_hash,
)
from .role_models import (
    DiffSemanticPayload,
    QualityReviewPayload,
    RolePayloadModel,
    SecurityReviewPayload,
    role_payload_model,
)
from .serialization import canonical_json_bytes, sha256_hex
from .validation import AgentTeamsValidationError, read_json_object


def load_role_payload(
    payload_path: str | Path,
    *,
    role: WorkerRole,
) -> RolePayloadModel:
    """Load one model-authored payload using the assignment's exact role."""

    payload, _ = read_json_object(payload_path)
    model = role_payload_model(role)
    try:
        return model.model_validate_json(canonical_json_bytes(payload))
    except Exception as exc:
        raise AgentTeamsValidationError(
            f"payload does not satisfy the {role} contract"
        ) from exc


def _worker_evidence(
    *,
    role: WorkerRole,
    payload: RolePayloadModel,
    input_artifact: ArtifactPointer,
) -> tuple[WorkerEvidence, ...]:
    if isinstance(payload, DiffSemanticPayload):
        items: tuple[tuple[str, tuple[str, ...], float | None], ...] = (
            (payload.summary, (), None),
        )
    elif isinstance(payload, (SecurityReviewPayload, QualityReviewPayload)):
        if payload.findings:
            items = tuple(
                (finding.claim, finding.line_refs, finding.confidence)
                for finding in payload.findings
            )
        else:
            items = ((payload.summary, (), None),)
    else:  # pragma: no cover - guarded by the closed RolePayload type family
        raise TypeError("unsupported role payload")

    evidence = []
    for summary, line_refs, confidence in items:
        content_hash = worker_evidence_content_hash(
            role=role,
            summary=summary,
            line_refs=line_refs,
            confidence=confidence,
            input_artifact=input_artifact,
        )
        evidence.append(
            WorkerEvidence(
                evidence_id=f"evidence-{content_hash[:20]}",
                level="E1",
                source="llm",
                summary=summary,
                line_refs=line_refs,
                confidence=confidence,
                input_artifact=input_artifact,
                content_hash=content_hash,
            )
        )
    return tuple(evidence)


def build_worker_delivery(
    request: ReviewRequestEnvelope,
    *,
    assignment: WorkerAssignmentEnvelope,
    context: RoleContextArtifact,
    payload: RolePayloadModel,
    started_at: datetime,
    finished_at: datetime,
    status: DeliveryStatus = "SUCCESS",
    model_calls: int = 1,
) -> WorkerDeliveryEnvelope:
    """Create a correlated delivery without trusting model-authored metadata."""

    validate_assignment_against_request(assignment, request)
    validate_context_against_assignment(context, assignment)
    validate_context_allows_semantic_delivery(context)
    if finished_at > assignment.deadline_at:
        raise AgentTeamsValidationError("delivery finished after the assignment deadline")
    if model_calls != 1:
        raise AgentTeamsValidationError("semantic delivery requires one domain analysis")
    if status == "BLOCKED":
        raise AgentTeamsValidationError("blocked tasks cannot build a semantic delivery")
    expected_model = role_payload_model(assignment.role)
    if type(payload) is not expected_model:
        raise AgentTeamsValidationError("payload type does not match the assigned role")
    if isinstance(payload, (SecurityReviewPayload, QualityReviewPayload)) and any(
        line_ref not in context.allowed_line_refs
        for finding in payload.findings
        for line_ref in finding.line_refs
    ):
        raise AgentTeamsValidationError("payload references a foreign context line")
    pointer = assignment.role_context
    output: dict[str, Any] = payload.model_dump(mode="json")
    return WorkerDeliveryEnvelope(
        schema_name="CodeSentinelAgentTeamsWorkerDelivery",
        schema_version="1.0.0",
        review_id=assignment.review_id,
        trace_id=assignment.trace_id,
        task_id=assignment.task_id,
        parent_task_id=assignment.parent_task_id,
        role=assignment.role,
        attempt=assignment.attempt,
        status=status,
        input_artifacts=(assignment.review_input, assignment.role_context),
        output=output,
        evidence=_worker_evidence(
            role=assignment.role,
            payload=payload,
            input_artifact=pointer,
        ),
        started_at=started_at,
        finished_at=finished_at,
        model_usage=ModelUsage(calls=model_calls),
        output_sha256=sha256_hex(canonical_json_bytes(output)),
    )


def write_delivery_atomic(
    delivery: WorkerDeliveryEnvelope,
    destination: str | Path,
    *,
    assignment: WorkerAssignmentEnvelope,
    artifact_root: str | Path,
) -> Path:
    """Create one delivery at the assignment-bound path under a trusted root."""

    target = Path(destination)
    root = Path(artifact_root)
    if not root.is_dir() or root.is_symlink():
        raise AgentTeamsValidationError("artifact root must be an existing real directory")
    if (
        delivery.review_id != assignment.review_id
        or delivery.trace_id != assignment.trace_id
        or delivery.task_id != assignment.task_id
        or delivery.parent_task_id != assignment.parent_task_id
        or delivery.role != assignment.role
        or delivery.attempt != assignment.attempt
    ):
        raise AgentTeamsValidationError("delivery identity does not match assignment")
    expected = root.joinpath(*PurePosixPath(assignment.delivery_ref).parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_parent = target.parent.resolve(strict=True)
        resolved_expected_parent = expected.parent.resolve(strict=True)
    except OSError as exc:
        raise AgentTeamsValidationError(
            "delivery path cannot be resolved under the artifact root"
        ) from exc
    if (
        target.name != expected.name
        or resolved_parent != resolved_expected_parent
        or not resolved_parent.is_relative_to(resolved_root)
    ):
        raise AgentTeamsValidationError(
            "delivery destination does not match the assignment under the artifact root"
        )
    if target.exists() or target.is_symlink():
        raise AgentTeamsValidationError("delivery destination already exists or is unsafe")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise AgentTeamsValidationError("delivery parent must be an existing real directory")

    content = canonical_json_bytes(delivery)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, target)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return target
