"""Trusted Worker assignment and role-context validation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .context_models import RoleContextArtifact, SecurityContextMetadata
from .models import (
    ArtifactPointer,
    ReviewRequestEnvelope,
    WorkerAssignmentEnvelope,
    WorkerDeliveryEnvelope,
)
from .serialization import canonical_json_bytes, sha256_hex
from .validation import AgentTeamsValidationError, read_json_object


def validate_assignment_against_request(
    assignment: WorkerAssignmentEnvelope,
    request: ReviewRequestEnvelope,
) -> None:
    """Require the immutable task assignment to descend from one review."""

    if assignment.review_id != request.review_id or assignment.trace_id != request.trace_id:
        raise AgentTeamsValidationError("assignment correlation IDs do not match request")
    if assignment.parent_task_id != request.root_task_id:
        raise AgentTeamsValidationError("assignment parent task does not match request")
    expected_review_input = ArtifactPointer(
        ref=request.input_artifact_ref,
        sha256=request.input_sha256,
    )
    if assignment.review_input != expected_review_input:
        raise AgentTeamsValidationError("assignment review input does not match request")
    if assignment.deadline_at > request.deadline_at:
        raise AgentTeamsValidationError("assignment deadline exceeds review deadline")


def load_and_validate_assignment(
    assignment_path: str | Path,
    request: ReviewRequestEnvelope,
    *,
    now: datetime,
) -> WorkerAssignmentEnvelope:
    payload, content = read_json_object(assignment_path)
    if content != canonical_json_bytes(payload):
        raise AgentTeamsValidationError("Worker assignment is not canonical JSON")
    assignment = WorkerAssignmentEnvelope.model_validate_json(content)
    assignment.assert_admissible(now=now)
    validate_assignment_against_request(assignment, request)
    return assignment


def validate_context_against_assignment(
    context: RoleContextArtifact,
    assignment: WorkerAssignmentEnvelope,
) -> None:
    if context.review_id != assignment.review_id or context.role != assignment.role:
        raise AgentTeamsValidationError("role context identity does not match assignment")
    if sha256_hex(canonical_json_bytes(context)) != assignment.role_context.sha256:
        raise AgentTeamsValidationError("role context content does not match assignment digest")


def load_and_validate_role_context(
    context_path: str | Path,
    assignment: WorkerAssignmentEnvelope,
) -> RoleContextArtifact:
    payload, content = read_json_object(context_path)
    if content != canonical_json_bytes(payload):
        raise AgentTeamsValidationError("role context is not canonical JSON")
    if sha256_hex(content) != assignment.role_context.sha256:
        raise AgentTeamsValidationError("role context digest does not match assignment")
    context = RoleContextArtifact.model_validate_json(content)
    validate_context_against_assignment(context, assignment)
    return context


def validate_context_allows_semantic_delivery(context: RoleContextArtifact) -> None:
    """Fail closed when trusted deterministic coverage could not complete."""

    metadata = context.parsed_metadata()
    if isinstance(metadata, SecurityContextMetadata) and any(
        item.status == "failed" for item in metadata.deterministic_coverage
    ):
        raise AgentTeamsValidationError(
            "failed deterministic security coverage blocks semantic delivery"
        )


def validate_delivery_against_assignment(
    delivery: WorkerDeliveryEnvelope,
    request: ReviewRequestEnvelope,
    assignment: WorkerAssignmentEnvelope,
    context: RoleContextArtifact,
) -> None:
    validate_assignment_against_request(assignment, request)
    validate_context_against_assignment(context, assignment)
    validate_context_allows_semantic_delivery(context)
    if (
        delivery.review_id != assignment.review_id
        or delivery.trace_id != assignment.trace_id
        or delivery.task_id != assignment.task_id
        or delivery.parent_task_id != assignment.parent_task_id
        or delivery.role != assignment.role
        or delivery.attempt != assignment.attempt
    ):
        raise AgentTeamsValidationError("delivery identity does not match assignment")
    expected_inputs = (assignment.review_input, assignment.role_context)
    if delivery.input_artifacts != expected_inputs:
        raise AgentTeamsValidationError("delivery inputs do not exactly match assignment")
    if any(item.input_artifact != assignment.role_context for item in delivery.evidence):
        raise AgentTeamsValidationError("semantic evidence must cite the assigned role context")
    if delivery.finished_at > assignment.deadline_at:
        raise AgentTeamsValidationError("delivery finished after the assignment deadline")
    if delivery.model_usage.calls != 1:
        raise AgentTeamsValidationError("semantic delivery must record one domain analysis")
    if delivery.status == "BLOCKED":
        raise AgentTeamsValidationError("blocked tasks cannot claim a semantic delivery")
    if any(
        line_ref not in context.allowed_line_refs
        for item in delivery.evidence
        for line_ref in item.line_refs
    ):
        raise AgentTeamsValidationError("delivery evidence references a foreign context line")
