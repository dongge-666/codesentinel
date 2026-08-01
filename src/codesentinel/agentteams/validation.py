"""Fail-closed validation for AgentTeams transport artifacts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (
    ArtifactPointer,
    ControlMessage,
    ReviewRequestEnvelope,
    WorkerDeliveryEnvelope,
    WorkerRole,
)
from .serialization import canonical_json_bytes, sha256_hex

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class AgentTeamsValidationError(ValueError):
    """A P10 transport document failed a fail-closed boundary check."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentTeamsValidationError("JSON document contains duplicate keys")
        result[key] = value
    return result


def _read_json_object(path: str | Path) -> tuple[dict[str, Any], bytes]:
    document = Path(path)
    if not document.is_file() or document.is_symlink():
        raise AgentTeamsValidationError("document must be a regular file")
    content = document.read_bytes()
    if not content or len(content) > MAX_DOCUMENT_BYTES:
        raise AgentTeamsValidationError("document size is outside the allowed boundary")
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentTeamsValidationError("document is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AgentTeamsValidationError("document root must be a JSON object")
    return value, content


def load_and_validate_request(
    request_path: str | Path,
    artifact_path: str | Path,
    *,
    now: datetime,
) -> ReviewRequestEnvelope:
    payload, _ = _read_json_object(request_path)
    request = ReviewRequestEnvelope.model_validate_json(canonical_json_bytes(payload))
    request.assert_admissible(now=now)
    artifact, artifact_bytes = _read_json_object(artifact_path)
    if artifact_bytes != canonical_json_bytes(artifact):
        raise AgentTeamsValidationError("input artifact is not canonical JSON")
    if sha256_hex(artifact_bytes) != request.input_sha256:
        raise AgentTeamsValidationError("input artifact digest does not match request")
    if artifact.get("review_id") != request.review_id:
        raise AgentTeamsValidationError("input artifact review_id does not match request")
    if artifact.get("cloud_safe") is not True:
        raise AgentTeamsValidationError("input artifact is not cloud-safe")
    return request


def load_and_validate_delivery(
    delivery_path: str | Path,
) -> WorkerDeliveryEnvelope:
    payload, _ = _read_json_object(delivery_path)
    return WorkerDeliveryEnvelope.model_validate_json(canonical_json_bytes(payload))


def validate_delivery_against_request(
    delivery: WorkerDeliveryEnvelope,
    request: ReviewRequestEnvelope,
    *,
    expected_role: WorkerRole,
    expected_task_id: str,
) -> None:
    if delivery.review_id != request.review_id or delivery.trace_id != request.trace_id:
        raise AgentTeamsValidationError("delivery correlation IDs do not match request")
    if delivery.parent_task_id != request.root_task_id:
        raise AgentTeamsValidationError("delivery parent task does not match request")
    if delivery.role != expected_role or delivery.task_id != expected_task_id:
        raise AgentTeamsValidationError("delivery role or task ID does not match assignment")
    expected_pointer = ArtifactPointer(
        ref=request.input_artifact_ref,
        sha256=request.input_sha256,
    )
    if expected_pointer not in delivery.input_artifacts:
        raise AgentTeamsValidationError("delivery does not reference the assigned input")


def build_assignment_control(
    request: ReviewRequestEnvelope,
    *,
    task_id: str,
    role: WorkerRole,
    attempt: int = 1,
) -> ControlMessage:
    return ControlMessage(
        review_id=request.review_id,
        trace_id=request.trace_id,
        task_id=task_id,
        parent_task_id=request.root_task_id,
        role=role,
        attempt=attempt,
        input_artifact=ArtifactPointer(
            ref=request.input_artifact_ref,
            sha256=request.input_sha256,
        ),
        deadline_at=request.deadline_at,
    )
