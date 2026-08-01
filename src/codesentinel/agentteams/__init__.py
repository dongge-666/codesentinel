"""AgentTeams transport contracts used by the P10 integration boundary."""

from .assignment import (
    load_and_validate_assignment,
    load_and_validate_role_context,
    validate_assignment_against_request,
    validate_context_allows_semantic_delivery,
    validate_delivery_against_assignment,
)
from .context_models import RoleContextArtifact, WorkerContextLine
from .delivery import build_worker_delivery, load_role_payload, write_delivery_atomic
from .models import (
    AgentTeamsBudget,
    ArtifactPointer,
    ControlMessage,
    ModelUsage,
    ReviewRequestEnvelope,
    WorkerAssignmentEnvelope,
    WorkerDeliveryEnvelope,
    WorkerEvidence,
)
from .role_models import (
    DiffSemanticPayload,
    QualityFindingDraft,
    QualityReviewPayload,
    SecurityFindingDraft,
    SecurityReviewPayload,
)
from .serialization import canonical_json_bytes, sha256_hex
from .validation import (
    build_assignment_control,
    load_and_validate_delivery,
    load_and_validate_request,
    validate_delivery_against_request,
)

__all__ = [
    "AgentTeamsBudget",
    "ArtifactPointer",
    "ControlMessage",
    "ModelUsage",
    "ReviewRequestEnvelope",
    "RoleContextArtifact",
    "WorkerAssignmentEnvelope",
    "WorkerContextLine",
    "WorkerDeliveryEnvelope",
    "WorkerEvidence",
    "DiffSemanticPayload",
    "QualityFindingDraft",
    "QualityReviewPayload",
    "SecurityFindingDraft",
    "SecurityReviewPayload",
    "build_worker_delivery",
    "build_assignment_control",
    "canonical_json_bytes",
    "load_and_validate_delivery",
    "load_and_validate_assignment",
    "load_and_validate_role_context",
    "load_and_validate_request",
    "load_role_payload",
    "sha256_hex",
    "validate_delivery_against_request",
    "validate_assignment_against_request",
    "validate_context_allows_semantic_delivery",
    "validate_delivery_against_assignment",
    "write_delivery_atomic",
]
