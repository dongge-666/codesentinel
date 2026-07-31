"""Stable public API for deterministic gate evaluation."""

from .engine import PolicyEngine, evaluate_gate, safe_evaluate_gate
from .loader import (
    DEFAULT_POLICY_VERSION,
    PolicyLoadError,
    load_policy,
)
from .models import PolicyDocument
from .validation import (
    CoreInputError,
    IntegrityIssue,
    PolicyEvaluationContext,
    ValidatedPolicyContext,
    validate_policy_context,
)

__all__ = [
    "CoreInputError",
    "DEFAULT_POLICY_VERSION",
    "IntegrityIssue",
    "PolicyDocument",
    "PolicyEngine",
    "PolicyEvaluationContext",
    "PolicyLoadError",
    "ValidatedPolicyContext",
    "evaluate_gate",
    "load_policy",
    "safe_evaluate_gate",
    "validate_policy_context",
]
