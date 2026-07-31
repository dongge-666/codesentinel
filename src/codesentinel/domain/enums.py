"""Frozen machine-readable enums for the CodeSentinel MVP."""

from enum import StrEnum


class GateStatus(StrEnum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    DISMISSED = "dismissed"
    UNVERIFIED = "unverified"


class EvidenceLevel(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"


class EvidenceSource(StrEnum):
    RULE = "rule"
    STATIC_TOOL = "static_tool"
    LLM = "llm"
    HUMAN = "human"
    SYSTEM = "system"


class SkillStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class CoverageStatus(StrEnum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class ChangeType(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class ReviewStage(StrEnum):
    CREATED = "created"
    DIFF_PARSED = "diff_parsed"
    RISK_MAPPED = "risk_mapped"
    REVIEWS_RUNNING = "reviews_running"
    EVIDENCE_COLLECTED = "evidence_collected"
    EVIDENCE_VALIDATED = "evidence_validated"
    RECHECK_REQUESTED = "recheck_requested"
    POLICY_EVALUATED = "policy_evaluated"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskCategory(StrEnum):
    SECRET = "secret"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    DANGEROUS_CALL = "dangerous_call"
    AUTH_BOUNDARY = "auth_boundary"
    LOGIC = "logic"
    EXCEPTION_HANDLING = "exception_handling"
    PERFORMANCE = "performance"
    TEST_GAP = "test_gap"
    SCOPE_LIMIT = "scope_limit"
    TOOL_FAILURE = "tool_failure"
