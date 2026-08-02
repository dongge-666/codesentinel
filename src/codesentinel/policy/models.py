"""Strict models for declarative, non-executable gate policy data."""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from codesentinel.domain import (
    EvidenceLevel,
    EvidenceSource,
    FindingStatus,
    GateStatus,
    RiskCategory,
    Severity,
)

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class PolicyModel(BaseModel):
    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class RuleIds(PolicyModel):
    pass_rule: NonEmptyStr = Field(alias="pass")
    input_failure: NonEmptyStr
    policy_failure: NonEmptyStr
    engine_failure: NonEmptyStr
    integrity_block: NonEmptyStr


class E3Qualifier(PolicyModel):
    source: EvidenceSource
    detector_name: NonEmptyStr
    detector_versions: tuple[NonEmptyStr, ...] = Field(min_length=1)

    @field_validator("detector_versions")
    @classmethod
    def versions_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("detector_versions must be unique")
        return value

    @model_validator(mode="after")
    def llm_cannot_be_an_e3_qualifier(self) -> Self:
        if self.source is EvidenceSource.LLM:
            raise ValueError("LLM cannot be allow-listed for E3")
        return self


class BlockRule(PolicyModel):
    rule_id: NonEmptyStr
    categories: tuple[RiskCategory, ...] = Field(min_length=1)
    statuses: tuple[FindingStatus, ...] = Field(min_length=1)
    min_severity: Severity
    min_evidence_level: EvidenceLevel
    require_new_side: bool

    @field_validator("categories", "statuses")
    @classmethod
    def values_must_be_unique(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("block rule values must be unique")
        return value


class NeedsReviewRule(PolicyModel):
    rule_id: NonEmptyStr
    manual_action: NonEmptyStr


class RequiredArtifact(PolicyModel):
    schema_name: NonEmptyStr
    schema_version: NonEmptyStr
    agent_id: NonEmptyStr
    agent_role: NonEmptyStr


class SeverityRank(PolicyModel):
    info: int
    low: int
    medium: int
    high: int
    critical: int

    @model_validator(mode="after")
    def ranks_must_be_contiguous(self) -> Self:
        if sorted(self.as_tuple()) != list(range(len(Severity))):
            raise ValueError("severity_rank values must be a contiguous ordering")
        return self

    def __getitem__(self, key: Severity) -> int:
        return getattr(self, key.value)

    def as_tuple(self) -> tuple[int, ...]:
        return (self.info, self.low, self.medium, self.high, self.critical)


class EvidenceRank(PolicyModel):
    e0: int = Field(alias="E0")
    e1: int = Field(alias="E1")
    e2: int = Field(alias="E2")
    e3: int = Field(alias="E3")

    @model_validator(mode="after")
    def ranks_must_be_contiguous(self) -> Self:
        if sorted(self.as_tuple()) != list(range(len(EvidenceLevel))):
            raise ValueError("evidence_rank values must be a contiguous ordering")
        return self

    def __getitem__(self, key: EvidenceLevel) -> int:
        return getattr(self, key.value.lower())

    def as_tuple(self) -> tuple[int, ...]:
        return (self.e0, self.e1, self.e2, self.e3)


class PolicyDocument(PolicyModel):
    schema_version: NonEmptyStr
    policy_version: NonEmptyStr
    decision_precedence: tuple[GateStatus, ...]
    required_artifacts: tuple[RequiredArtifact, ...] = Field(min_length=1)
    always_required_skills: tuple[NonEmptyStr, ...] = Field(min_length=1)
    provider_failure_error_codes: tuple[NonEmptyStr, ...]
    severity_rank: SeverityRank
    evidence_rank: EvidenceRank
    rule_ids: RuleIds
    e3_qualifiers: tuple[E3Qualifier, ...] = Field(min_length=1)
    block_rules: tuple[BlockRule, ...] = Field(min_length=1)
    needs_review_rules: tuple[NeedsReviewRule, ...] = Field(min_length=1)

    @field_validator(
        "always_required_skills",
        "provider_failure_error_codes",
    )
    @classmethod
    def string_lists_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("policy lists must be unique")
        return value

    @model_validator(mode="after")
    def policy_shape_must_be_frozen(self) -> Self:
        if self.schema_version != "1.0.0" or self.policy_version != "mvp-1.0.0":
            raise ValueError("policy metadata must identify mvp-1.0.0")

        expected_precedence = (
            GateStatus.FAILED,
            GateStatus.BLOCK,
            GateStatus.NEEDS_REVIEW,
            GateStatus.PASS,
        )
        if self.decision_precedence != expected_precedence:
            raise ValueError("decision_precedence must be FAILED, BLOCK, NEEDS_REVIEW, PASS")

        expected_artifacts = (
            ("SecurityReview", "1.0.0", "security-scanner", "Security Scanner"),
            ("QualityReview", "1.0.0", "quality-reviewer", "Quality Reviewer"),
        )
        actual_artifacts = tuple(
            (
                item.schema_name,
                item.schema_version,
                item.agent_id,
                item.agent_role,
            )
            for item in self.required_artifacts
        )
        if actual_artifacts != expected_artifacts:
            raise ValueError("required artifact identities must match mvp-1.0.0")

        if self.always_required_skills != ("detect_secret",):
            raise ValueError("mvp-1.0.0 must always require detect_secret")
        expected_provider_errors = {
            "MODEL_AUTH_ERROR",
            "MODEL_ERROR",
            "MODEL_QUOTA_EXCEEDED",
            "RATE_LIMITED",
            "TIMEOUT",
        }
        if set(self.provider_failure_error_codes) != expected_provider_errors:
            raise ValueError("provider failure codes must match mvp-1.0.0")

        if self.severity_rank.as_tuple() != (0, 1, 2, 3, 4):
            raise ValueError("severity_rank semantics must match mvp-1.0.0")
        if self.evidence_rank.as_tuple() != (0, 1, 2, 3):
            raise ValueError("evidence_rank semantics must match mvp-1.0.0")

        actual_rule_ids = (
            self.rule_ids.pass_rule,
            self.rule_ids.input_failure,
            self.rule_ids.policy_failure,
            self.rule_ids.engine_failure,
            self.rule_ids.integrity_block,
        )
        if actual_rule_ids != ("P001", "F001", "F002", "F003", "B004"):
            raise ValueError("built-in rule IDs must match mvp-1.0.0")

        block_ids = [rule.rule_id for rule in self.block_rules]
        needs_ids = [rule.rule_id for rule in self.needs_review_rules]
        if block_ids != ["B001", "B002", "B003"]:
            raise ValueError("mvp-1.0.0 must define exactly B001-B003 as finding rules")
        if needs_ids != [f"N{number:03d}" for number in range(1, 9)]:
            raise ValueError("mvp-1.0.0 must define exactly N001-N008")
        expected_manual_actions = (
            "Re-run or manually complete every mandatory check.",
            "Reduce the diff scope or provide the missing code context.",
            "Resolve the listed evidence conflicts before merging.",
            "Manually validate each unresolved high-severity finding.",
            "Review the medium-risk business semantics and expected behavior.",
            "Repair or replace the invalid or incomplete Agent artifact.",
            "Restore the required model or tool service and re-run the missing review.",
            "Perform the remaining targeted checks manually; automatic recheck is exhausted.",
        )
        if tuple(
            rule.manual_action for rule in self.needs_review_rules
        ) != expected_manual_actions:
            raise ValueError("manual actions must match mvp-1.0.0")

        expected_block_semantics = {
            "B001": (
                (RiskCategory.SECRET,),
                (FindingStatus.CONFIRMED,),
            ),
            "B002": (
                (RiskCategory.COMMAND_INJECTION, RiskCategory.DANGEROUS_CALL),
                (FindingStatus.CONFIRMED,),
            ),
            "B003": (
                (RiskCategory.SQL_INJECTION,),
                (FindingStatus.CONFIRMED,),
            ),
        }
        for rule in self.block_rules:
            expected_categories, expected_statuses = expected_block_semantics[
                rule.rule_id
            ]
            if (
                rule.categories != expected_categories
                or rule.statuses != expected_statuses
                or rule.min_severity is not Severity.HIGH
                or rule.min_evidence_level is not EvidenceLevel.E3
                or not rule.require_new_side
            ):
                raise ValueError(
                    f"{rule.rule_id} semantics must match mvp-1.0.0"
                )

        all_rule_ids = [
            self.rule_ids.pass_rule,
            self.rule_ids.input_failure,
            self.rule_ids.policy_failure,
            self.rule_ids.engine_failure,
            self.rule_ids.integrity_block,
            *block_ids,
            *needs_ids,
        ]
        if len(all_rule_ids) != len(set(all_rule_ids)):
            raise ValueError("rule IDs must be globally unique")

        qualifier_keys = {
            (item.source, item.detector_name, item.detector_versions)
            for item in self.e3_qualifiers
        }
        expected_qualifiers = {
            (EvidenceSource.RULE, "detect_secret", ("1.0.0",)),
            (EvidenceSource.RULE, "detect_injection", ("1.0.0", "1.1.0")),
            (
                EvidenceSource.STATIC_TOOL,
                "detect_injection",
                ("1.0.0", "1.1.0"),
            ),
            (
                EvidenceSource.RULE,
                "detect_dangerous_call",
                ("1.0.0", "1.1.0"),
            ),
            (EvidenceSource.SYSTEM, "policy_integrity", ("1.0.0",)),
        }
        if qualifier_keys != expected_qualifiers:
            raise ValueError("E3 qualifiers must match mvp-1.0.0")
        return self
