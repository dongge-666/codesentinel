"""Deterministic, offline gate evaluation for the frozen MVP policy."""

from __future__ import annotations

from datetime import UTC, datetime

from codesentinel.domain import (
    CoverageRecord,
    CoverageStatus,
    Evidence,
    EvidenceLevel,
    Finding,
    FindingStatus,
    GateDecision,
    GateStatus,
    Severity,
    SkillStatus,
)
from codesentinel.domain.models import EvidenceIndexEntry

from .models import BlockRule, PolicyDocument
from .validation import (
    CoreInputError,
    PolicyEvaluationContext,
    ValidatedPolicyContext,
    validate_policy_context,
)

_INTEGRITY_TAMPER_CODES = frozenset(
    {
        "ARTIFACT_LINEAGE_CYCLE",
        "ARTIFACT_LINEAGE_DANGLING",
        "CONFLICT_FINDING_DANGLING",
        "CONFLICT_RULE_DANGLING",
        "DUPLICATE_ARTIFACT_ID",
        "DUPLICATE_CONFLICT_ID",
        "DUPLICATE_COVERAGE_ID",
        "DUPLICATE_EVIDENCE_ID",
        "DUPLICATE_FINDING_ID",
        "E3_PROVENANCE_UNVERIFIED",
        "EVIDENCE_FINDING_LOCATION_MISMATCH",
        "EVIDENCE_LOCATION_INVALID",
        "FINDING_EVIDENCE_DANGLING",
        "FINDING_LOCATION_INVALID",
        "ROUTE_LOCATION_INVALID",
        "VERIFIED_E3_DANGLING",
    }
)


def _safe_identifier(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    stripped = value.strip()
    return stripped if stripped else fallback


def _safe_decided_at(value: object) -> datetime:
    if not isinstance(value, datetime):
        return datetime(1970, 1, 1, tzinfo=UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        return datetime(1970, 1, 1, tzinfo=UTC)
    return value.astimezone(UTC)


def _failed_decision(
    context: object,
    *,
    policy_version: str,
    rule_id: str,
    summary: str,
) -> GateDecision:
    return GateDecision(
        review_id=_safe_identifier(
            getattr(context, "review_id", None),
            "invalid-review",
        ),
        status=GateStatus.FAILED,
        policy_version=policy_version,
        matched_rule_ids=(rule_id,),
        blocking_finding_ids=(),
        review_finding_ids=(),
        warning_finding_ids=(),
        coverage_complete=False,
        unresolved_conflict_ids=(),
        reason_summary=summary,
        manual_actions=(),
        evidence_index=(),
        trace_id=_safe_identifier(
            getattr(context, "trace_id", None),
            "invalid-trace",
        ),
        decided_at=_safe_decided_at(getattr(context, "decided_at", None)),
    )


class PolicyEngine:
    """A pure evaluator; it never reads files, clocks, repositories, or networks."""

    def __init__(self, policy: PolicyDocument) -> None:
        if not isinstance(policy, PolicyDocument):
            raise TypeError("policy must be a PolicyDocument")
        # Revalidation closes Pydantic's intentionally unchecked model_copy(update=...)
        # path and gives the evaluator its own deeply immutable policy snapshot.
        self.policy = PolicyDocument.model_validate_json(policy.model_dump_json())

    def evaluate(self, context: PolicyEvaluationContext) -> GateDecision:
        try:
            validated = validate_policy_context(context, self.policy)
        except CoreInputError:
            return _failed_decision(
                context,
                policy_version=self.policy.policy_version,
                rule_id=self.policy.rule_ids.input_failure,
                summary="FAILED: the core review context is invalid.",
            )
        return self._evaluate_validated(validated)

    def _qualified_evidence(
        self,
        validated: ValidatedPolicyContext,
        finding_id: str,
    ) -> list[Evidence]:
        finding = next(
            item for item in validated.findings if item.finding_id == finding_id
        )
        evidence_by_id = {item.evidence_id: item for item in validated.evidence}
        return [
            evidence_by_id[evidence_id]
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
            and evidence_id not in validated.invalid_evidence_ids
            and (finding_id, evidence_id)
            not in validated.invalid_finding_evidence_pairs
        ]

    def _finding_matches_block_rule(
        self,
        validated: ValidatedPolicyContext,
        finding: Finding,
        rule: BlockRule,
    ) -> bool:
        finding_id = finding.finding_id
        if (
            finding_id in validated.invalid_finding_ids
            or finding_id in validated.conflict_disqualified_finding_ids
            or finding.category not in rule.categories
            or finding.status not in rule.statuses
            or self.policy.severity_rank[finding.severity]
            < self.policy.severity_rank[rule.min_severity]
        ):
            return False

        qualified = self._qualified_evidence(validated, finding_id)
        eligible = [
            item
            for item in qualified
            if self.policy.evidence_rank[item.level]
            >= self.policy.evidence_rank[rule.min_evidence_level]
        ]
        if rule.require_new_side:
            if not any(location.side == "new" for location in finding.locations):
                return False
            eligible = [
                item
                for item in eligible
                if item.location is not None and item.location.side == "new"
            ]
        return bool(eligible)

    def _mandatory_coverage(
        self,
        validated: ValidatedPolicyContext,
    ) -> tuple[bool, list[CoverageRecord]]:
        valid_records = [
            record
            for record in validated.coverage
            if record.coverage_id not in validated.invalid_coverage_ids
        ]
        failing: list[CoverageRecord] = [
            record
            for record in valid_records
            if record.mandatory and record.status is not CoverageStatus.COMPLETED
        ]
        complete = not failing

        for skill_name in self.policy.always_required_skills:
            matches = [
                record for record in valid_records if record.skill_name == skill_name
            ]
            if (
                not matches
                or any(not record.mandatory for record in matches)
                or any(record.status is not CoverageStatus.COMPLETED for record in matches)
            ):
                complete = False
                failing.extend(matches)

        for route in validated.context.risk_map.routes:
            if not route.mandatory:
                continue
            for skill_name in route.required_skills:
                matches = [
                    record
                    for record in valid_records
                    if record.skill_name == skill_name
                    and route.route_id in record.route_ids
                ]
                if (
                    not matches
                    or any(not record.mandatory for record in matches)
                    or any(
                        record.status is not CoverageStatus.COMPLETED
                        for record in matches
                    )
                ):
                    complete = False
                    failing.extend(matches)

        unique_failing = {record.coverage_id: record for record in failing}
        return complete, [
            unique_failing[key] for key in sorted(unique_failing)
        ]

    def _evaluate_validated(
        self,
        validated: ValidatedPolicyContext,
    ) -> GateDecision:
        evidence_by_id = {item.evidence_id: item for item in validated.evidence}
        finding_by_id = {item.finding_id: item for item in validated.findings}

        block_matches: dict[str, list[str]] = {}
        for rule in self.policy.block_rules:
            matched = [
                finding.finding_id
                for finding in validated.findings
                if self._finding_matches_block_rule(validated, finding, rule)
            ]
            if matched:
                block_matches[rule.rule_id] = sorted(set(matched))

        integrity_tamper = any(
            issue.code in _INTEGRITY_TAMPER_CODES for issue in validated.issues
        )
        independent_strong_signals: list[str] = []
        if integrity_tamper:
            for finding in validated.findings:
                if (
                    finding.status is not FindingStatus.CONFIRMED
                    or self.policy.severity_rank[finding.severity]
                    < self.policy.severity_rank[Severity.HIGH]
                    or finding.finding_id in validated.invalid_finding_ids
                    or finding.finding_id
                    in validated.conflict_disqualified_finding_ids
                ):
                    continue
                qualified = self._qualified_evidence(
                    validated,
                    finding.finding_id,
                )
                if (
                    any(location.side == "new" for location in finding.locations)
                    and any(
                        item.level is EvidenceLevel.E3
                        and item.location is not None
                        and item.location.side == "new"
                        for item in qualified
                    )
                ):
                    independent_strong_signals.append(finding.finding_id)
        if independent_strong_signals:
            block_matches[self.policy.rule_ids.integrity_block] = sorted(
                set(independent_strong_signals)
            )

        mandatory_complete, failing_mandatory = self._mandatory_coverage(validated)
        required_artifacts_complete = all(
            len(
                [
                    artifact
                    for artifact in validated.artifacts
                    if artifact.schema_name == required.schema_name
                ]
            )
            == 1
            and any(
                artifact.schema_name == required.schema_name
                and artifact.agent_id == required.agent_id
                and artifact.agent_role == required.agent_role
                and artifact.schema_version == required.schema_version
                and artifact.status is SkillStatus.SUCCESS
                and artifact.review_id == validated.context.review_id
                for artifact in validated.artifacts
            )
            for required in self.policy.required_artifacts
        )
        coverage_complete = mandatory_complete and required_artifacts_complete

        needs_rule_ids: set[str] = set()
        review_finding_ids: set[str] = set()
        if not mandatory_complete:
            needs_rule_ids.add("N001")
        if (
            validated.context.diff_analysis.truncated
            or validated.context.diff_analysis.unsupported_files
            or any(
                item.is_binary or item.language == "unknown"
                for item in validated.context.diff_analysis.files
            )
        ):
            needs_rule_ids.add("N002")

        unresolved_conflicts = list(
            {
                item.conflict_id: item
                for item in validated.conflicts
                if not item.resolved
            }.values()
        )
        if unresolved_conflicts:
            needs_rule_ids.add("N003")
            review_finding_ids.update(
                finding_id
                for conflict in unresolved_conflicts
                for finding_id in conflict.finding_ids
                if finding_id in finding_by_id
            )

        blocking_finding_ids = {
            finding_id
            for values in block_matches.values()
            for finding_id in values
        }
        for finding in validated.findings:
            if finding.status is FindingStatus.DISMISSED:
                continue
            if finding.finding_id in blocking_finding_ids:
                continue
            severity_rank = self.policy.severity_rank[finding.severity]
            if severity_rank >= self.policy.severity_rank[Severity.HIGH]:
                needs_rule_ids.add("N004")
                review_finding_ids.add(finding.finding_id)
            elif severity_rank == self.policy.severity_rank[Severity.MEDIUM]:
                needs_rule_ids.add("N005")
                review_finding_ids.add(finding.finding_id)

        if (
            validated.issues
            or not required_artifacts_complete
            or validated.context.schema_repair_exhausted
        ):
            needs_rule_ids.add("N006")
            review_finding_ids.update(validated.invalid_finding_ids)

        provider_error_codes = set(self.policy.provider_failure_error_codes)
        if any(
            record.error_code in provider_error_codes
            for record in failing_mandatory
            if record.error_code is not None
        ):
            needs_rule_ids.add("N007")
        if validated.context.recheck_exhausted:
            needs_rule_ids.add("N008")

        ordered_block_rules = [
            rule.rule_id for rule in self.policy.block_rules if rule.rule_id in block_matches
        ]
        if self.policy.rule_ids.integrity_block in block_matches:
            ordered_block_rules.append(self.policy.rule_ids.integrity_block)
        ordered_needs_rules = [
            rule.rule_id
            for rule in self.policy.needs_review_rules
            if rule.rule_id in needs_rule_ids
        ]

        if ordered_block_rules:
            status = GateStatus.BLOCK
            matched_rule_ids = [*ordered_block_rules, *ordered_needs_rules]
            reason_summary = (
                "BLOCK: deterministic strong evidence matched "
                + ", ".join(ordered_block_rules)
                + (
                    "; review remains incomplete under "
                    + ", ".join(ordered_needs_rules)
                    if ordered_needs_rules
                    else ""
                )
                + "."
            )
        elif ordered_needs_rules:
            status = GateStatus.NEEDS_REVIEW
            matched_rule_ids = ordered_needs_rules
            reason_summary = (
                "NEEDS_REVIEW: fail-closed review conditions matched "
                + ", ".join(ordered_needs_rules)
                + "."
            )
        else:
            status = GateStatus.PASS
            matched_rule_ids = [self.policy.rule_ids.pass_rule]
            reason_summary = (
                f"PASS: all {self.policy.policy_version} mandatory checks completed "
                "with no blocking evidence."
            )

        manual_action_by_rule = {
            rule.rule_id: rule.manual_action
            for rule in self.policy.needs_review_rules
        }
        manual_actions = [
            manual_action_by_rule[rule_id]
            for rule_id in ordered_needs_rules
        ]

        warning_finding_ids = sorted(
            {
            finding.finding_id
            for finding in validated.findings
            if finding.status is not FindingStatus.DISMISSED
            and self.policy.severity_rank[finding.severity]
            <= self.policy.severity_rank[Severity.LOW]
            and finding.finding_id not in blocking_finding_ids
            and finding.finding_id not in review_finding_ids
            }
        )
        review_finding_ids.difference_update(blocking_finding_ids)

        evidence_index = [
            EvidenceIndexEntry(
                finding_id=finding.finding_id,
                evidence_ids=tuple(
                    sorted(
                    evidence_id
                    for evidence_id in finding.evidence_ids
                    if evidence_id in evidence_by_id
                    and evidence_id not in validated.invalid_evidence_ids
                    and (finding.finding_id, evidence_id)
                    not in validated.invalid_finding_evidence_pairs
                    )
                ),
            )
            for finding in {
                item.finding_id: item for item in validated.findings
            }.values()
        ]

        return GateDecision(
            review_id=validated.context.review_id,
            status=status,
            policy_version=self.policy.policy_version,
            matched_rule_ids=tuple(matched_rule_ids),
            blocking_finding_ids=tuple(sorted(blocking_finding_ids)),
            review_finding_ids=tuple(sorted(review_finding_ids)),
            warning_finding_ids=tuple(warning_finding_ids),
            coverage_complete=coverage_complete,
            unresolved_conflict_ids=tuple(
                item.conflict_id for item in unresolved_conflicts
            ),
            reason_summary=reason_summary,
            manual_actions=tuple(manual_actions),
            evidence_index=tuple(evidence_index),
            trace_id=validated.context.trace_id,
            decided_at=validated.context.decided_at,
        )


def evaluate_gate(
    context: PolicyEvaluationContext,
    policy: PolicyDocument,
) -> GateDecision:
    """Evaluate a known policy; unexpected engine failures remain visible."""

    return PolicyEngine(policy).evaluate(context)


def safe_evaluate_gate(
    context: PolicyEvaluationContext,
    policy: PolicyDocument | None,
) -> GateDecision:
    """Fail closed when policy loading or the engine itself is unavailable."""

    if policy is None:
        return _failed_decision(
            context,
            policy_version="mvp-1.0.0",
            rule_id="F002",
            summary="FAILED: the requested policy is unavailable or invalid.",
        )
    try:
        return evaluate_gate(context, policy)
    except Exception:
        return _failed_decision(
            context,
            policy_version=policy.policy_version,
            rule_id=policy.rule_ids.engine_failure,
            summary="FAILED: the deterministic policy engine could not complete.",
        )
