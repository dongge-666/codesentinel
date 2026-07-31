"""Pure in-memory reference and evidence qualification for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from codesentinel.domain import (
    AgentArtifact,
    CoverageRecord,
    DiffAnalysis,
    Evidence,
    EvidenceConflict,
    EvidenceLevel,
    FileChange,
    Finding,
    FindingStatus,
    RiskMap,
)
from codesentinel.domain.models import CodeLocation

from .models import PolicyDocument


class CoreInputError(ValueError):
    """The review cannot establish a trustworthy core evaluation context."""


@dataclass(frozen=True, slots=True)
class PolicyEvaluationContext:
    review_id: str
    trace_id: str
    decided_at: datetime
    diff_analysis: DiffAnalysis
    risk_map: RiskMap
    artifacts: tuple[AgentArtifact, ...]
    verified_e3_evidence_ids: tuple[str, ...] = ()
    conflicts: tuple[EvidenceConflict, ...] = ()
    root_artifact_ids: tuple[str, ...] = ()
    schema_repair_exhausted: bool = False
    recheck_exhausted: bool = False


@dataclass(frozen=True, slots=True, order=True)
class IntegrityIssue:
    code: str
    subject_id: str
    description: str


@dataclass(frozen=True, slots=True)
class ValidatedPolicyContext:
    context: PolicyEvaluationContext
    artifacts: tuple[AgentArtifact, ...]
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    coverage: tuple[CoverageRecord, ...]
    conflicts: tuple[EvidenceConflict, ...]
    issues: tuple[IntegrityIssue, ...]
    invalid_finding_ids: frozenset[str]
    invalid_evidence_ids: frozenset[str]
    invalid_finding_evidence_pairs: frozenset[tuple[str, str]]
    invalid_coverage_ids: frozenset[str]
    conflict_disqualified_finding_ids: frozenset[str]


def _duplicates(values: list[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _location_matches_diff(
    location: CodeLocation,
    *,
    hunk_to_file: dict[str, FileChange],
) -> bool:
    file_change = hunk_to_file.get(location.hunk_id)
    if file_change is None:
        return False
    if location.side == "old":
        return file_change.old_path == location.file_path
    return file_change.new_path == location.file_path


def _locations_support_same_claim(
    evidence_location: CodeLocation,
    finding_location: CodeLocation,
) -> bool:
    """Require evidence to support the same changed-side region as its finding."""

    return (
        evidence_location.file_path == finding_location.file_path
        and evidence_location.hunk_id == finding_location.hunk_id
        and evidence_location.side == finding_location.side
        and evidence_location.start_line <= finding_location.end_line
        and finding_location.start_line <= evidence_location.end_line
    )


def _lineage_cycle_ids(artifacts: tuple[AgentArtifact, ...]) -> set[str]:
    graph = {
        artifact.artifact_id: {
            item
            for item in artifact.input_artifact_ids
            if item in {candidate.artifact_id for candidate in artifacts}
        }
        for artifact in artifacts
    }
    visiting: set[str] = set()
    visited: set[str] = set()
    cycles: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        if node in visiting:
            if node in path:
                cycles.update(path[path.index(node) :])
            return
        if node in visited:
            return
        visiting.add(node)
        for parent in sorted(graph.get(node, set())):
            visit(parent, (*path, node))
        visiting.remove(node)
        visited.add(node)

    for artifact_id in sorted(graph):
        visit(artifact_id, ())
    return cycles


def validate_policy_context(
    context: PolicyEvaluationContext,
    policy: PolicyDocument,
) -> ValidatedPolicyContext:
    """Validate the closed reference graph without executing tools or doing I/O."""

    if not isinstance(context, PolicyEvaluationContext):
        raise CoreInputError("context must be a PolicyEvaluationContext")
    if not isinstance(context.review_id, str) or not isinstance(context.trace_id, str):
        raise CoreInputError("review_id and trace_id must be strings")
    if not context.review_id.strip() or not context.trace_id.strip():
        raise CoreInputError("review_id and trace_id must be non-empty")
    if not isinstance(context.decided_at, datetime):
        raise CoreInputError("decided_at must be a datetime")
    if context.decided_at.tzinfo is None or context.decided_at.utcoffset() is None:
        raise CoreInputError("decided_at must be timezone-aware")
    if context.decided_at.utcoffset().total_seconds() != 0:
        raise CoreInputError("decided_at must use UTC")
    if not isinstance(context.diff_analysis, DiffAnalysis):
        raise CoreInputError("diff_analysis must be a DiffAnalysis")
    if not isinstance(context.risk_map, RiskMap):
        raise CoreInputError("risk_map must be a RiskMap")
    if not isinstance(context.artifacts, tuple) or not all(
        isinstance(item, AgentArtifact) for item in context.artifacts
    ):
        raise CoreInputError("artifacts must be a tuple of AgentArtifact")
    if not isinstance(context.conflicts, tuple) or not all(
        isinstance(item, EvidenceConflict) for item in context.conflicts
    ):
        raise CoreInputError("conflicts must be a tuple of EvidenceConflict")
    if not isinstance(context.root_artifact_ids, tuple) or not all(
        isinstance(item, str) for item in context.root_artifact_ids
    ):
        raise CoreInputError("root_artifact_ids must be a tuple of strings")
    if not isinstance(context.verified_e3_evidence_ids, tuple) or not all(
        isinstance(item, str) for item in context.verified_e3_evidence_ids
    ):
        raise CoreInputError("verified_e3_evidence_ids must be a tuple of strings")
    if not isinstance(context.schema_repair_exhausted, bool) or not isinstance(
        context.recheck_exhausted,
        bool,
    ):
        raise CoreInputError("exhaustion flags must be booleans")
    try:
        context = replace(
            context,
            diff_analysis=DiffAnalysis.model_validate_json(
                context.diff_analysis.model_dump_json()
            ),
            risk_map=RiskMap.model_validate_json(context.risk_map.model_dump_json()),
            artifacts=tuple(
                AgentArtifact.model_validate_json(item.model_dump_json())
                for item in context.artifacts
            ),
            conflicts=tuple(
                EvidenceConflict.model_validate_json(item.model_dump_json())
                for item in context.conflicts
            ),
        )
    except Exception as exc:
        raise CoreInputError(
            "context models failed defensive revalidation"
        ) from exc
    if context.diff_analysis.review_id != context.review_id:
        raise CoreInputError("DiffAnalysis review_id does not match the context")
    if context.risk_map.review_id != context.review_id:
        raise CoreInputError("RiskMap review_id does not match the context")
    if len(context.root_artifact_ids) != len(set(context.root_artifact_ids)):
        raise CoreInputError("root_artifact_ids must be unique")
    if len(context.verified_e3_evidence_ids) != len(
        set(context.verified_e3_evidence_ids)
    ):
        raise CoreInputError("verified_e3_evidence_ids must be unique")

    artifacts = tuple(sorted(context.artifacts, key=lambda item: item.artifact_id))
    findings = tuple(
        sorted(
            (finding for artifact in artifacts for finding in artifact.findings),
            key=lambda item: item.finding_id,
        )
    )
    evidence = tuple(
        sorted(
            (item for artifact in artifacts for item in artifact.evidence),
            key=lambda item: item.evidence_id,
        )
    )
    coverage = tuple(
        sorted(
            (item for artifact in artifacts for item in artifact.coverage),
            key=lambda item: item.coverage_id,
        )
    )
    conflicts = tuple(sorted(context.conflicts, key=lambda item: item.conflict_id))

    issues: list[IntegrityIssue] = []
    invalid_finding_ids: set[str] = set()
    invalid_evidence_ids: set[str] = set()
    invalid_finding_evidence_pairs: set[tuple[str, str]] = set()
    invalid_coverage_ids: set[str] = set()
    conflict_disqualified_finding_ids: set[str] = set()

    duplicate_sets = (
        ("DUPLICATE_ARTIFACT_ID", [item.artifact_id for item in artifacts]),
        ("DUPLICATE_FINDING_ID", [item.finding_id for item in findings]),
        ("DUPLICATE_EVIDENCE_ID", [item.evidence_id for item in evidence]),
        ("DUPLICATE_COVERAGE_ID", [item.coverage_id for item in coverage]),
        ("DUPLICATE_CONFLICT_ID", [item.conflict_id for item in conflicts]),
    )
    for code, values in duplicate_sets:
        for duplicate in sorted(_duplicates(values)):
            issues.append(IntegrityIssue(code, duplicate, "ID is not unique in the review"))
            if code == "DUPLICATE_FINDING_ID":
                invalid_finding_ids.add(duplicate)
            elif code == "DUPLICATE_EVIDENCE_ID":
                invalid_evidence_ids.add(duplicate)
            elif code == "DUPLICATE_COVERAGE_ID":
                invalid_coverage_ids.add(duplicate)

    for artifact in artifacts:
        if artifact.review_id != context.review_id:
            issues.append(
                IntegrityIssue(
                    "ARTIFACT_REVIEW_MISMATCH",
                    artifact.artifact_id,
                    "AgentArtifact review_id does not match the context",
                )
            )
            invalid_finding_ids.update(item.finding_id for item in artifact.findings)
            invalid_evidence_ids.update(item.evidence_id for item in artifact.evidence)
            invalid_coverage_ids.update(item.coverage_id for item in artifact.coverage)

    hunk_to_file = {
        hunk_id: file_change
        for file_change in context.diff_analysis.files
        for hunk_id in file_change.hunk_ids
    }
    known_file_paths = {
        path
        for file_change in context.diff_analysis.files
        for path in (file_change.old_path, file_change.new_path)
        if path is not None
    }
    for route in context.risk_map.routes:
        for location in route.locations:
            if not _location_matches_diff(location, hunk_to_file=hunk_to_file):
                issues.append(
                    IntegrityIssue(
                        "ROUTE_LOCATION_INVALID",
                        route.route_id,
                        "RiskRoute location does not reference the parsed diff",
                    )
                )

    qualifier_keys = {
        (item.source, item.detector_name, version)
        for item in policy.e3_qualifiers
        for version in item.detector_versions
    }
    evidence_by_id = {item.evidence_id: item for item in evidence}
    for evidence_id in context.verified_e3_evidence_ids:
        item = evidence_by_id.get(evidence_id)
        if item is None:
            issues.append(
                IntegrityIssue(
                    "VERIFIED_E3_DANGLING",
                    evidence_id,
                    "Verified E3 registry references unavailable evidence",
                )
            )
        elif item.level is not EvidenceLevel.E3:
            issues.append(
                IntegrityIssue(
                    "VERIFIED_E3_NOT_E3",
                    evidence_id,
                    "Verified E3 registry may contain only E3 evidence",
                )
            )
    for item in evidence:
        if item.location is not None and not _location_matches_diff(
            item.location,
            hunk_to_file=hunk_to_file,
        ):
            issues.append(
                IntegrityIssue(
                    "EVIDENCE_LOCATION_INVALID",
                    item.evidence_id,
                    "Evidence location does not reference the parsed diff",
                )
            )
            invalid_evidence_ids.add(item.evidence_id)
        if item.level is EvidenceLevel.E3:
            if item.evidence_id not in context.verified_e3_evidence_ids:
                issues.append(
                    IntegrityIssue(
                        "E3_PROVENANCE_UNVERIFIED",
                        item.evidence_id,
                        "E3 evidence was not registered by the trusted verifier",
                    )
                )
                invalid_evidence_ids.add(item.evidence_id)
            qualifier = (item.source, item.detector_name, item.detector_version)
            if qualifier not in qualifier_keys:
                issues.append(
                    IntegrityIssue(
                        "E3_DETECTOR_NOT_ALLOWED",
                        item.evidence_id,
                        "E3 detector identity is not allow-listed by this policy",
                    )
                )
                invalid_evidence_ids.add(item.evidence_id)

    for finding in findings:
        if any(
            not _location_matches_diff(location, hunk_to_file=hunk_to_file)
            for location in finding.locations
        ):
            issues.append(
                IntegrityIssue(
                    "FINDING_LOCATION_INVALID",
                    finding.finding_id,
                    "Finding location does not reference the parsed diff",
                )
            )
            invalid_finding_ids.add(finding.finding_id)
        missing = sorted(
            evidence_id
            for evidence_id in finding.evidence_ids
            if evidence_id not in evidence_by_id
        )
        if missing:
            issues.append(
                IntegrityIssue(
                    "FINDING_EVIDENCE_DANGLING",
                    finding.finding_id,
                    "Finding references unavailable evidence",
                )
            )
            invalid_finding_ids.add(finding.finding_id)
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if (
                item is None
                or not finding.locations
                or (
                    item.location is not None
                    and any(
                        _locations_support_same_claim(item.location, location)
                        for location in finding.locations
                    )
                )
            ):
                continue
            issues.append(
                IntegrityIssue(
                    "EVIDENCE_FINDING_LOCATION_MISMATCH",
                    f"{finding.finding_id}:{evidence_id}",
                    "Evidence does not support the finding's changed-side location",
                )
            )
            invalid_finding_evidence_pairs.add((finding.finding_id, evidence_id))
        usable = [
            evidence_by_id[evidence_id]
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
            and evidence_id not in invalid_evidence_ids
            and (finding.finding_id, evidence_id)
            not in invalid_finding_evidence_pairs
        ]
        if (
            finding.status in {FindingStatus.CONFIRMED, FindingStatus.SUSPECTED}
            and not any(item.level is not EvidenceLevel.E0 for item in usable)
        ):
            issues.append(
                IntegrityIssue(
                    "FINDING_HAS_NO_QUALIFIED_EVIDENCE",
                    finding.finding_id,
                    "Confirmed or suspected finding has no qualified evidence above E0",
                )
            )
            invalid_finding_ids.add(finding.finding_id)

    route_ids = {route.route_id for route in context.risk_map.routes}
    for record in coverage:
        missing_routes = sorted(set(record.route_ids) - route_ids)
        if missing_routes:
            issues.append(
                IntegrityIssue(
                    "COVERAGE_ROUTE_DANGLING",
                    record.coverage_id,
                    "Coverage references an unavailable route",
                )
            )
            invalid_coverage_ids.add(record.coverage_id)
        if any(path not in known_file_paths for path in record.files_checked):
            issues.append(
                IntegrityIssue(
                    "COVERAGE_FILE_INVALID",
                    record.coverage_id,
                    "Coverage references a file outside the parsed diff",
                )
            )
            invalid_coverage_ids.add(record.coverage_id)

    def matching_records(skill_name: str, route_id: str | None) -> list[CoverageRecord]:
        return [
            record
            for record in coverage
            if record.skill_name == skill_name
            and (route_id is None or route_id in record.route_ids)
        ]

    for skill_name in context.risk_map.always_on_skills:
        matches = matching_records(skill_name, None)
        if not matches:
            issues.append(
                IntegrityIssue(
                    "PLANNED_COVERAGE_MISSING",
                    skill_name,
                    "Always-on skill has no CoverageRecord",
                )
            )
        if skill_name in policy.always_required_skills:
            for record in matches:
                if not record.mandatory:
                    issues.append(
                        IntegrityIssue(
                            "MANDATORY_COVERAGE_DOWNGRADED",
                            record.coverage_id,
                            "Policy-required coverage cannot be marked optional",
                        )
                    )
                    invalid_coverage_ids.add(record.coverage_id)

    for route in context.risk_map.routes:
        for skill_name in route.required_skills:
            matches = matching_records(skill_name, route.route_id)
            if not matches:
                issues.append(
                    IntegrityIssue(
                        "PLANNED_COVERAGE_MISSING",
                        f"{route.route_id}:{skill_name}",
                        "Planned route skill has no CoverageRecord",
                    )
                )
            if route.mandatory:
                for record in matches:
                    if not record.mandatory:
                        issues.append(
                            IntegrityIssue(
                                "MANDATORY_COVERAGE_DOWNGRADED",
                                record.coverage_id,
                                "Mandatory route coverage cannot be marked optional",
                            )
                        )
                        invalid_coverage_ids.add(record.coverage_id)

    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    known_artifact_ids = artifact_ids | set(context.root_artifact_ids)
    for artifact in artifacts:
        dangling = sorted(set(artifact.input_artifact_ids) - known_artifact_ids)
        if dangling:
            issues.append(
                IntegrityIssue(
                    "ARTIFACT_LINEAGE_DANGLING",
                    artifact.artifact_id,
                    "Artifact lineage contains an unavailable parent",
                )
            )
    for artifact_id in sorted(_lineage_cycle_ids(artifacts)):
        issues.append(
            IntegrityIssue(
                "ARTIFACT_LINEAGE_CYCLE",
                artifact_id,
                "Artifact lineage must be acyclic",
            )
        )

    finding_ids = {item.finding_id for item in findings}
    known_rule_ids = {
        policy.rule_ids.pass_rule,
        policy.rule_ids.input_failure,
        policy.rule_ids.policy_failure,
        policy.rule_ids.engine_failure,
        policy.rule_ids.integrity_block,
        *(item.rule_id for item in policy.block_rules),
        *(item.rule_id for item in policy.needs_review_rules),
    }
    for conflict in conflicts:
        if set(conflict.finding_ids) - finding_ids:
            issues.append(
                IntegrityIssue(
                    "CONFLICT_FINDING_DANGLING",
                    conflict.conflict_id,
                    "EvidenceConflict references an unavailable finding",
                )
            )
        if set(conflict.rule_ids) - known_rule_ids:
            issues.append(
                IntegrityIssue(
                    "CONFLICT_RULE_DANGLING",
                    conflict.conflict_id,
                    "EvidenceConflict references an unavailable policy rule",
                )
            )
        if not conflict.resolved and conflict.type in {
            "contradiction",
            "severity_mismatch",
            "location_mismatch",
        }:
            conflict_disqualified_finding_ids.update(
                finding_id
                for finding_id in conflict.finding_ids
                if finding_id in finding_ids
            )

    return ValidatedPolicyContext(
        context=context,
        artifacts=artifacts,
        findings=findings,
        evidence=evidence,
        coverage=coverage,
        conflicts=conflicts,
        issues=tuple(sorted(set(issues))),
        invalid_finding_ids=frozenset(invalid_finding_ids),
        invalid_evidence_ids=frozenset(invalid_evidence_ids),
        invalid_finding_evidence_pairs=frozenset(
            invalid_finding_evidence_pairs
        ),
        invalid_coverage_ids=frozenset(invalid_coverage_ids),
        conflict_disqualified_finding_ids=frozenset(
            conflict_disqualified_finding_ids
        ),
    )
