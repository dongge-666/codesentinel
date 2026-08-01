"""P8 evidence normalization, deduplication, and conflict identification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

from codesentinel.domain import EvidenceConflict, Finding, FindingStatus, Severity
from codesentinel.policy import (
    PolicyDocument,
    PolicyEvaluationContext,
    ValidatedPolicyContext,
    validate_policy_context,
)

from .models import (
    CanonicalEvidence,
    CanonicalFinding,
    EvidenceValidationReport,
    ValidationIssue,
)


@dataclass(frozen=True, slots=True)
class EvidenceAssuranceResult:
    context: PolicyEvaluationContext
    validated: ValidatedPolicyContext
    report: EvidenceValidationReport


def _hash(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()


def _location_key(location) -> tuple[object, ...]:
    return (
        location.file_path,
        location.hunk_id,
        location.side,
        location.start_line,
        location.end_line,
        location.snippet_hash,
    )


def normalized_finding_fingerprint(finding: Finding) -> str:
    """Return an agent-independent semantic identity for Finding deduplication."""

    locations = tuple(sorted(_location_key(item) for item in finding.locations))
    return _hash(finding.category.value, locations)


class EvidenceAssurance:
    """Create a read-only assurance view; original Agent artifacts remain immutable."""

    def validate(
        self,
        context: PolicyEvaluationContext,
        policy: PolicyDocument,
    ) -> EvidenceAssuranceResult:
        preliminary = validate_policy_context(context, policy)
        detected = self._detect_conflicts(preliminary)
        conflicts = {
            conflict.conflict_id: conflict for conflict in (*detected, *context.conflicts)
        }
        assured_context = replace(
            context,
            conflicts=tuple(conflicts[key] for key in sorted(conflicts)),
        )
        validated = validate_policy_context(assured_context, policy)
        canonical_findings = self._canonical_findings(
            validated.findings,
            validated.invalid_finding_ids,
        )
        canonical_evidence = self._canonical_evidence(
            validated.evidence,
            policy,
            validated.invalid_evidence_ids,
        )
        all_finding_ids = {item.finding_id for item in validated.findings}
        all_evidence_ids = {item.evidence_id for item in validated.evidence}
        report = EvidenceValidationReport(
            review_id=context.review_id,
            canonical_findings=canonical_findings,
            canonical_evidence=canonical_evidence,
            conflicts=validated.conflicts,
            issues=tuple(
                ValidationIssue(
                    code=item.code,
                    subject_id=item.subject_id,
                    description=item.description,
                )
                for item in validated.issues
            ),
            valid_finding_ids=tuple(sorted(all_finding_ids - validated.invalid_finding_ids)),
            invalid_finding_ids=tuple(sorted(validated.invalid_finding_ids)),
            valid_evidence_ids=tuple(sorted(all_evidence_ids - validated.invalid_evidence_ids)),
            invalid_evidence_ids=tuple(sorted(validated.invalid_evidence_ids)),
        )
        return EvidenceAssuranceResult(assured_context, validated, report)

    @staticmethod
    def _canonical_findings(
        findings: tuple[Finding, ...],
        invalid_ids: frozenset[str],
    ) -> tuple[CanonicalFinding, ...]:
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            groups.setdefault(normalized_finding_fingerprint(finding), []).append(finding)
        result = []
        for fingerprint, members in sorted(groups.items()):
            selected = max(
                members,
                key=lambda item: (item.finding_id not in invalid_ids, _finding_rank(item)),
            )
            result.append(
                CanonicalFinding(
                    canonical_id=f"canonical-finding-{fingerprint[:20]}",
                    normalized_fingerprint=fingerprint,
                    member_finding_ids=tuple(sorted(item.finding_id for item in members)),
                    selected=selected,
                )
            )
        return tuple(result)

    @staticmethod
    def _canonical_evidence(
        evidence,
        policy: PolicyDocument,
        invalid_ids: frozenset[str],
    ) -> tuple[CanonicalEvidence, ...]:
        groups: dict[tuple[object, ...], list] = {}
        for item in evidence:
            key = (
                item.content_hash,
                None if item.location is None else _location_key(item.location),
            )
            groups.setdefault(key, []).append(item)
        result = []
        for key, members in sorted(groups.items(), key=lambda item: str(item[0])):
            selected = max(
                members,
                key=lambda item: (
                    item.evidence_id not in invalid_ids,
                    policy.evidence_rank[item.level],
                ),
            )
            identity = _hash(key)
            result.append(
                CanonicalEvidence(
                    canonical_id=f"canonical-evidence-{identity[:20]}",
                    member_evidence_ids=tuple(sorted(item.evidence_id for item in members)),
                    selected=selected,
                )
            )
        return tuple(result)

    def _detect_conflicts(
        self,
        validated: ValidatedPolicyContext,
    ) -> tuple[EvidenceConflict, ...]:
        groups: dict[str, list[Finding]] = {}
        fingerprints: dict[str, list[Finding]] = {}
        for finding in validated.findings:
            groups.setdefault(normalized_finding_fingerprint(finding), []).append(finding)
            fingerprints.setdefault(finding.fingerprint, []).append(finding)

        conflicts: dict[str, EvidenceConflict] = {}
        for normalized, members in sorted(groups.items()):
            if len(members) < 2:
                continue
            finding_ids = tuple(sorted(item.finding_id for item in members))
            statuses = {item.status for item in members}
            if FindingStatus.DISMISSED in statuses and statuses & {
                FindingStatus.CONFIRMED,
                FindingStatus.SUSPECTED,
            }:
                conflict = self._conflict(
                    "contradiction",
                    finding_ids,
                    normalized,
                    "Equivalent findings disagree on whether the risk is active.",
                )
                conflicts[conflict.conflict_id] = conflict
            severities = {_severity_rank(item.severity) for item in members}
            if max(severities) - min(severities) >= 2:
                conflict = self._conflict(
                    "severity_mismatch",
                    finding_ids,
                    normalized,
                    "Equivalent findings disagree materially on severity.",
                )
                conflicts[conflict.conflict_id] = conflict

        for declared, members in sorted(fingerprints.items()):
            normalized = {normalized_finding_fingerprint(item) for item in members}
            if len(members) >= 2 and len(normalized) >= 2:
                conflict = self._conflict(
                    "location_mismatch",
                    tuple(sorted(item.finding_id for item in members)),
                    declared,
                    "The same declared fingerprint points to different changed locations.",
                )
                conflicts[conflict.conflict_id] = conflict

        coverage_by_skill = {}
        for record in validated.coverage:
            coverage_by_skill.setdefault(record.skill_name, []).append(record)
        for route in validated.context.risk_map.routes:
            related = tuple(
                item.finding_id
                for item in validated.findings
                if item.category == route.category
                and any(
                    _overlaps(left, right)
                    for left in item.locations
                    for right in route.locations
                )
            )
            if not related:
                continue
            for skill in route.required_skills:
                matches = [
                    item
                    for item in coverage_by_skill.get(skill, [])
                    if route.route_id in item.route_ids
                ]
                if matches and all(item.status.value == "completed" for item in matches):
                    continue
                identity = _hash("coverage_gap", route.route_id, skill, related)
                conflict = EvidenceConflict(
                    conflict_id=f"conflict-{identity[:20]}",
                    finding_ids=tuple(sorted(set(related))),
                    rule_ids=("N001",),
                    type="coverage_gap",
                    description=f"Mandatory routed Skill {skill} lacks completed coverage.",
                    requires_recheck=True,
                    resolved=False,
                    resolution=None,
                )
                conflicts[conflict.conflict_id] = conflict
        return tuple(conflicts[key] for key in sorted(conflicts))

    @staticmethod
    def _conflict(kind: str, finding_ids: tuple[str, ...], identity: str, description: str):
        return EvidenceConflict(
            conflict_id=f"conflict-{_hash(kind, identity, finding_ids)[:20]}",
            finding_ids=finding_ids,
            rule_ids=(),
            type=kind,
            description=description,
            requires_recheck=True,
            resolved=False,
            resolution=None,
        )


def _overlaps(left, right) -> bool:
    return (
        left.file_path == right.file_path
        and left.hunk_id == right.hunk_id
        and left.side == right.side
        and left.start_line <= right.end_line
        and right.start_line <= left.end_line
    )


def _severity_rank(value: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[value]


def _finding_rank(finding: Finding) -> tuple[int, int, float, str]:
    status = {
        FindingStatus.DISMISSED: 0,
        FindingStatus.UNVERIFIED: 1,
        FindingStatus.SUSPECTED: 2,
        FindingStatus.CONFIRMED: 3,
    }[finding.status]
    return (status, _severity_rank(finding.severity), finding.confidence, finding.finding_id)
