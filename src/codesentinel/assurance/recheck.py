"""A single bounded, append-only targeted recheck around the pure Policy Engine."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace

from codesentinel.domain import (
    AgentArtifact,
    CoverageRecord,
    CoverageStatus,
    FindingStatus,
    GateStatus,
)
from codesentinel.policy import PolicyDocument, PolicyEvaluationContext, safe_evaluate_gate

from .evidence import EvidenceAssurance
from .models import (
    RecheckOutcome,
    RecheckRequest,
    RecheckResult,
    RecheckTarget,
)

RecheckExecutor = Callable[[RecheckRequest], RecheckResult]


@dataclass(frozen=True, slots=True)
class TargetedRecheckExecution:
    context: PolicyEvaluationContext
    outcome: RecheckOutcome


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


def _overlaps(left, right) -> bool:
    return (
        left.file_path == right.file_path
        and left.hunk_id == right.hunk_id
        and left.side == right.side
        and left.start_line <= right.end_line
        and right.start_line <= left.end_line
    )


class TargetedRecheckController:
    """Plan and apply no more than one narrow recheck, then rerun Policy."""

    def __init__(self, assurance: EvidenceAssurance | None = None) -> None:
        self._assurance = assurance or EvidenceAssurance()

    def run_once(
        self,
        context: PolicyEvaluationContext,
        policy: PolicyDocument,
        executor: RecheckExecutor,
        *,
        previous_attempts: int = 0,
    ) -> TargetedRecheckExecution:
        if previous_attempts < 0 or previous_attempts > 1:
            raise ValueError("previous_attempts must be zero or one")
        assured = self._assurance.validate(context, policy)
        initial_context = assured.context
        initial_decision = safe_evaluate_gate(initial_context, policy)

        if initial_decision.status is not GateStatus.NEEDS_REVIEW:
            return self._outcome(initial_context, initial_decision, initial_decision)
        if previous_attempts == 1 or initial_context.recheck_exhausted:
            exhausted_context = replace(initial_context, recheck_exhausted=True)
            final = safe_evaluate_gate(exhausted_context, policy)
            return self._outcome(
                exhausted_context,
                initial_decision,
                final,
                exhausted=True,
            )

        request = self._plan_request(assured.validated, initial_decision)
        if request is None:
            return self._outcome(initial_context, initial_decision, initial_decision)

        try:
            result = executor(request)
        except Exception as exc:
            result = RecheckResult(
                request_id=request.request_id,
                review_id=request.review_id,
                status="failed",
                failure_reason=f"Targeted recheck executor failed: {type(exc).__name__}.",
            )
        try:
            self._validate_result_identity(request, result)
        except Exception:
            return self._exhausted_after_attempt(
                initial_context,
                initial_decision,
                policy,
                request,
            )
        if result.status != "success":
            return self._exhausted_after_attempt(
                initial_context,
                initial_decision,
                policy,
                request,
            )

        try:
            updated = self._apply_result(initial_context, request, result)
        except Exception:
            return self._exhausted_after_attempt(
                initial_context,
                initial_decision,
                policy,
                request,
            )
        reassured = self._assurance.validate(updated, policy)
        interim = safe_evaluate_gate(reassured.context, policy)
        if interim.status is GateStatus.NEEDS_REVIEW:
            final_context = replace(reassured.context, recheck_exhausted=True)
            final = safe_evaluate_gate(final_context, policy)
            exhausted = True
        else:
            final_context = reassured.context
            final = interim
            exhausted = False
        return self._outcome(
            final_context,
            initial_decision,
            final,
            request=request,
            attempts=1,
            exhausted=exhausted,
            appended=tuple(item.evidence_id for item in result.additional_evidence),
        )

    @staticmethod
    def _plan_request(validated, decision) -> RecheckRequest | None:
        findings_by_id = {item.finding_id: item for item in validated.findings}
        targets: dict[str, RecheckTarget] = {}

        for conflict in validated.conflicts:
            if conflict.resolved or not conflict.requires_recheck:
                continue
            locations = tuple(
                {
                    _location_key(location): location
                    for finding_id in conflict.finding_ids
                    if finding_id in findings_by_id
                    for location in findings_by_id[finding_id].locations
                }.values()
            )
            identity = _hash("conflict", conflict.conflict_id)
            targets[identity] = RecheckTarget(
                target_id=f"target-{identity[:20]}",
                finding_ids=conflict.finding_ids,
                conflict_ids=(conflict.conflict_id,),
                skill_names=(),
                route_ids=(),
                locations=tuple(sorted(locations, key=_location_key)),
                reason="Resolve one explicit evidence conflict at its cited location.",
            )

        targeted_finding_ids = {
            finding_id for target in targets.values() for finding_id in target.finding_ids
        }
        for finding_id in (*decision.review_finding_ids, *validated.invalid_finding_ids):
            finding = findings_by_id.get(finding_id)
            if finding is None or finding_id in targeted_finding_ids or not finding.locations:
                continue
            identity = _hash("finding", finding_id)
            targets[identity] = RecheckTarget(
                target_id=f"target-{identity[:20]}",
                finding_ids=(finding_id,),
                conflict_ids=(),
                skill_names=(),
                route_ids=(),
                locations=tuple(sorted(finding.locations, key=_location_key)),
                reason="Acquire evidence for one unresolved finding at its cited location.",
            )

        coverage = tuple(
            item
            for item in validated.coverage
            if item.coverage_id not in validated.invalid_coverage_ids
        )
        required: dict[tuple[str, str | None], tuple] = {
            (skill, None): () for skill in validated.context.risk_map.always_on_skills
        }
        for route in validated.context.risk_map.routes:
            if route.mandatory:
                for skill in route.required_skills:
                    required[(skill, route.route_id)] = route.locations
        for (skill, route_id), locations in sorted(
            required.items(), key=lambda item: (item[0][0], item[0][1] or "")
        ):
            matches = [
                item
                for item in coverage
                if item.skill_name == skill
                and (route_id is None or route_id in item.route_ids)
            ]
            if matches and all(
                item.mandatory and item.status is CoverageStatus.COMPLETED for item in matches
            ):
                continue
            identity = _hash("coverage", skill, route_id)
            targets[identity] = RecheckTarget(
                target_id=f"target-{identity[:20]}",
                finding_ids=(),
                conflict_ids=(),
                skill_names=(skill,),
                route_ids=() if route_id is None else (route_id,),
                locations=tuple(sorted(locations, key=_location_key)),
                reason="Complete one missing or failed mandatory routed Skill.",
            )

        if not targets:
            return None
        ordered = tuple(targets[key] for key in sorted(targets))
        original_evidence_ids = tuple(sorted(item.evidence_id for item in validated.evidence))
        request_digest = _hash(
            validated.context.review_id,
            *(item.target_id for item in ordered),
        )
        request_id = f"recheck-{request_digest[:20]}"
        return RecheckRequest(
            request_id=request_id,
            review_id=validated.context.review_id,
            targets=ordered,
            original_evidence_ids=original_evidence_ids,
        )

    @staticmethod
    def _validate_result_identity(request: RecheckRequest, result: RecheckResult) -> None:
        if not isinstance(result, RecheckResult):
            raise TypeError("recheck executor must return RecheckResult")
        if result.request_id != request.request_id or result.review_id != request.review_id:
            raise ValueError("recheck result does not match its request")
        if result.attempt != request.attempt:
            raise ValueError("recheck attempt does not match its request")

    def _apply_result(
        self,
        context: PolicyEvaluationContext,
        request: RecheckRequest,
        result: RecheckResult,
    ) -> PolicyEvaluationContext:
        original_ids = set(request.original_evidence_ids)
        additional_by_id = {item.evidence_id: item for item in result.additional_evidence}
        if len(additional_by_id) != len(result.additional_evidence):
            raise ValueError("recheck evidence IDs must be unique")
        if original_ids & set(additional_by_id):
            raise ValueError("recheck must append evidence instead of replacing it")
        if set(result.verified_e3_evidence_ids) - set(additional_by_id):
            raise ValueError("recheck E3 registry may reference only appended evidence")
        appended_e3_ids = {
            item.evidence_id
            for item in result.additional_evidence
            if item.level.value == "E3"
        }
        if set(result.verified_e3_evidence_ids) != appended_e3_ids:
            raise ValueError("every appended E3 item must be registered by the trusted verifier")

        target_finding_ids = {
            finding_id for target in request.targets for finding_id in target.finding_ids
        }
        target_conflict_ids = {
            conflict_id for target in request.targets for conflict_id in target.conflict_ids
        }
        target_skill_names = {
            skill_name for target in request.targets for skill_name in target.skill_names
        }
        target_route_ids = {
            route_id for target in request.targets for route_id in target.route_ids
        }
        target_locations = tuple(
            location for target in request.targets for location in target.locations
        )
        linked_evidence_ids = {
            evidence_id for link in result.evidence_links for evidence_id in link.evidence_ids
        }
        linked_evidence_sequence = tuple(
            evidence_id for link in result.evidence_links for evidence_id in link.evidence_ids
        )
        if len(linked_evidence_sequence) != len(set(linked_evidence_sequence)):
            raise ValueError("each appended evidence item may be linked only once")
        if linked_evidence_ids != set(additional_by_id):
            raise ValueError("every appended evidence item must be linked exactly by scope")
        if any(link.finding_id not in target_finding_ids for link in result.evidence_links):
            raise ValueError("recheck linked evidence outside requested findings")
        if any(
            resolution.finding_id not in target_finding_ids
            for resolution in result.finding_resolutions
        ):
            raise ValueError("recheck resolved a finding outside requested scope")
        if any(
            resolution.conflict_id not in target_conflict_ids
            for resolution in result.conflict_resolutions
        ):
            raise ValueError("recheck resolved a conflict outside requested scope")
        if any(
            record.skill_name not in target_skill_names
            or not record.mandatory
            or set(record.route_ids) - target_route_ids
            for record in result.coverage_updates
        ):
            raise ValueError("recheck updated Coverage outside requested scope")
        for evidence in result.additional_evidence:
            if evidence.location is not None and not any(
                _overlaps(evidence.location, location) for location in target_locations
            ):
                raise ValueError("recheck evidence is outside requested locations")

        evidence_by_linked_finding = {
            link.finding_id: tuple(additional_by_id[item] for item in link.evidence_ids)
            for link in result.evidence_links
        }
        for resolution in result.finding_resolutions:
            if resolution.status not in {FindingStatus.CONFIRMED, FindingStatus.DISMISSED}:
                continue
            support = evidence_by_linked_finding.get(resolution.finding_id, ())
            if not any(
                item.source.value != "llm"
                and item.level.value in {"E2", "E3"}
                and item.location is not None
                for item in support
            ):
                raise ValueError(
                    "confirming or dismissing a finding requires new non-LLM E2/E3 evidence"
                )

        links_by_finding = {
            link.finding_id: link.evidence_ids for link in result.evidence_links
        }
        status_by_finding = {
            item.finding_id: item.status for item in result.finding_resolutions
        }
        coverage_by_skill = {item.skill_name: item for item in result.coverage_updates}
        artifacts = []
        assigned_evidence_ids: set[str] = set()
        for artifact in context.artifacts:
            local_finding_ids = {item.finding_id for item in artifact.findings}
            local_new_ids = {
                evidence_id
                for finding_id, evidence_ids in links_by_finding.items()
                if finding_id in local_finding_ids
                for evidence_id in evidence_ids
            }
            assigned_evidence_ids.update(local_new_ids)
            findings = tuple(
                finding.model_copy(
                    update={
                        "evidence_ids": tuple(
                            dict.fromkeys(
                                (
                                    *finding.evidence_ids,
                                    *links_by_finding.get(finding.finding_id, ()),
                                )
                            )
                        ),
                        "status": status_by_finding.get(finding.finding_id, finding.status),
                    }
                )
                for finding in artifact.findings
            )
            updated = artifact.model_copy(
                update={
                    "findings": findings,
                    "evidence": (
                        *artifact.evidence,
                        *(additional_by_id[item] for item in sorted(local_new_ids)),
                    ),
                    "coverage": self._updated_coverage(
                        artifact,
                        coverage_by_skill,
                    ),
                }
            )
            artifacts.append(AgentArtifact.model_validate_json(updated.model_dump_json()))
        if assigned_evidence_ids != set(additional_by_id):
            raise ValueError("recheck evidence could not be assigned to one existing artifact")

        resolutions = {item.conflict_id: item.resolution for item in result.conflict_resolutions}
        conflicts = tuple(
            conflict.model_copy(
                update={
                    "resolved": conflict.conflict_id in resolutions or conflict.resolved,
                    "resolution": resolutions.get(conflict.conflict_id, conflict.resolution),
                }
            )
            for conflict in context.conflicts
        )
        return replace(
            context,
            artifacts=tuple(artifacts),
            verified_e3_evidence_ids=tuple(
                dict.fromkeys(
                    (*context.verified_e3_evidence_ids, *result.verified_e3_evidence_ids)
                )
            ),
            conflicts=conflicts,
            recheck_exhausted=False,
        )

    @staticmethod
    def _updated_coverage(
        artifact: AgentArtifact,
        coverage_by_skill: dict[str, CoverageRecord],
    ) -> tuple[CoverageRecord, ...]:
        security_skills = {
            "detect_secret",
            "detect_injection",
            "detect_dangerous_call",
            "security_semantic_review",
        }
        allowed = security_skills if artifact.schema_name == "SecurityReview" else {
            "review_code_quality"
        }
        replacements = {
            skill: record for skill, record in coverage_by_skill.items() if skill in allowed
        }
        retained = tuple(
            item for item in artifact.coverage if item.skill_name not in replacements
        )
        return (*retained, *(replacements[key] for key in sorted(replacements)))

    def _exhausted_after_attempt(
        self,
        context: PolicyEvaluationContext,
        initial,
        policy: PolicyDocument,
        request: RecheckRequest,
    ) -> TargetedRecheckExecution:
        exhausted_context = replace(context, recheck_exhausted=True)
        final = safe_evaluate_gate(exhausted_context, policy)
        return self._outcome(
            exhausted_context,
            initial,
            final,
            request=request,
            attempts=1,
            exhausted=True,
        )

    @staticmethod
    def _outcome(
        context: PolicyEvaluationContext,
        initial,
        final,
        *,
        request: RecheckRequest | None = None,
        attempts: int = 0,
        exhausted: bool = False,
        appended: tuple[str, ...] = (),
    ) -> TargetedRecheckExecution:
        return TargetedRecheckExecution(
            context=context,
            outcome=RecheckOutcome(
                initial_decision=initial,
                request=request,
                final_decision=final,
                attempts=attempts,
                exhausted=exhausted,
                appended_evidence_ids=appended,
            ),
        )
