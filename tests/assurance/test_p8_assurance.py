from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from codesentinel.assurance import (
    EvidenceAssurance,
    FindingEvidenceAppend,
    FindingResolution,
    RecheckResult,
    RiskRouter,
    SemanticRiskHint,
    TargetedRecheckController,
    reconcile_coverage,
)
from codesentinel.domain import (
    AgentArtifact,
    ChangeType,
    CodeLocation,
    CoverageRecord,
    CoverageStatus,
    DiffAnalysis,
    Evidence,
    EvidenceLevel,
    EvidenceSource,
    FileChange,
    Finding,
    FindingStatus,
    GateStatus,
    RiskCategory,
    RiskMap,
    RiskRoute,
    Severity,
    SkillStatus,
)
from codesentinel.gitdiff import DiffLineKind
from codesentinel.policy import PolicyEvaluationContext, load_policy, safe_evaluate_gate
from codesentinel.skills.security import SanitizedDiffLine, SanitizedDiffView

NOW = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
POLICY = load_policy()


def make_diff(*, additions: int = 1) -> DiffAnalysis:
    return DiffAnalysis(
        review_id="review-p8",
        diff_hash="diff-p8",
        files=(
            FileChange(
                file_id="file-p8",
                old_path="src/app.py",
                new_path="src/app.py",
                change_type=ChangeType.MODIFIED,
                language="python",
                additions=additions,
                deletions=0,
                is_binary=False,
                content_hash="file-hash",
                hunk_ids=("hunk-p8",),
            ),
        ),
        total_additions=additions,
        total_deletions=0,
        changed_lines=additions,
        summary="A bounded Python change.",
        change_intents=("change application behavior",),
        affected_symbols=("handler",),
        truncated=False,
        unsupported_files=(),
        parser_version="p5-1.0.0",
    )


def make_sanitized(*contents: str) -> SanitizedDiffView:
    return SanitizedDiffView(
        review_id="review-p8",
        source_diff_hash="diff-p8",
        lines=tuple(
            SanitizedDiffLine(
                file_path="src/app.py",
                hunk_id="hunk-p8",
                kind=DiffLineKind.ADDITION,
                side="new",
                line_number=index,
                content=content,
                source_content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                redaction_ids=(),
            )
            for index, content in enumerate(contents, start=1)
        ),
        redaction_ids=(),
        cloud_safe=True,
        reason="The source passed local secret masking.",
    )


def test_risk_router_triggers_frozen_categories_and_is_deterministic() -> None:
    lines = (
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        "subprocess.run(command, shell=True)",
        "if user.role == 'admin':",
        "for item in records:",
    )
    router = RiskRouter()
    first = router.build(make_diff(additions=4), make_sanitized(*lines))
    second = router.build(make_diff(additions=4), make_sanitized(*lines))

    assert first == second
    categories = {route.category for route in first.risk_map.routes}
    assert {
        RiskCategory.SQL_INJECTION,
        RiskCategory.COMMAND_INJECTION,
        RiskCategory.AUTH_BOUNDARY,
        RiskCategory.PERFORMANCE,
    } <= categories
    planned = {entry.skill_name for entry in first.skill_plan if entry.planned}
    assert "detect_secret" in planned
    assert "detect_injection" in planned
    assert "detect_dangerous_call" in planned


def test_every_skipped_skill_has_reason_and_coverage() -> None:
    routing = RiskRouter().build(make_diff(), make_sanitized("value = 1"))
    skipped = {item.skill for item in routing.risk_map.skipped_candidates}
    assert skipped == {"detect_injection", "detect_dangerous_call"}
    assert all(item.reason for item in routing.risk_map.skipped_candidates)

    actual = tuple(
        make_coverage(f"coverage-{name}", name)
        for name in (
            "detect_secret",
            "security_semantic_review",
            "review_code_quality",
        )
    )
    records = reconcile_coverage(routing, actual)
    skipped_records = {item.skill_name: item for item in records if item.status == "skipped"}
    assert set(skipped_records) == skipped
    assert all(item.reason and not item.mandatory for item in skipped_records.values())


def test_rule_routing_survives_semantic_failure() -> None:
    result = RiskRouter().build(
        make_diff(),
        make_sanitized("subprocess.run(command, shell=True)"),
        semantic_failure_reason="provider timeout",
    )
    assert result.semantic_status == "failed"
    assert result.risk_map.model_used is True
    assert RiskCategory.COMMAND_INJECTION in {
        route.category for route in result.risk_map.routes
    }


def test_matching_rule_and_semantic_hint_create_one_hybrid_route() -> None:
    source = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
    result = RiskRouter().build(
        make_diff(),
        make_sanitized(source),
        semantic_hints=(
            SemanticRiskHint(
                category=RiskCategory.SQL_INJECTION,
                severity_hint=Severity.HIGH,
                locations=(make_location(content=source),),
                reason="Semantic analysis identified user-controlled query construction.",
            ),
        ),
    )
    matching = [
        route
        for route in result.risk_map.routes
        if route.category is RiskCategory.SQL_INJECTION
    ]
    assert len(matching) == 1
    assert matching[0].route_source == "hybrid"
    assert result.semantic_status == "success"


def make_location(*, line: int = 1, content: str | None = None) -> CodeLocation:
    return CodeLocation(
        file_path="src/app.py",
        start_line=line,
        end_line=line,
        side="new",
        hunk_id="hunk-p8",
        snippet_hash=(
            hashlib.sha256(content.encode("utf-8")).hexdigest()
            if content is not None
            else f"line-hash-{line}"
        ),
    )


def make_coverage(
    coverage_id: str,
    skill: str,
    *,
    route_ids: tuple[str, ...] = (),
) -> CoverageRecord:
    return CoverageRecord(
        coverage_id=coverage_id,
        skill_name=skill,
        skill_version="1.0.0",
        status=CoverageStatus.COMPLETED,
        mandatory=True,
        route_ids=route_ids,
        files_checked=("src/app.py",),
        reason="The bounded changed-file scope was checked.",
        error_code=None,
        duration_ms=5,
    )


def make_risk_map() -> RiskMap:
    return RiskMap(
        review_id="review-p8",
        routes=(
            RiskRoute(
                route_id="route-secret",
                category=RiskCategory.SECRET,
                severity_hint=Severity.HIGH,
                locations=(make_location(),),
                required_skills=("detect_secret",),
                reason="Secret-like data requires deterministic verification.",
                mandatory=True,
                route_source="rule",
            ),
        ),
        always_on_skills=(
            "detect_secret",
            "security_semantic_review",
            "review_code_quality",
        ),
        planned_skill_count=3,
        skipped_candidates=(),
        model_used=False,
    )


def make_evidence(
    evidence_id: str,
    *,
    level: EvidenceLevel,
    source: EvidenceSource,
    detector: str,
    content_hash: str | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        level=level,
        source=source,
        detector_name=detector,
        detector_version="1.0.0",
        summary="A bounded risk signal was captured.",
        location=make_location(),
        reproducible=level is EvidenceLevel.E3,
        confidence=1.0,
        artifact_ref=None,
        content_hash=content_hash or f"hash-{evidence_id}",
        created_at=NOW,
    )


def make_finding(
    finding_id: str,
    *,
    evidence_ids: tuple[str, ...],
    status: FindingStatus,
    severity: Severity,
    agent_id: str,
    fingerprint: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        category=RiskCategory.SECRET,
        title="A secret may be exposed",
        claim="The changed line may expose a credential.",
        severity=severity,
        status=status,
        locations=(make_location(),),
        evidence_ids=evidence_ids,
        confidence=1.0,
        recommendation="Remove the credential and rotate it.",
        agent_id=agent_id,
        fingerprint=fingerprint,
    )


def make_artifact(
    *,
    security: bool,
    findings: tuple[Finding, ...] = (),
    evidence: tuple[Evidence, ...] = (),
) -> AgentArtifact:
    coverage = (
        (
            make_coverage(
                "coverage-secret",
                "detect_secret",
                route_ids=("route-secret",),
            ),
            make_coverage("coverage-security-semantic", "security_semantic_review"),
        )
        if security
        else (make_coverage("coverage-quality", "review_code_quality"),)
    )
    return AgentArtifact(
        artifact_id="artifact-security" if security else "artifact-quality",
        review_id="review-p8",
        agent_id="security-scanner" if security else "quality-reviewer",
        agent_role="Security Scanner" if security else "Quality Reviewer",
        schema_name="SecurityReview" if security else "QualityReview",
        schema_version="1.0.0",
        findings=findings,
        evidence=evidence,
        coverage=coverage,
        summary="The bounded review completed.",
        input_artifact_ids=(),
        model_name="deepseek-v4-pro",
        prompt_version="p8-test-v1",
        started_at=NOW,
        completed_at=NOW + timedelta(milliseconds=20),
        status=SkillStatus.SUCCESS,
    )


def make_context(
    security: AgentArtifact,
    quality: AgentArtifact,
    *,
    verified: tuple[str, ...] = (),
) -> PolicyEvaluationContext:
    return PolicyEvaluationContext(
        review_id="review-p8",
        trace_id="trace-p8",
        decided_at=NOW,
        diff_analysis=make_diff(),
        risk_map=make_risk_map(),
        artifacts=(security, quality),
        verified_e3_evidence_ids=verified,
    )


def test_llm_cannot_self_upgrade_and_unregistered_e3_is_invalid() -> None:
    with pytest.raises(ValidationError, match="LLM evidence cannot exceed E1"):
        make_evidence(
            "evidence-llm-e3",
            level=EvidenceLevel.E3,
            source=EvidenceSource.LLM,
            detector="security-scanner",
        )

    strong = make_evidence(
        "evidence-unregistered",
        level=EvidenceLevel.E3,
        source=EvidenceSource.RULE,
        detector="detect_secret",
    )
    finding = make_finding(
        "finding-unregistered",
        evidence_ids=(strong.evidence_id,),
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        agent_id="security-scanner",
        fingerprint="fingerprint-unregistered",
    )
    result = EvidenceAssurance().validate(
        make_context(
            make_artifact(security=True, findings=(finding,), evidence=(strong,)),
            make_artifact(security=False),
        ),
        POLICY,
    )
    assert strong.evidence_id in result.report.invalid_evidence_ids
    assert finding.finding_id in result.report.invalid_finding_ids
    assert {item.code for item in result.report.issues} >= {
        "E3_PROVENANCE_UNVERIFIED",
        "FINDING_HAS_NO_QUALIFIED_EVIDENCE",
    }


def test_dedup_and_conflicts_force_needs_review() -> None:
    strong = make_evidence(
        "evidence-strong",
        level=EvidenceLevel.E3,
        source=EvidenceSource.RULE,
        detector="detect_secret",
        content_hash="same-signal",
    )
    confirmed = make_finding(
        "finding-confirmed",
        evidence_ids=(strong.evidence_id,),
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        agent_id="security-scanner",
        fingerprint="security-fingerprint",
    )
    dismissed = make_finding(
        "finding-dismissed",
        evidence_ids=(),
        status=FindingStatus.DISMISSED,
        severity=Severity.LOW,
        agent_id="quality-reviewer",
        fingerprint="quality-fingerprint",
    )
    result = EvidenceAssurance().validate(
        make_context(
            make_artifact(security=True, findings=(confirmed,), evidence=(strong,)),
            make_artifact(security=False, findings=(dismissed,)),
            verified=(strong.evidence_id,),
        ),
        POLICY,
    )
    assert len(result.report.canonical_findings) == 1
    assert set(result.report.canonical_findings[0].member_finding_ids) == {
        confirmed.finding_id,
        dismissed.finding_id,
    }
    assert {item.type for item in result.report.conflicts} >= {
        "contradiction",
        "severity_mismatch",
    }
    decision = safe_evaluate_gate(result.context, POLICY)
    assert decision.status is GateStatus.NEEDS_REVIEW
    assert "N003" in decision.matched_rule_ids


def make_recheck_context() -> PolicyEvaluationContext:
    weak = make_evidence(
        "evidence-weak",
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector="security-scanner",
    )
    finding = make_finding(
        "finding-weak",
        evidence_ids=(weak.evidence_id,),
        status=FindingStatus.SUSPECTED,
        severity=Severity.HIGH,
        agent_id="security-scanner",
        fingerprint="fingerprint-weak",
    )
    return make_context(
        make_artifact(security=True, findings=(finding,), evidence=(weak,)),
        make_artifact(security=False),
    )


def test_one_targeted_recheck_appends_e3_and_reruns_policy() -> None:
    calls = []

    def executor(request):
        calls.append(request.request_id)
        evidence = make_evidence(
            "evidence-rechecked",
            level=EvidenceLevel.E3,
            source=EvidenceSource.RULE,
            detector="detect_secret",
        )
        return RecheckResult(
            request_id=request.request_id,
            review_id=request.review_id,
            status="success",
            additional_evidence=(evidence,),
            evidence_links=(
                FindingEvidenceAppend(
                    finding_id="finding-weak",
                    evidence_ids=(evidence.evidence_id,),
                ),
            ),
            finding_resolutions=(
                FindingResolution(
                    finding_id="finding-weak",
                    status=FindingStatus.CONFIRMED,
                    resolution="The frozen local detector reproduced the secret signal.",
                ),
            ),
            verified_e3_evidence_ids=(evidence.evidence_id,),
        )

    execution = TargetedRecheckController().run_once(
        make_recheck_context(),
        POLICY,
        executor,
    )
    assert len(calls) == 1
    assert execution.outcome.attempts == 1
    assert execution.outcome.initial_decision.status is GateStatus.NEEDS_REVIEW
    assert execution.outcome.final_decision.status is GateStatus.BLOCK
    assert execution.outcome.appended_evidence_ids == ("evidence-rechecked",)
    assert execution.context.verified_e3_evidence_ids == ("evidence-rechecked",)


def test_unresolved_recheck_is_exhausted_and_cannot_run_twice() -> None:
    calls = []

    def inconclusive(request):
        calls.append(request.request_id)
        return RecheckResult(
            request_id=request.request_id,
            review_id=request.review_id,
            status="success",
        )

    controller = TargetedRecheckController()
    first = controller.run_once(make_recheck_context(), POLICY, inconclusive)
    assert len(calls) == 1
    assert first.outcome.final_decision.status is GateStatus.NEEDS_REVIEW
    assert first.outcome.exhausted is True
    assert "N008" in first.outcome.final_decision.matched_rule_ids

    second = controller.run_once(
        first.context,
        POLICY,
        inconclusive,
        previous_attempts=1,
    )
    assert len(calls) == 1
    assert second.outcome.attempts == 0
    assert second.outcome.exhausted is True


def test_targeted_recheck_can_repair_failed_mandatory_coverage() -> None:
    security = make_artifact(security=True)
    failed = CoverageRecord(
        coverage_id="coverage-secret-failed",
        skill_name="detect_secret",
        skill_version="1.0.0",
        status=CoverageStatus.FAILED,
        mandatory=True,
        route_ids=("route-secret",),
        files_checked=("src/app.py",),
        reason="The local detector timed out.",
        error_code="TIMEOUT",
        duration_ms=100,
    )
    security = AgentArtifact.model_validate_json(
        security.model_copy(
            update={"coverage": (failed, security.coverage[1])}
        ).model_dump_json()
    )
    context = make_context(security, make_artifact(security=False))

    def executor(request):
        completed = make_coverage(
            "coverage-secret-rechecked",
            "detect_secret",
            route_ids=("route-secret",),
        )
        return RecheckResult(
            request_id=request.request_id,
            review_id=request.review_id,
            status="success",
            coverage_updates=(completed,),
        )

    execution = TargetedRecheckController().run_once(context, POLICY, executor)
    assert execution.outcome.initial_decision.status is GateStatus.NEEDS_REVIEW
    assert execution.outcome.attempts == 1
    assert execution.outcome.final_decision.status is GateStatus.PASS
    assert execution.outcome.exhausted is False


def test_model_only_recheck_cannot_dismiss_a_finding() -> None:
    def executor(request):
        weak = make_evidence(
            "evidence-second-opinion",
            level=EvidenceLevel.E1,
            source=EvidenceSource.LLM,
            detector="security-scanner",
        )
        return RecheckResult(
            request_id=request.request_id,
            review_id=request.review_id,
            status="success",
            additional_evidence=(weak,),
            evidence_links=(
                FindingEvidenceAppend(
                    finding_id="finding-weak",
                    evidence_ids=(weak.evidence_id,),
                ),
            ),
            finding_resolutions=(
                FindingResolution(
                    finding_id="finding-weak",
                    status=FindingStatus.DISMISSED,
                    resolution="A second model did not reproduce the concern.",
                ),
            ),
        )

    execution = TargetedRecheckController().run_once(
        make_recheck_context(),
        POLICY,
        executor,
    )
    assert execution.outcome.final_decision.status is GateStatus.NEEDS_REVIEW
    assert execution.outcome.exhausted is True
    assert execution.outcome.appended_evidence_ids == ()
    assert "N008" in execution.outcome.final_decision.matched_rule_ids
