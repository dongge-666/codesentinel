from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import codesentinel.policy.engine as engine_module
from codesentinel.domain import (
    AgentArtifact,
    ChangeType,
    CodeLocation,
    CoverageRecord,
    CoverageStatus,
    DiffAnalysis,
    Evidence,
    EvidenceConflict,
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
from codesentinel.policy import (
    DEFAULT_POLICY_VERSION,
    PolicyDocument,
    PolicyEngine,
    PolicyEvaluationContext,
    PolicyLoadError,
    load_policy,
    safe_evaluate_gate,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
POLICY = load_policy()


def make_location(
    *,
    side: str = "new",
    start_line: int = 10,
    end_line: int | None = None,
) -> CodeLocation:
    if end_line is None:
        end_line = start_line
    return CodeLocation(
        file_path="src/app.py",
        start_line=start_line,
        end_line=end_line,
        side=side,
        hunk_id="hunk-1",
        snippet_hash=f"snippet-{side}",
    )


def make_diff(
    *,
    review_id: str = "review-1",
    truncated: bool = False,
    unsupported_files: tuple[str, ...] = (),
    language: str = "python",
    is_binary: bool = False,
) -> DiffAnalysis:
    return DiffAnalysis(
        review_id=review_id,
        diff_hash="diff-hash",
        files=(
            FileChange(
                file_id="file-1",
                old_path="src/app.py",
                new_path="src/app.py",
                change_type=ChangeType.MODIFIED,
                language=language,
                additions=2,
                deletions=1,
                is_binary=is_binary,
                content_hash="file-content-hash",
                hunk_ids=("hunk-1",),
            ),
        ),
        total_additions=2,
        total_deletions=1,
        changed_lines=3,
        summary="A bounded Python change.",
        change_intents=("validate input",),
        affected_symbols=("validate",),
        truncated=truncated,
        unsupported_files=unsupported_files,
        parser_version="1.0.0",
    )


def make_risk_map(*, review_id: str = "review-1") -> RiskMap:
    return RiskMap(
        review_id=review_id,
        routes=(
            RiskRoute(
                route_id="route-1",
                category=RiskCategory.SECRET,
                severity_hint=Severity.HIGH,
                locations=(make_location(),),
                required_skills=("detect_secret",),
                reason="New strings require deterministic secret detection.",
                mandatory=True,
                route_source="rule",
            ),
        ),
        always_on_skills=("detect_secret", "review_code_quality"),
        planned_skill_count=2,
        skipped_candidates=(),
        model_used=False,
    )


def make_coverage(
    coverage_id: str,
    skill_name: str,
    *,
    mandatory: bool,
    route_ids: tuple[str, ...] = (),
    status: CoverageStatus = CoverageStatus.COMPLETED,
    error_code: str | None = None,
) -> CoverageRecord:
    return CoverageRecord(
        coverage_id=coverage_id,
        skill_name=skill_name,
        skill_version="1.0.0",
        status=status,
        mandatory=mandatory,
        route_ids=route_ids,
        files_checked=("src/app.py",),
        reason="The planned file scope was processed.",
        error_code=error_code,
        duration_ms=10,
    )


def make_evidence(
    suffix: str = "1",
    *,
    level: EvidenceLevel = EvidenceLevel.E3,
    source: EvidenceSource = EvidenceSource.RULE,
    detector_name: str = "detect_secret",
    detector_version: str = "1.0.0",
    side: str = "new",
    start_line: int = 10,
) -> Evidence:
    return Evidence(
        evidence_id=f"evidence-{suffix}",
        level=level,
        source=source,
        detector_name=detector_name,
        detector_version=detector_version,
        summary="A reproducible test signal was captured.",
        location=make_location(side=side, start_line=start_line),
        reproducible=level is EvidenceLevel.E3,
        confidence=1.0,
        artifact_ref=f"artifacts/evidence-{suffix}.json",
        content_hash=f"evidence-hash-{suffix}",
        created_at=NOW,
    )


def make_finding(
    suffix: str = "1",
    *,
    category: RiskCategory = RiskCategory.SECRET,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.CONFIRMED,
    evidence_ids: tuple[str, ...] | None = None,
    side: str = "new",
    start_line: int = 10,
) -> Finding:
    if evidence_ids is None:
        evidence_ids = (f"evidence-{suffix}",)
    return Finding(
        finding_id=f"finding-{suffix}",
        category=category,
        title="A bounded test finding",
        claim="The changed line exhibits a reviewable risk pattern.",
        severity=severity,
        status=status,
        locations=(make_location(side=side, start_line=start_line),),
        evidence_ids=evidence_ids,
        confidence=1.0,
        recommendation="Inspect and correct the changed line.",
        agent_id="security-scanner",
        fingerprint=f"fingerprint-{suffix}",
    )


def make_security_artifact(
    *,
    findings: tuple[Finding, ...] = (),
    evidence: tuple[Evidence, ...] = (),
    coverage: tuple[CoverageRecord, ...] | None = None,
    input_artifact_ids: tuple[str, ...] = (),
    status: SkillStatus = SkillStatus.SUCCESS,
    artifact_id: str = "artifact-security",
    agent_id: str = "security-scanner",
    agent_role: str = "Security Scanner",
    schema_version: str = "1.0.0",
) -> AgentArtifact:
    if coverage is None:
        coverage = (
            make_coverage(
                "coverage-security",
                "detect_secret",
                mandatory=True,
                route_ids=("route-1",),
            ),
        )
    return AgentArtifact(
        artifact_id=artifact_id,
        review_id="review-1",
        agent_id=agent_id,
        agent_role=agent_role,
        schema_name="SecurityReview",
        schema_version=schema_version,
        findings=findings,
        evidence=evidence,
        coverage=coverage,
        summary="Security review completed.",
        input_artifact_ids=input_artifact_ids,
        model_name=None,
        prompt_version=None,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        status=status,
    )


def make_quality_artifact(
    *,
    coverage_status: CoverageStatus = CoverageStatus.COMPLETED,
    error_code: str | None = None,
    findings: tuple[Finding, ...] = (),
    evidence: tuple[Evidence, ...] = (),
    coverage: tuple[CoverageRecord, ...] | None = None,
    artifact_id: str = "artifact-quality",
    agent_id: str = "quality-reviewer",
    agent_role: str = "Quality Reviewer",
    schema_version: str = "1.0.0",
) -> AgentArtifact:
    if coverage is None:
        coverage = (
            make_coverage(
                "coverage-quality",
                "review_code_quality",
                mandatory=False,
                status=coverage_status,
                error_code=error_code,
            ),
        )
    return AgentArtifact(
        artifact_id=artifact_id,
        review_id="review-1",
        agent_id=agent_id,
        agent_role=agent_role,
        schema_name="QualityReview",
        schema_version=schema_version,
        findings=findings,
        evidence=evidence,
        coverage=coverage,
        summary="Quality review completed.",
        input_artifact_ids=(),
        model_name="deepseek-v4-pro",
        prompt_version="quality-v1",
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        status=SkillStatus.SUCCESS,
    )


def make_context(
    *,
    artifacts: tuple[AgentArtifact, ...] | None = None,
    conflicts: tuple[EvidenceConflict, ...] = (),
    diff: DiffAnalysis | None = None,
    risk_map: RiskMap | None = None,
    review_id: str = "review-1",
    trace_id: str = "trace-1",
    root_artifact_ids: tuple[str, ...] = (),
    verified_e3_evidence_ids: tuple[str, ...] | None = None,
    schema_repair_exhausted: bool = False,
    recheck_exhausted: bool = False,
) -> PolicyEvaluationContext:
    if artifacts is None:
        artifacts = (make_security_artifact(), make_quality_artifact())
    if verified_e3_evidence_ids is None:
        verified_e3_evidence_ids = tuple(
            dict.fromkeys(
                item.evidence_id
                for artifact in artifacts
                for item in artifact.evidence
                if item.level is EvidenceLevel.E3
            )
        )
    return PolicyEvaluationContext(
        review_id=review_id,
        trace_id=trace_id,
        decided_at=NOW,
        diff_analysis=diff or make_diff(),
        risk_map=risk_map or make_risk_map(),
        artifacts=artifacts,
        verified_e3_evidence_ids=verified_e3_evidence_ids,
        conflicts=conflicts,
        root_artifact_ids=root_artifact_ids,
        schema_repair_exhausted=schema_repair_exhausted,
        recheck_exhausted=recheck_exhausted,
    )


def evaluate(context: PolicyEvaluationContext):
    return PolicyEngine(POLICY).evaluate(context)


def test_bundled_policy_is_version_locked_and_complete() -> None:
    assert POLICY.policy_version == DEFAULT_POLICY_VERSION
    assert [rule.rule_id for rule in POLICY.block_rules] == ["B001", "B002", "B003"]
    assert [rule.rule_id for rule in POLICY.needs_review_rules] == [
        f"N{number:03d}" for number in range(1, 9)
    ]
    assert [status.value for status in POLICY.decision_precedence] == [
        "FAILED",
        "BLOCK",
        "NEEDS_REVIEW",
        "PASS",
    ]


def test_policy_loader_rejects_unknown_version_and_filename(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match="Unsupported"):
        load_policy("mvp-9.9.9")

    wrong_name = tmp_path / "wrong-name.toml"
    wrong_name.write_text("", encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="filename"):
        load_policy(policy_path=wrong_name)


def test_policy_loader_rejects_modified_bytes(tmp_path: Path) -> None:
    bundled = (
        Path(__file__).parents[2]
        / "src"
        / "codesentinel"
        / "policies"
        / "mvp-1.0.0.toml"
    )
    policy_copy = tmp_path / "mvp-1.0.0.toml"
    policy_copy.write_bytes(bundled.read_bytes() + b"\n# modified\n")

    with pytest.raises(PolicyLoadError, match="integrity"):
        load_policy(policy_path=policy_copy)


def test_loaded_policy_is_deeply_immutable() -> None:
    assert isinstance(POLICY.block_rules, tuple)
    assert isinstance(POLICY.block_rules[0].categories, tuple)
    assert not hasattr(POLICY.block_rules, "clear")
    assert not hasattr(POLICY.severity_rank, "clear")

    with pytest.raises(ValidationError):
        POLICY.severity_rank.high = 0


def test_policy_engine_revalidates_unchecked_policy_copies() -> None:
    weakened_rule = POLICY.block_rules[0].model_copy(
        update={
            "statuses": (FindingStatus.SUSPECTED,),
            "min_evidence_level": EvidenceLevel.E1,
        }
    )
    weakened_policy = POLICY.model_copy(
        update={
            "block_rules": (
                weakened_rule,
                *POLICY.block_rules[1:],
            )
        }
    )

    with pytest.raises(ValidationError):
        PolicyEngine(weakened_policy)

    payload = POLICY.model_dump(mode="python", by_alias=True)
    payload["severity_rank"]["high"] = 0
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(payload)


def test_closed_world_baseline_passes() -> None:
    decision = evaluate(make_context())

    assert decision.status is GateStatus.PASS
    assert decision.matched_rule_ids == ("P001",)
    assert decision.coverage_complete is True
    assert decision.blocking_finding_ids == ()
    assert decision.manual_actions == ()


@pytest.mark.parametrize(
    ("category", "detector_name", "expected_rule"),
    [
        (RiskCategory.SECRET, "detect_secret", "B001"),
        (RiskCategory.COMMAND_INJECTION, "detect_injection", "B002"),
        (RiskCategory.DANGEROUS_CALL, "detect_dangerous_call", "B002"),
        (RiskCategory.SQL_INJECTION, "detect_injection", "B003"),
    ],
)
def test_new_confirmed_high_e3_findings_block(
    category: RiskCategory,
    detector_name: str,
    expected_rule: str,
) -> None:
    signal = make_evidence(detector_name=detector_name)
    finding = make_finding(category=category)
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.BLOCK
    assert decision.matched_rule_ids == (expected_rule,)
    assert decision.blocking_finding_ids == ("finding-1",)
    assert decision.review_finding_ids == ()


def test_self_reported_e3_without_trusted_registration_cannot_block() -> None:
    signal = make_evidence()
    finding = make_finding()
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        ),
        verified_e3_evidence_ids=(),
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004", "N006")
    assert decision.blocking_finding_ids == ()


def test_llm_e1_can_never_block() -> None:
    signal = make_evidence(
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    finding = make_finding(status=FindingStatus.SUSPECTED)
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004",)
    assert decision.blocking_finding_ids == ()
    assert decision.review_finding_ids == ("finding-1",)


def test_multiple_e2_signals_do_not_accidentally_become_e3() -> None:
    signals = (
        make_evidence(
            "1",
            level=EvidenceLevel.E2,
            detector_name="heuristic-a",
        ),
        make_evidence(
            "2",
            level=EvidenceLevel.E2,
            detector_name="heuristic-b",
        ),
    )
    finding = make_finding(evidence_ids=("evidence-1", "evidence-2"))
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=signals),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004",)
    assert decision.blocking_finding_ids == ()


def test_block_evidence_must_overlap_its_finding_location() -> None:
    signal = make_evidence(start_line=20)
    finding = make_finding(start_line=10)
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004", "N006")
    assert decision.blocking_finding_ids == ()
    assert decision.evidence_index[0].evidence_ids == ()


@pytest.mark.parametrize(
    "coverage_status",
    [
        CoverageStatus.FAILED,
        CoverageStatus.SKIPPED,
        CoverageStatus.NOT_APPLICABLE,
    ],
)
def test_any_non_completed_mandatory_coverage_cannot_pass(
    coverage_status: CoverageStatus,
) -> None:
    error_code = "TOOL_ERROR" if coverage_status is CoverageStatus.FAILED else None
    security_coverage = make_coverage(
        "coverage-security",
        "detect_secret",
        mandatory=True,
        route_ids=("route-1",),
        status=coverage_status,
        error_code=error_code,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(coverage=(security_coverage,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert "N001" in decision.matched_rule_ids
    assert decision.coverage_complete is False


def test_missing_and_downgraded_mandatory_coverage_fail_closed() -> None:
    unrelated = make_coverage(
        "coverage-unrelated",
        "unplanned_optional_skill",
        mandatory=False,
    )
    missing = make_context(
        artifacts=(
            make_security_artifact(coverage=(unrelated,)),
            make_quality_artifact(),
        )
    )
    downgraded = make_context(
        artifacts=(
            make_security_artifact(
                coverage=(
                    make_coverage(
                        "coverage-security",
                        "detect_secret",
                        mandatory=False,
                        route_ids=("route-1",),
                    ),
                )
            ),
            make_quality_artifact(),
        )
    )

    for context in (missing, downgraded):
        decision = evaluate(context)
        assert decision.status is GateStatus.NEEDS_REVIEW
        assert {"N001", "N006"} <= set(decision.matched_rule_ids)
        assert decision.coverage_complete is False


def test_optional_failed_coverage_does_not_prevent_pass() -> None:
    context = make_context(
        artifacts=(
            make_security_artifact(),
            make_quality_artifact(
                coverage_status=CoverageStatus.FAILED,
                error_code="OPTIONAL_TOOL_UNAVAILABLE",
            ),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.PASS
    assert decision.coverage_complete is True


def test_truncated_diff_requires_review() -> None:
    decision = evaluate(make_context(diff=make_diff(truncated=True)))

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N002",)


@pytest.mark.parametrize(
    "diff",
    [
        make_diff(unsupported_files=("src/unknown.js",)),
        make_diff(language="unknown"),
        make_diff(is_binary=True),
    ],
    ids=["unsupported-file", "unknown-language", "binary-file"],
)
def test_unsupported_or_binary_scope_never_passes(diff: DiffAnalysis) -> None:
    decision = evaluate(make_context(diff=diff))

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N002",)


def test_unresolved_conflict_disqualifies_a_blocker() -> None:
    signal = make_evidence()
    finding = make_finding()
    second_signal = make_evidence(
        "2",
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    second_finding = make_finding(
        "2",
        category=RiskCategory.LOGIC,
        severity=Severity.LOW,
        status=FindingStatus.SUSPECTED,
    )
    conflict = EvidenceConflict(
        conflict_id="conflict-1",
        finding_ids=("finding-1", "finding-2"),
        rule_ids=(),
        type="contradiction",
        description="A deterministic rule contradicts the finding claim.",
        requires_recheck=True,
        resolved=False,
        resolution=None,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(
                findings=(finding, second_finding),
                evidence=(signal, second_signal),
            ),
            make_quality_artifact(),
        ),
        conflicts=(conflict,),
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N003", "N004")
    assert decision.blocking_finding_ids == ()
    assert decision.unresolved_conflict_ids == ("conflict-1",)


def test_medium_active_finding_requires_review() -> None:
    signal = make_evidence(
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    finding = make_finding(
        category=RiskCategory.LOGIC,
        severity=Severity.MEDIUM,
        status=FindingStatus.SUSPECTED,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N005",)
    assert decision.review_finding_ids == ("finding-1",)


def test_schema_repair_exhaustion_requires_review() -> None:
    decision = evaluate(make_context(schema_repair_exhausted=True))

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N006",)


def test_provider_failure_on_mandatory_check_adds_n007() -> None:
    failed = make_coverage(
        "coverage-security",
        "detect_secret",
        mandatory=True,
        route_ids=("route-1",),
        status=CoverageStatus.FAILED,
        error_code="MODEL_ERROR",
    )
    context = make_context(
        artifacts=(
            make_security_artifact(coverage=(failed,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N001", "N007")


def test_recheck_exhaustion_requires_review() -> None:
    decision = evaluate(make_context(recheck_exhausted=True))

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N008",)


def test_missing_required_artifact_requires_review() -> None:
    decision = evaluate(make_context(artifacts=(make_security_artifact(),)))

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N006",)
    assert decision.coverage_complete is False


@pytest.mark.parametrize(
    "quality",
    [
        make_quality_artifact(
            agent_id="security-scanner",
            agent_role="Security Scanner",
        ),
        make_quality_artifact(schema_version="999.0.0"),
    ],
    ids=["wrong-role", "wrong-schema-version"],
)
def test_required_artifact_identity_is_exact(
    quality: AgentArtifact,
) -> None:
    decision = evaluate(
        make_context(artifacts=(make_security_artifact(), quality))
    )

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N006",)
    assert decision.coverage_complete is False


def test_multiple_required_artifact_submissions_fail_closed() -> None:
    second_coverage = make_coverage(
        "coverage-security-2",
        "detect_secret",
        mandatory=True,
        route_ids=("route-1",),
    )
    second_security = make_security_artifact(
        artifact_id="artifact-security-2",
        coverage=(second_coverage,),
        status=SkillStatus.FAILED,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(),
            second_security,
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N006",)
    assert decision.coverage_complete is False


def test_block_precedes_incomplete_coverage() -> None:
    signal = make_evidence()
    finding = make_finding()
    failed = make_coverage(
        "coverage-security",
        "detect_secret",
        mandatory=True,
        route_ids=("route-1",),
        status=CoverageStatus.FAILED,
        error_code="TOOL_ERROR",
    )
    context = make_context(
        artifacts=(
            make_security_artifact(
                findings=(finding,),
                evidence=(signal,),
                coverage=(failed,),
            ),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.BLOCK
    assert decision.matched_rule_ids == ("B001", "N001")
    assert decision.coverage_complete is False


def test_old_side_evidence_is_not_a_new_code_blocker() -> None:
    signal = make_evidence(side="old")
    finding = make_finding(side="old")
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004",)
    assert decision.blocking_finding_ids == ()


def test_old_side_signal_plus_integrity_issue_does_not_trigger_b004() -> None:
    signal = make_evidence(side="old")
    finding = make_finding(side="old")
    context = make_context(
        artifacts=(
            make_security_artifact(
                findings=(finding,),
                evidence=(signal,),
                input_artifact_ids=("missing-parent",),
            ),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004", "N006")
    assert "B004" not in decision.matched_rule_ids


def test_unknown_e3_detector_is_invalid_and_cannot_block() -> None:
    signal = make_evidence(detector_name="unknown-detector")
    finding = make_finding()
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N004", "N006")
    assert decision.blocking_finding_ids == ()


def test_integrity_problem_alone_does_not_trigger_b004() -> None:
    context = make_context(
        artifacts=(
            make_security_artifact(input_artifact_ids=("missing-parent",)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N006",)
    assert "B004" not in decision.matched_rule_ids


def test_integrity_problem_plus_independent_strong_signal_triggers_b004() -> None:
    signal = make_evidence(detector_name="detect_injection")
    finding = make_finding(category=RiskCategory.AUTH_BOUNDARY)
    context = make_context(
        artifacts=(
            make_security_artifact(
                findings=(finding,),
                evidence=(signal,),
                input_artifact_ids=("missing-parent",),
            ),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.BLOCK
    assert decision.matched_rule_ids == ("B004", "N006")
    assert decision.blocking_finding_ids == ("finding-1",)


def test_low_finding_is_a_warning_but_does_not_prevent_pass() -> None:
    signal = make_evidence(
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    finding = make_finding(
        category=RiskCategory.LOGIC,
        severity=Severity.LOW,
        status=FindingStatus.SUSPECTED,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        )
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.PASS
    assert decision.warning_finding_ids == ("finding-1",)
    assert decision.evidence_index[0].finding_id == "finding-1"
    assert decision.evidence_index[0].evidence_ids == ("evidence-1",)


def test_invalid_core_context_returns_failed_f001() -> None:
    context = make_context(diff=make_diff(review_id="another-review"))

    decision = evaluate(context)

    assert decision.status is GateStatus.FAILED
    assert decision.matched_rule_ids == ("F001",)
    assert decision.coverage_complete is False


def test_duplicate_finding_ids_degrade_to_review_instead_of_engine_failure() -> None:
    signal = make_evidence()
    finding = make_finding()
    security = make_security_artifact(findings=(finding,), evidence=(signal,))
    quality = make_quality_artifact(findings=(finding,), evidence=(signal,))

    decision = safe_evaluate_gate(
        make_context(artifacts=(security, quality)),
        POLICY,
    )

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert "N006" in decision.matched_rule_ids
    assert "F003" not in decision.matched_rule_ids
    assert [item.finding_id for item in decision.evidence_index] == ["finding-1"]


def test_duplicate_conflict_ids_degrade_to_review_instead_of_engine_failure() -> None:
    signal = make_evidence(
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    finding = make_finding(status=FindingStatus.SUSPECTED)
    conflict = EvidenceConflict(
        conflict_id="conflict-1",
        finding_ids=("finding-1",),
        rule_ids=("N001",),
        type="coverage_gap",
        description="A policy coverage rule is not reconciled.",
        requires_recheck=True,
        resolved=False,
        resolution=None,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        ),
        conflicts=(conflict, conflict),
    )

    decision = safe_evaluate_gate(context, POLICY)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert {"N003", "N006"} <= set(decision.matched_rule_ids)
    assert decision.unresolved_conflict_ids == ("conflict-1",)
    assert "F003" not in decision.matched_rule_ids


def test_unknown_conflict_rule_reference_fails_closed() -> None:
    signal = make_evidence(
        level=EvidenceLevel.E1,
        source=EvidenceSource.LLM,
        detector_name="semantic-review",
    )
    finding = make_finding(
        category=RiskCategory.LOGIC,
        severity=Severity.LOW,
        status=FindingStatus.SUSPECTED,
    )
    conflict = EvidenceConflict(
        conflict_id="conflict-unknown-rule",
        finding_ids=("finding-1",),
        rule_ids=("UNKNOWN-RULE",),
        type="coverage_gap",
        description="The conflict cites a rule outside the active policy.",
        requires_recheck=True,
        resolved=False,
        resolution=None,
    )
    context = make_context(
        artifacts=(
            make_security_artifact(findings=(finding,), evidence=(signal,)),
            make_quality_artifact(),
        ),
        conflicts=(conflict,),
    )

    decision = evaluate(context)

    assert decision.status is GateStatus.NEEDS_REVIEW
    assert decision.matched_rule_ids == ("N003", "N006")
    assert decision.unresolved_conflict_ids == ("conflict-unknown-rule",)


@pytest.mark.parametrize(
    "updates",
    [
        {"decided_at": None},
        {"review_id": None},
        {"trace_id": None},
    ],
)
def test_safe_wrapper_never_raises_on_malformed_context_fields(
    updates: dict[str, object],
) -> None:
    malformed = replace(make_context(), **updates)

    decision = safe_evaluate_gate(malformed, POLICY)

    assert decision.status is GateStatus.FAILED
    assert decision.matched_rule_ids == ("F001",)


def test_unavailable_policy_returns_failed_f002() -> None:
    decision = safe_evaluate_gate(make_context(), None)

    assert decision.status is GateStatus.FAILED
    assert decision.matched_rule_ids == ("F002",)


def test_unexpected_engine_error_returns_failed_f003(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_unexpected(*args: object, **kwargs: object) -> None:
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(engine_module, "validate_policy_context", raise_unexpected)

    decision = safe_evaluate_gate(make_context(), POLICY)

    assert decision.status is GateStatus.FAILED
    assert decision.matched_rule_ids == ("F003",)
    assert "sensitive internal detail" not in decision.reason_summary


def test_engine_output_is_deterministic_and_does_not_mutate_input() -> None:
    evidence = (
        make_evidence(
            "b",
            level=EvidenceLevel.E1,
            source=EvidenceSource.LLM,
            detector_name="semantic-review",
        ),
        make_evidence(
            "a",
            level=EvidenceLevel.E1,
            source=EvidenceSource.LLM,
            detector_name="semantic-review",
        ),
    )
    findings = (
        make_finding(
            "b",
            category=RiskCategory.LOGIC,
            severity=Severity.LOW,
            status=FindingStatus.SUSPECTED,
        ),
        make_finding(
            "a",
            category=RiskCategory.TEST_GAP,
            severity=Severity.INFO,
            status=FindingStatus.SUSPECTED,
        ),
    )
    security = make_security_artifact(findings=findings, evidence=evidence)
    context = make_context(
        artifacts=(make_quality_artifact(), security),
    )
    before = tuple(item.model_dump_json() for item in context.artifacts)

    first = evaluate(context)
    for _ in range(100):
        assert evaluate(context) == first

    after = tuple(item.model_dump_json() for item in context.artifacts)
    assert before == after
    assert first.warning_finding_ids == ("finding-a", "finding-b")
    assert [item.finding_id for item in first.evidence_index] == [
        "finding-a",
        "finding-b",
    ]
