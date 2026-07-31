from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

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
    GateDecision,
    GateStatus,
    ReviewRequest,
    ReviewStage,
    RiskCategory,
    RiskMap,
    RiskRoute,
    Severity,
    SkillStatus,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def location(**updates: object) -> CodeLocation:
    values: dict[str, object] = {
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 12,
        "side": "new",
        "hunk_id": "hunk-1",
        "snippet_hash": "snippet-hash",
    }
    values.update(updates)
    return CodeLocation.model_validate(values)


def file_change(**updates: object) -> FileChange:
    values: dict[str, object] = {
        "file_id": "file-1",
        "old_path": "src/app.py",
        "new_path": "src/app.py",
        "change_type": ChangeType.MODIFIED,
        "language": "python",
        "additions": 2,
        "deletions": 1,
        "is_binary": False,
        "content_hash": "diff-content-hash",
        "hunk_ids": ("hunk-1",),
    }
    values.update(updates)
    return FileChange.model_validate(values)


def diff_analysis(**updates: object) -> DiffAnalysis:
    values: dict[str, object] = {
        "review_id": "review-1",
        "diff_hash": "diff-hash",
        "files": (file_change(),),
        "total_additions": 2,
        "total_deletions": 1,
        "changed_lines": 3,
        "summary": "A bounded Python change.",
        "change_intents": ("validate input",),
        "affected_symbols": ("validate",),
        "truncated": False,
        "unsupported_files": (),
        "parser_version": "1.0.0",
    }
    values.update(updates)
    return DiffAnalysis.model_validate(values)


def risk_route(**updates: object) -> RiskRoute:
    values: dict[str, object] = {
        "route_id": "route-1",
        "category": RiskCategory.SECRET,
        "severity_hint": Severity.HIGH,
        "locations": (location(),),
        "required_skills": ("detect_secret",),
        "reason": "A new string literal requires secret detection.",
        "mandatory": True,
        "route_source": "rule",
    }
    values.update(updates)
    return RiskRoute.model_validate(values)


def risk_map(**updates: object) -> RiskMap:
    values: dict[str, object] = {
        "review_id": "review-1",
        "routes": (risk_route(),),
        "always_on_skills": ("detect_secret", "review_code_quality"),
        "planned_skill_count": 2,
        "skipped_candidates": (),
        "model_used": False,
    }
    values.update(updates)
    return RiskMap.model_validate(values)


def evidence(**updates: object) -> Evidence:
    values: dict[str, object] = {
        "evidence_id": "evidence-1",
        "level": EvidenceLevel.E3,
        "source": EvidenceSource.RULE,
        "detector_name": "detect_secret",
        "detector_version": "1.0.0",
        "summary": "A deterministic synthetic credential pattern matched.",
        "location": location(),
        "reproducible": True,
        "confidence": 1.0,
        "artifact_ref": "artifacts/evidence-1.json",
        "content_hash": "evidence-hash",
        "created_at": NOW,
    }
    values.update(updates)
    return Evidence.model_validate(values)


def finding(**updates: object) -> Finding:
    values: dict[str, object] = {
        "finding_id": "finding-1",
        "category": RiskCategory.SECRET,
        "title": "Synthetic credential introduced",
        "claim": "A credential-shaped value is present on a new line.",
        "severity": Severity.HIGH,
        "status": FindingStatus.CONFIRMED,
        "locations": (location(),),
        "evidence_ids": ("evidence-1",),
        "confidence": 1.0,
        "recommendation": "Remove the value and rotate the synthetic credential.",
        "agent_id": "security-scanner",
        "fingerprint": "finding-fingerprint",
    }
    values.update(updates)
    return Finding.model_validate(values)


def coverage(**updates: object) -> CoverageRecord:
    values: dict[str, object] = {
        "coverage_id": "coverage-1",
        "skill_name": "detect_secret",
        "skill_version": "1.0.0",
        "status": CoverageStatus.COMPLETED,
        "mandatory": True,
        "route_ids": ("route-1",),
        "files_checked": ("src/app.py",),
        "reason": "All new Python lines were checked.",
        "error_code": None,
        "duration_ms": 12,
    }
    values.update(updates)
    return CoverageRecord.model_validate(values)


def artifact(**updates: object) -> AgentArtifact:
    values: dict[str, object] = {
        "artifact_id": "artifact-1",
        "review_id": "review-1",
        "agent_id": "security-scanner",
        "agent_role": "Security Scanner",
        "schema_name": "SecurityReview",
        "schema_version": "1.0.0",
        "findings": (finding(),),
        "evidence": (evidence(),),
        "coverage": (coverage(),),
        "summary": "Security review completed.",
        "input_artifact_ids": (),
        "model_name": None,
        "prompt_version": None,
        "started_at": NOW,
        "completed_at": NOW + timedelta(seconds=1),
        "status": SkillStatus.SUCCESS,
    }
    values.update(updates)
    return AgentArtifact.model_validate(values)


def conflict(**updates: object) -> EvidenceConflict:
    values: dict[str, object] = {
        "conflict_id": "conflict-1",
        "finding_ids": ("finding-1",),
        "rule_ids": ("N001",),
        "type": "coverage_gap",
        "description": "The finding conflicts with an incomplete coverage rule.",
        "requires_recheck": True,
        "resolved": False,
        "resolution": None,
    }
    values.update(updates)
    return EvidenceConflict.model_validate(values)


def decision(**updates: object) -> GateDecision:
    values: dict[str, object] = {
        "review_id": "review-1",
        "status": GateStatus.PASS,
        "policy_version": "mvp-1.0.0",
        "matched_rule_ids": ("P001",),
        "blocking_finding_ids": (),
        "review_finding_ids": (),
        "warning_finding_ids": (),
        "coverage_complete": True,
        "unresolved_conflict_ids": (),
        "reason_summary": "All mandatory checks completed.",
        "manual_actions": (),
        "evidence_index": (),
        "trace_id": "trace-1",
        "decided_at": NOW,
    }
    values.update(updates)
    return GateDecision.model_validate(values)


PUBLIC_CONTRACTS = [
    ReviewRequest(repository_path="D:/repository"),
    location(),
    file_change(),
    diff_analysis(),
    risk_route(),
    risk_map(),
    evidence(),
    finding(),
    coverage(),
    artifact(),
    conflict(),
    decision(),
]


@pytest.mark.parametrize("instance", PUBLIC_CONTRACTS, ids=lambda item: type(item).__name__)
def test_all_twelve_contracts_round_trip_json(instance: object) -> None:
    model_type = type(instance)
    restored = model_type.model_validate_json(instance.model_dump_json())

    assert restored == instance


@pytest.mark.parametrize("instance", PUBLIC_CONTRACTS, ids=lambda item: type(item).__name__)
def test_all_twelve_contracts_reject_extra_fields(instance: object) -> None:
    payload = instance.model_dump(mode="json")
    payload["unexpected"] = True

    with pytest.raises(ValidationError):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", PUBLIC_CONTRACTS, ids=lambda item: type(item).__name__)
def test_all_twelve_json_schemas_forbid_additional_properties(instance: object) -> None:
    assert type(instance).model_json_schema()["additionalProperties"] is False


def test_all_contract_collections_are_deeply_immutable_tuples() -> None:
    collections = (
        file_change().hunk_ids,
        diff_analysis().files,
        diff_analysis().change_intents,
        diff_analysis().affected_symbols,
        diff_analysis().unsupported_files,
        risk_route().locations,
        risk_route().required_skills,
        risk_map().routes,
        risk_map().always_on_skills,
        risk_map().skipped_candidates,
        finding().locations,
        finding().evidence_ids,
        coverage().route_ids,
        coverage().files_checked,
        artifact().findings,
        artifact().evidence,
        artifact().coverage,
        artifact().input_artifact_ids,
        conflict().finding_ids,
        conflict().rule_ids,
        decision().matched_rule_ids,
        decision().evidence_index,
    )

    assert all(isinstance(items, tuple) for items in collections)
    assert all(not hasattr(items, "clear") for items in collections)


def test_frozen_enum_values_are_exact() -> None:
    assert [item.value for item in GateStatus] == [
        "PASS",
        "BLOCK",
        "NEEDS_REVIEW",
        "FAILED",
    ]
    assert [item.value for item in EvidenceLevel] == ["E0", "E1", "E2", "E3"]
    assert [item.value for item in Severity] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
    assert [item.value for item in FindingStatus] == [
        "confirmed",
        "suspected",
        "dismissed",
        "unverified",
    ]
    assert [item.value for item in EvidenceSource] == [
        "rule",
        "static_tool",
        "llm",
        "human",
        "system",
    ]
    assert [item.value for item in SkillStatus] == [
        "success",
        "partial",
        "skipped",
        "failed",
    ]
    assert [item.value for item in CoverageStatus] == [
        "completed",
        "skipped",
        "failed",
        "not_applicable",
    ]
    assert [item.value for item in ChangeType] == [
        "added",
        "modified",
        "deleted",
        "renamed",
    ]
    assert [item.value for item in ReviewStage] == [
        "created",
        "diff_parsed",
        "risk_mapped",
        "reviews_running",
        "evidence_collected",
        "evidence_validated",
        "recheck_requested",
        "policy_evaluated",
        "completed",
        "failed",
    ]
    assert [item.value for item in RiskCategory] == [
        "secret",
        "sql_injection",
        "command_injection",
        "dangerous_call",
        "auth_boundary",
        "logic",
        "exception_handling",
        "performance",
        "test_gap",
        "scope_limit",
        "tool_failure",
    ]


def test_review_request_applies_defaults_and_bounds() -> None:
    request = ReviewRequest(repository_path="D:/repository")

    assert request.base_revision == "HEAD"
    assert request.include_staged is True
    assert request.include_untracked is False
    assert request.max_changed_lines == 1000
    with pytest.raises(ValidationError):
        ReviewRequest(repository_path="relative/repository")
    with pytest.raises(ValidationError):
        ReviewRequest(repository_path="D:/repository", max_changed_lines=5001)


@pytest.mark.parametrize(
    "bad_path",
    [
        "/absolute.py",
        "../escape.py",
        "src/./app.py",
        "src/app.py/",
        r"src\\app.py",
        "C:/outside.py",
        "C:outside.py",
        "src/app.py:stream",
        "src/\x00app.py",
    ],
)
def test_code_location_rejects_non_relative_posix_paths(bad_path: str) -> None:
    with pytest.raises(ValidationError):
        location(file_path=bad_path)


def test_code_location_rejects_reversed_lines_and_non_utc_time() -> None:
    with pytest.raises(ValidationError):
        location(start_line=20, end_line=19)
    with pytest.raises(ValidationError):
        evidence(created_at=NOW.astimezone(timezone(timedelta(hours=8))))


@pytest.mark.parametrize(
    ("change_type", "old_path", "new_path"),
    [
        (ChangeType.ADDED, "src/old.py", "src/new.py"),
        (ChangeType.DELETED, "src/old.py", "src/new.py"),
        (ChangeType.MODIFIED, None, "src/new.py"),
        (ChangeType.RENAMED, "src/app.py", "src/app.py"),
    ],
)
def test_file_change_paths_follow_change_type(
    change_type: ChangeType,
    old_path: str | None,
    new_path: str | None,
) -> None:
    with pytest.raises(ValidationError):
        file_change(
            change_type=change_type,
            old_path=old_path,
            new_path=new_path,
        )


def test_modified_file_cannot_hide_a_rename() -> None:
    with pytest.raises(ValidationError):
        file_change(
            change_type=ChangeType.MODIFIED,
            old_path="src/old.py",
            new_path="src/new.py",
        )


def test_diff_analysis_rejects_inconsistent_totals_and_duplicate_intents() -> None:
    with pytest.raises(ValidationError):
        diff_analysis(changed_lines=4)
    with pytest.raises(ValidationError):
        diff_analysis(change_intents=("same", "same"))


def test_risk_map_requires_detect_secret_and_consistent_skill_count() -> None:
    with pytest.raises(ValidationError):
        risk_map(always_on_skills=("review_code_quality",))
    with pytest.raises(ValidationError):
        risk_map(planned_skill_count=3)


@pytest.mark.parametrize("level", [EvidenceLevel.E2, EvidenceLevel.E3])
def test_llm_evidence_cannot_exceed_e1(level: EvidenceLevel) -> None:
    with pytest.raises(ValidationError):
        evidence(
            level=level,
            source=EvidenceSource.LLM,
            reproducible=level is EvidenceLevel.E3,
        )


def test_e3_requires_reproducibility_and_location_for_non_system_sources() -> None:
    with pytest.raises(ValidationError):
        evidence(reproducible=False)
    with pytest.raises(ValidationError):
        evidence(location=None)
    system_evidence = evidence(
        source=EvidenceSource.SYSTEM,
        detector_name="policy_integrity",
        location=None,
    )
    assert system_evidence.location is None


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -0.1, 1.1])
def test_confidence_must_be_finite_and_bounded(confidence: float) -> None:
    with pytest.raises(ValidationError):
        evidence(confidence=confidence)


def test_finding_requires_location_and_evidence_for_active_claims() -> None:
    with pytest.raises(ValidationError):
        finding(locations=())
    with pytest.raises(ValidationError):
        finding(evidence_ids=())
    system_finding = finding(
        category=RiskCategory.TOOL_FAILURE,
        locations=(),
    )
    assert system_finding.locations == ()


def test_failed_coverage_requires_error_code() -> None:
    with pytest.raises(ValidationError):
        coverage(status=CoverageStatus.FAILED, error_code=None)
    with pytest.raises(ValidationError):
        coverage(status=CoverageStatus.COMPLETED, error_code="TIMEOUT")


def test_artifact_validates_model_prompt_time_and_local_evidence_references() -> None:
    with pytest.raises(ValidationError):
        artifact(model_name="deepseek-v4-pro", prompt_version=None)
    with pytest.raises(ValidationError):
        artifact(started_at=NOW + timedelta(seconds=2), completed_at=NOW)
    with pytest.raises(ValidationError):
        artifact(evidence=())


def test_conflict_resolution_fields_are_consistent() -> None:
    with pytest.raises(ValidationError):
        conflict(resolved=True, resolution=None)
    with pytest.raises(ValidationError):
        conflict(resolved=False, resolution="Already fixed.")
    with pytest.raises(ValidationError):
        conflict(
            type="contradiction",
            finding_ids=("finding-1",),
            rule_ids=(),
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"status": GateStatus.PASS, "coverage_complete": False},
        {
            "status": GateStatus.BLOCK,
            "coverage_complete": True,
            "matched_rule_ids": ("B001",),
            "blocking_finding_ids": (),
        },
        {
            "status": GateStatus.NEEDS_REVIEW,
            "coverage_complete": False,
            "matched_rule_ids": ("N001",),
            "manual_actions": (),
        },
        {
            "status": GateStatus.FAILED,
            "coverage_complete": True,
            "matched_rule_ids": ("F001",),
        },
    ],
)
def test_gate_decision_enforces_status_invariants(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        decision(**updates)


def test_nullable_contract_fields_remain_required() -> None:
    coverage_required = set(CoverageRecord.model_json_schema()["required"])
    artifact_required = set(AgentArtifact.model_json_schema()["required"])

    assert "error_code" in coverage_required
    assert {"model_name", "prompt_version"} <= artifact_required


@pytest.mark.parametrize(
    ("model", "field_name", "bad_value"),
    [
        (ReviewRequest, "include_staged", "false"),
        (ReviewRequest, "max_changed_lines", "100"),
        (CoverageRecord, "duration_ms", "10"),
        (Evidence, "confidence", "0.5"),
    ],
)
def test_contracts_reject_implicit_primitive_coercion(
    model: type[object],
    field_name: str,
    bad_value: object,
) -> None:
    factories = {
        ReviewRequest: {"repository_path": "D:/repository"},
        CoverageRecord: coverage().model_dump(mode="python"),
        Evidence: evidence().model_dump(mode="python"),
    }
    payload = factories[model]
    payload[field_name] = bad_value

    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_gate_decision_requires_coherent_rule_and_finding_indexes() -> None:
    indexed = (
        {"finding_id": "finding-1", "evidence_ids": ("evidence-1",)},
    )
    with pytest.raises(ValidationError):
        decision(status=GateStatus.PASS, matched_rule_ids=("B001",))
    with pytest.raises(ValidationError):
        decision(
            status=GateStatus.NEEDS_REVIEW,
            matched_rule_ids=("N004",),
            coverage_complete=True,
            review_finding_ids=("finding-1",),
            manual_actions=("Inspect the finding.",),
            evidence_index=(),
        )
    with pytest.raises(ValidationError):
        decision(
            status=GateStatus.BLOCK,
            matched_rule_ids=("B001",),
            blocking_finding_ids=("finding-1",),
            review_finding_ids=("finding-1",),
            evidence_index=indexed,
        )
