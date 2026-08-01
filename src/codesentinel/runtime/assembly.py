"""P9 glue for fallbacks, semantic routes, Coverage, and review artifacts."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from codesentinel.agents import (
    QUALITY_REVIEWER_PROMPT,
    SECURITY_REVIEWER_PROMPT,
    AgentRunResult,
    ProviderErrorCode,
)
from codesentinel.assurance import (
    ALWAYS_ON_SKILLS,
    SKILL_UNIVERSE,
    RiskRoutingResult,
    SemanticRiskHint,
    SkillPlanEntry,
    reconcile_coverage,
)
from codesentinel.domain import (
    AgentArtifact,
    CodeLocation,
    CoverageRecord,
    CoverageStatus,
    DiffAnalysis,
    RiskCategory,
    RiskMap,
    Severity,
    SkillStatus,
)
from codesentinel.domain.models import SkippedCandidate
from codesentinel.gitdiff import DiffLineKind, GitDiffArtifact
from codesentinel.preflight.deepseek import DEFAULT_MODEL
from codesentinel.skills.security import SanitizedDiffView, SecurityScanResult
from codesentinel.skills.security.base import stable_id

_SECURITY_SKILLS = {
    "detect_secret",
    "detect_injection",
    "detect_dangerous_call",
    "security_semantic_review",
}


def fallback_diff_analysis(artifact: GitDiffArtifact, reason: str) -> DiffAnalysis:
    """Build a truthful deterministic DiffAnalysis when semantic analysis is absent."""

    return DiffAnalysis(
        review_id=artifact.review_id,
        diff_hash=artifact.diff_hash,
        files=tuple(item.change for item in artifact.files),
        total_additions=artifact.total_additions,
        total_deletions=artifact.total_deletions,
        changed_lines=artifact.changed_lines,
        summary=f"Deterministic fallback analysis: {reason}",
        change_intents=(),
        affected_symbols=(),
        truncated=artifact.exceeds_changed_line_limit,
        unsupported_files=artifact.unsupported_files,
        parser_version=artifact.parser_version,
    )


def fallback_routing(diff: DiffAnalysis, reason: str) -> RiskRoutingResult:
    """Deny optional source processing when a cloud-safe route cannot be built."""

    skipped = tuple(
        SkippedCandidate(skill=skill, reason=reason)
        for skill in SKILL_UNIVERSE
        if skill not in ALWAYS_ON_SKILLS
    )
    risk_map = RiskMap(
        review_id=diff.review_id,
        routes=(),
        always_on_skills=ALWAYS_ON_SKILLS,
        planned_skill_count=len(ALWAYS_ON_SKILLS),
        skipped_candidates=skipped,
        model_used=False,
    )
    return RiskRoutingResult(
        risk_map=risk_map,
        skill_plan=tuple(
            SkillPlanEntry(
                skill_name=skill,
                planned=skill in ALWAYS_ON_SKILLS,
                mandatory=skill in ALWAYS_ON_SKILLS,
                route_ids=(),
                reason=(
                    "Always-on coverage remains required under fail-closed routing."
                    if skill in ALWAYS_ON_SKILLS
                    else reason
                ),
            )
            for skill in SKILL_UNIVERSE
        ),
        semantic_status="failed",
        semantic_failure_reason=reason,
    )


def semantic_hints_from_analysis(
    analysis: DiffAnalysis,
    sanitized: SanitizedDiffView,
) -> tuple[SemanticRiskHint, ...]:
    """Map bounded Diff-Analyzer semantics to exact sanitized lines without evidence."""

    added = tuple(
        item
        for item in sanitized.lines
        if item.side == "new" and item.kind is DiffLineKind.ADDITION
    )
    if not added:
        return ()
    semantic_text = " ".join(
        (analysis.summary, *analysis.change_intents, *analysis.affected_symbols)
    ).lower()
    specs = (
        (
            RiskCategory.SQL_INJECTION,
            Severity.HIGH,
            re.compile(r"\b(sql|query|database|cursor)\b"),
            re.compile(r"\b(sql|query|execute|cursor|select|insert|update|delete)\b", re.I),
        ),
        (
            RiskCategory.COMMAND_INJECTION,
            Severity.HIGH,
            re.compile(r"\b(shell|command|subprocess|process execution)\b"),
            re.compile(r"\b(shell|command|subprocess|os\.system|os\.popen)\b", re.I),
        ),
        (
            RiskCategory.AUTH_BOUNDARY,
            Severity.HIGH,
            re.compile(r"\b(auth|authorization|permission|role|access control)\b"),
            re.compile(r"\b(auth|authorize|permission|role|is_admin|token)\b", re.I),
        ),
        (
            RiskCategory.EXCEPTION_HANDLING,
            Severity.MEDIUM,
            re.compile(r"\b(exception|error handling|failure handling)\b"),
            re.compile(r"\b(try|except|raise|error|exception)\b", re.I),
        ),
        (
            RiskCategory.PERFORMANCE,
            Severity.MEDIUM,
            re.compile(r"\b(performance|latency|n\+1|slow|loop)\b"),
            re.compile(r"\b(for|while|all|sleep|query|request)\b", re.I),
        ),
        (
            RiskCategory.TEST_GAP,
            Severity.MEDIUM,
            re.compile(r"\b(test gap|missing test|regression test|untested)\b"),
            re.compile(r"\b(test|assert|branch|return)\b", re.I),
        ),
    )
    hints = []
    for category, severity, semantic_pattern, line_pattern in specs:
        if semantic_pattern.search(semantic_text) is None:
            continue
        line = next(
            (
                item
                for item in added
                if line_pattern.search(f"{item.file_path}\n{item.content}")
            ),
            added[0],
        )
        hints.append(
            SemanticRiskHint(
                category=category,
                severity_hint=severity,
                locations=(_location(line),),
                reason=(
                    "Diff Analyzer semantics requested bounded follow-up for "
                    f"{category.value}."
                ),
            )
        )
    if not hints:
        hints.append(
            SemanticRiskHint(
                category=RiskCategory.LOGIC,
                severity_hint=Severity.LOW,
                locations=(_location(added[0]),),
                reason="Diff Analyzer semantics were used to focus quality review.",
            )
        )
    return tuple(hints)


def deterministic_security_plan(
    routing: RiskRoutingResult,
) -> dict[str, tuple[str, ...]]:
    """Return only deterministic P6 Skills that P9 is authorized to execute."""

    return {
        item.skill_name: item.route_ids
        for item in routing.skill_plan
        if item.planned
        and item.skill_name
        in {"detect_secret", "detect_injection", "detect_dangerous_call"}
    }


def assemble_review_artifacts(
    *,
    scan: SecurityScanResult,
    routing: RiskRoutingResult,
    security_run: AgentRunResult,
    quality_run: AgentRunResult,
    security_input_ids: tuple[str, ...],
    quality_input_ids: tuple[str, ...],
    files_checked: tuple[str, ...],
    now: datetime | None = None,
) -> tuple[AgentArtifact, AgentArtifact]:
    """Merge P6 and P7 outputs into the two exact P4-required artifacts."""

    timestamp = now or datetime.now(UTC)
    actual_coverage = [
        item for item in scan.coverage if item.status is not CoverageStatus.SKIPPED
    ]
    security_semantic = _agent_artifact_or_failure(
        security_run,
        review_id=scan.review_id,
        agent_id="security-scanner",
        agent_role="Security Scanner",
        schema_name="SecurityReview",
        skill_name="security_semantic_review",
        prompt_version=SECURITY_REVIEWER_PROMPT.version,
        input_ids=security_input_ids,
        files_checked=files_checked,
        timestamp=timestamp,
    )
    quality = _agent_artifact_or_failure(
        quality_run,
        review_id=scan.review_id,
        agent_id="quality-reviewer",
        agent_role="Quality Reviewer",
        schema_name="QualityReview",
        skill_name="review_code_quality",
        prompt_version=QUALITY_REVIEWER_PROMPT.version,
        input_ids=quality_input_ids,
        files_checked=files_checked,
        timestamp=timestamp,
    )
    actual_coverage.extend(security_semantic.coverage)
    actual_coverage.extend(quality.coverage)
    reconciled = reconcile_coverage(routing, tuple(actual_coverage))
    security_coverage = tuple(
        item for item in reconciled if item.skill_name in _SECURITY_SKILLS
    )
    quality_coverage = tuple(
        item for item in reconciled if item.skill_name == "review_code_quality"
    )

    findings = _unique_by_id((*scan.findings, *security_semantic.findings), "finding_id")
    evidence = _unique_by_id((*scan.evidence, *security_semantic.evidence), "evidence_id")
    started_at = min(
        *(item.started_at for item in scan.skill_results),
        security_semantic.started_at,
    )
    completed_at = max(
        *(item.completed_at for item in scan.skill_results),
        security_semantic.completed_at,
    )
    security = AgentArtifact(
        artifact_id=stable_id(
            "artifact",
            scan.review_id,
            "security-aggregate",
            security_semantic.artifact_id,
        ),
        review_id=scan.review_id,
        agent_id="security-scanner",
        agent_role="Security Scanner",
        schema_name="SecurityReview",
        schema_version="1.0.0",
        findings=findings,
        evidence=evidence,
        coverage=security_coverage,
        summary=(
            f"Deterministic findings: {len(scan.findings)}; semantic findings: "
            f"{len(security_semantic.findings)}. {security_semantic.summary}"
        )[:1000],
        input_artifact_ids=tuple(
            dict.fromkeys((*security_semantic.input_artifact_ids, *security_input_ids))
        ),
        model_name=security_semantic.model_name,
        prompt_version=security_semantic.prompt_version,
        started_at=started_at,
        completed_at=completed_at,
        status=security_semantic.status,
    )
    quality = AgentArtifact.model_validate_json(
        quality.model_copy(update={"coverage": quality_coverage}).model_dump_json()
    )
    return security, quality


def schema_repair_exhausted(*runs: AgentRunResult) -> bool:
    return any(
        item.failure_code
        in {
            ProviderErrorCode.INVALID_JSON,
            ProviderErrorCode.SCHEMA_ERROR,
            ProviderErrorCode.OUTPUT_CONTRACT_ERROR,
            ProviderErrorCode.TRUNCATED_RESPONSE,
        }
        for item in runs
    )


def _agent_artifact_or_failure(
    run: AgentRunResult,
    *,
    review_id: str,
    agent_id: str,
    agent_role: str,
    schema_name: str,
    skill_name: str,
    prompt_version: str,
    input_ids: tuple[str, ...],
    files_checked: tuple[str, ...],
    timestamp: datetime,
) -> AgentArtifact:
    if run.status is SkillStatus.SUCCESS and isinstance(run.output, AgentArtifact):
        return run.output
    calls = run.calls
    started_at = calls[0].started_at if calls else timestamp
    completed_at = calls[-1].completed_at if calls else timestamp
    error_code = _policy_provider_error(run.failure_code)
    coverage = CoverageRecord(
        coverage_id=stable_id("coverage", review_id, skill_name, prompt_version),
        skill_name=skill_name,
        skill_version="1.0.0",
        status=CoverageStatus.FAILED,
        mandatory=True,
        route_ids=(),
        files_checked=files_checked,
        reason=run.failure_message or "Structured Agent review failed.",
        error_code=error_code,
        duration_ms=sum(item.latency_ms for item in calls),
    )
    model_name = calls[0].requested_model if calls else DEFAULT_MODEL
    return AgentArtifact(
        artifact_id=stable_id("artifact", review_id, agent_id, "failed", error_code),
        review_id=review_id,
        agent_id=agent_id,
        agent_role=agent_role,
        schema_name=schema_name,
        schema_version="1.0.0",
        findings=(),
        evidence=(),
        coverage=(coverage,),
        summary=f"Structured Agent failed: {error_code}.",
        input_artifact_ids=input_ids,
        model_name=model_name,
        prompt_version=prompt_version,
        started_at=started_at,
        completed_at=completed_at,
        status=SkillStatus.FAILED,
    )


def _policy_provider_error(code: ProviderErrorCode | None) -> str:
    return {
        ProviderErrorCode.AUTHENTICATION_ERROR: "MODEL_AUTH_ERROR",
        ProviderErrorCode.INSUFFICIENT_BALANCE: "MODEL_QUOTA_EXCEEDED",
        ProviderErrorCode.RATE_LIMIT: "RATE_LIMITED",
        ProviderErrorCode.TIMEOUT: "TIMEOUT",
    }.get(code, "MODEL_ERROR")


def _unique_by_id(values: tuple, attribute: str) -> tuple:
    result = {}
    for item in values:
        result.setdefault(getattr(item, attribute), item)
    return tuple(result[key] for key in sorted(result))


def _location(line) -> CodeLocation:
    return CodeLocation(
        file_path=line.file_path,
        start_line=line.line_number,
        end_line=line.line_number,
        side=line.side,
        hunk_id=line.hunk_id,
        snippet_hash=line.content_hash,
    )
