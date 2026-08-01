"""P9 single-process reference runner joining the validated P5-P8 components."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from codesentinel.agents import (
    AgentRunResult,
    ContextBuildError,
    DiffAnalyzerAgent,
    DiffAnalyzerContext,
    ModelCallBudget,
    ProviderErrorCode,
    QualityReviewerAgent,
    QualityReviewerContext,
    SecurityReviewerContext,
    SecuritySemanticAgent,
)
from codesentinel.assurance import (
    EvidenceAssurance,
    RecheckResult,
    RiskRouter,
    TargetedRecheckController,
)
from codesentinel.domain import (
    AgentArtifact,
    CoverageStatus,
    DiffAnalysis,
    ReviewRequest,
    SkillStatus,
)
from codesentinel.gitdiff import GitDiffError, GitDiffReader
from codesentinel.policy import PolicyEvaluationContext, load_policy, safe_evaluate_gate
from codesentinel.skills.security import SecuritySkillSuite
from codesentinel.skills.security.base import stable_id

from .artifacts import (
    PersistedReview,
    ReviewArtifactPayload,
    ReviewArtifactStore,
)
from .assembly import (
    assemble_review_artifacts,
    deterministic_security_plan,
    fallback_diff_analysis,
    fallback_routing,
    schema_repair_exhausted,
    semantic_hints_from_analysis,
)
from .models import (
    EXIT_CODE_BY_STATUS,
    ReviewReport,
    ReviewTraceEvent,
    RunError,
    RunMetrics,
    RunStage,
    TraceStatus,
)


class LocalReviewRunError(RuntimeError):
    def __init__(self, code: str, stage: RunStage, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.stage = stage
        self.safe_message = safe_message


@dataclass(frozen=True, slots=True)
class LocalReviewExecution:
    report: ReviewReport
    persisted: PersistedReview
    payload: ReviewArtifactPayload


class _TraceRecorder:
    def __init__(self, review_id: str, trace_id: str) -> None:
        self.review_id = review_id
        self.trace_id = trace_id
        self.events: list[ReviewTraceEvent] = []

    def add(
        self,
        *,
        stage: RunStage,
        actor: str,
        status: TraceStatus,
        started_at: datetime,
        completed_at: datetime,
        artifact_refs: tuple[str, ...] = (),
        error_code: str | None = None,
        details: dict[str, str | int | float | bool | None] | None = None,
    ) -> None:
        sequence = len(self.events) + 1
        duration_ms = max(0, int((completed_at - started_at).total_seconds() * 1000))
        self.events.append(
            ReviewTraceEvent(
                event_id=f"{self.review_id}-trace-{sequence:03d}",
                review_id=self.review_id,
                trace_id=self.trace_id,
                sequence=sequence,
                stage=stage,
                actor=actor,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                artifact_refs=artifact_refs,
                error_code=error_code,
                details=details or {},
            )
        )


class LocalReviewRunner:
    """A reference runner; it is deliberately not an AgentTeams runtime."""

    def __init__(
        self,
        *,
        workspace_root: str | Path,
        diff_agent: DiffAnalyzerAgent,
        security_agent: SecuritySemanticAgent,
        quality_agent: QualityReviewerAgent,
        git_reader: GitDiffReader | None = None,
        security_suite: SecuritySkillSuite | None = None,
        risk_router: RiskRouter | None = None,
        artifact_store: ReviewArtifactStore | None = None,
    ) -> None:
        self._git = git_reader or GitDiffReader()
        self._security_suite = security_suite or SecuritySkillSuite()
        self._router = risk_router or RiskRouter()
        self._diff_agent = diff_agent
        self._security_agent = security_agent
        self._quality_agent = quality_agent
        self._policy = load_policy()
        self._assurance = EvidenceAssurance()
        self._recheck = TargetedRecheckController(self._assurance)
        self._store = artifact_store or ReviewArtifactStore(workspace_root)

    def run(
        self,
        request: ReviewRequest,
        *,
        review_id: str | None = None,
        allow_recheck: bool = True,
        max_duration_seconds: float = 240.0,
    ) -> LocalReviewExecution:
        if not 0 < max_duration_seconds <= 600:
            raise ValueError("max_duration_seconds must be between 0 and 600")
        started_at = datetime.now(UTC)
        timer = time.perf_counter_ns()
        deadline = time.monotonic() + max_duration_seconds
        selected_id = review_id or _new_review_id(started_at)
        self._store.preflight(
            selected_id,
            target_repository=request.repository_path,
        )
        trace_id = f"trace-{_hash(selected_id)[:20]}"
        trace = _TraceRecorder(selected_id, trace_id)
        errors: list[RunError] = []
        budget = ModelCallBudget(max_calls=4)

        _ensure_before_deadline(deadline, RunStage.DIFF)
        stage_started = datetime.now(UTC)
        try:
            git_diff = self._git.read(request, review_id=selected_id)
        except GitDiffError as exc:
            raise LocalReviewRunError(
                "GIT_INPUT_ERROR",
                RunStage.DIFF,
                str(exc),
            ) from exc
        trace.add(
            stage=RunStage.DIFF,
            actor="Diff Intake",
            status=TraceStatus.SUCCESS,
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("input-summary.json",),
            details={
                "files": len(git_diff.files),
                "changed_lines": git_diff.changed_lines,
                "diff_hash": git_diff.diff_hash,
            },
        )

        _ensure_before_deadline(deadline, RunStage.SECRET_BOUNDARY)
        stage_started = datetime.now(UTC)
        secret_result, sanitized = self._security_suite.run_secret_boundary(git_diff)
        secret_failed = secret_result.status is SkillStatus.FAILED
        if secret_failed:
            errors.append(
                RunError(
                    error_code=secret_result.coverage.error_code or "TOOL_ERROR",
                    stage=RunStage.SECRET_BOUNDARY,
                    message=secret_result.coverage.reason,
                    retryable=True,
                )
            )
        trace.add(
            stage=RunStage.SECRET_BOUNDARY,
            actor="Security Scanner",
            status=TraceStatus.FAILED if secret_failed else TraceStatus.SUCCESS,
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("sanitized-diff.json",),
            error_code=secret_result.coverage.error_code if secret_failed else None,
            details={
                "cloud_safe": sanitized.cloud_safe,
                "redactions": len(secret_result.redactions),
            },
        )

        _ensure_before_deadline(deadline, RunStage.DIFF_ANALYSIS)
        diff_context = None
        stage_started = datetime.now(UTC)
        if sanitized.cloud_safe:
            try:
                diff_context = DiffAnalyzerContext.from_artifacts(git_diff, sanitized)
                diff_run = self._diff_agent.run(diff_context, budget=budget)
            except ContextBuildError as exc:
                diff_run = _failed_agent_run(
                    review_id=selected_id,
                    agent_id="diff-analyzer",
                    target_schema="DiffAnalysis@1.0.0",
                    code=exc.code,
                    message=exc.safe_message,
                )
        else:
            diff_run = _failed_agent_run(
                review_id=selected_id,
                agent_id="diff-analyzer",
                target_schema="DiffAnalysis@1.0.0",
                code=ProviderErrorCode.CONTEXT_UNSAFE,
                message="Secret or scope checks denied cloud source disclosure.",
            )
        if diff_run.status is SkillStatus.SUCCESS and isinstance(
            diff_run.output, DiffAnalysis
        ):
            diff_analysis = diff_run.output
            diff_status = TraceStatus.SUCCESS
            diff_error = None
        else:
            diff_error = _record_agent_error(errors, RunStage.DIFF_ANALYSIS, diff_run)
            diff_analysis = fallback_diff_analysis(
                git_diff,
                diff_run.failure_message or "semantic analysis was unavailable",
            )
            diff_status = TraceStatus.FAILED
        trace.add(
            stage=RunStage.DIFF_ANALYSIS,
            actor="Diff Analyzer",
            status=diff_status,
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("diff-analysis.json",),
            error_code=diff_error,
            details={"model_calls": len(diff_run.calls), "fallback": diff_error is not None},
        )

        _ensure_before_deadline(deadline, RunStage.RISK_ROUTING)
        stage_started = datetime.now(UTC)
        if sanitized.cloud_safe:
            try:
                hints = (
                    semantic_hints_from_analysis(diff_analysis, sanitized)
                    if diff_run.status is SkillStatus.SUCCESS
                    else ()
                )
                routing = self._router.build(
                    diff_analysis,
                    sanitized,
                    semantic_hints=hints,
                    semantic_failure_reason=(
                        diff_run.failure_message
                        if diff_run.status is SkillStatus.FAILED
                        else None
                    ),
                )
                routing_status = TraceStatus.SUCCESS
                routing_error = None
            except Exception:
                routing = fallback_routing(
                    diff_analysis,
                    "Risk routing contract failed; optional checks were denied.",
                )
                routing_status = TraceStatus.FAILED
                routing_error = "ROUTING_ERROR"
                errors.append(
                    RunError(
                        error_code=routing_error,
                        stage=RunStage.RISK_ROUTING,
                        message="Risk routing failed and was replaced by a fail-closed plan.",
                        retryable=False,
                    )
                )
        else:
            routing = fallback_routing(diff_analysis, sanitized.reason)
            routing_status = TraceStatus.FAILED
            routing_error = "CONTEXT_UNSAFE"
        trace.add(
            stage=RunStage.RISK_ROUTING,
            actor="Diff Analyzer",
            status=routing_status,
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("risk-routing.json",),
            error_code=routing_error,
            details={
                "routes": len(routing.risk_map.routes),
                "planned_skills": routing.risk_map.planned_skill_count,
            },
        )

        _ensure_before_deadline(deadline, RunStage.SECURITY_SKILLS)
        stage_started = datetime.now(UTC)
        scan = self._security_suite.run_routed(
            git_diff,
            secret_result=secret_result,
            sanitized_diff=sanitized,
            planned_route_ids=deterministic_security_plan(routing),
        )
        for item in scan.coverage:
            if item.status is CoverageStatus.FAILED and item.skill_name != "detect_secret":
                errors.append(
                    RunError(
                        error_code=item.error_code or "TOOL_ERROR",
                        stage=RunStage.SECURITY_SKILLS,
                        message=item.reason,
                        retryable=True,
                    )
                )
        trace.add(
            stage=RunStage.SECURITY_SKILLS,
            actor="Security Scanner",
            status=(
                TraceStatus.FAILED
                if any(item.status is CoverageStatus.FAILED for item in scan.coverage)
                else TraceStatus.SUCCESS
            ),
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("security-review.json",),
            error_code=(
                next(
                    (
                        item.error_code
                        for item in scan.coverage
                        if item.status is CoverageStatus.FAILED
                    ),
                    None,
                )
            ),
            details={
                "findings": len(scan.findings),
                "verified_e3": len(scan.verified_e3_evidence_ids),
            },
        )

        files_checked = tuple(
            dict.fromkeys(
                item.change.new_path or item.change.old_path for item in git_diff.files
            )
        )
        git_root_id = stable_id("git-diff", git_diff.review_id, git_diff.diff_hash)
        scan_root_id = stable_id(
            "security-scan",
            git_diff.diff_hash,
            scan.schema_version,
        )
        security_input_ids = (git_root_id, scan_root_id)
        quality_input_ids = (git_root_id,)

        _ensure_before_deadline(deadline, RunStage.SECURITY_REVIEW)
        stage_started = datetime.now(UTC)
        if sanitized.cloud_safe and sanitized.lines:
            try:
                security_context = SecurityReviewerContext.from_scan(git_diff, scan)
                security_run = self._security_agent.run(security_context, budget=budget)
                security_input_ids = security_context.input_artifact_ids
            except ContextBuildError as exc:
                security_run = _failed_agent_run(
                    review_id=selected_id,
                    agent_id="security-scanner",
                    target_schema="SecurityReview@1.0.0",
                    code=exc.code,
                    message=exc.safe_message,
                )
        else:
            security_run = _failed_agent_run(
                review_id=selected_id,
                agent_id="security-scanner",
                target_schema="SecurityReview@1.0.0",
                code=ProviderErrorCode.CONTEXT_UNSAFE,
                message="No cloud-safe Python lines were available for Security Review.",
            )
        security_error = (
            None
            if security_run.status is SkillStatus.SUCCESS
            else _record_agent_error(errors, RunStage.SECURITY_REVIEW, security_run)
        )
        trace.add(
            stage=RunStage.SECURITY_REVIEW,
            actor="Security Scanner",
            status=(
                TraceStatus.SUCCESS
                if security_error is None
                else TraceStatus.FAILED
            ),
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("security-review.json",),
            error_code=security_error,
            details={"model_calls": len(security_run.calls)},
        )

        _ensure_before_deadline(deadline, RunStage.QUALITY_REVIEW)
        stage_started = datetime.now(UTC)
        if sanitized.cloud_safe and sanitized.lines:
            try:
                quality_context = QualityReviewerContext.from_artifacts(
                    git_diff,
                    sanitized,
                    ruff_summary=(
                        "P9 uses diff-only semantic review; Ruff does not execute against "
                        "the target worktree."
                    ),
                )
                quality_run = self._quality_agent.run(quality_context, budget=budget)
                quality_input_ids = quality_context.input_artifact_ids
            except ContextBuildError as exc:
                quality_run = _failed_agent_run(
                    review_id=selected_id,
                    agent_id="quality-reviewer",
                    target_schema="QualityReview@1.0.0",
                    code=exc.code,
                    message=exc.safe_message,
                )
        else:
            quality_run = _failed_agent_run(
                review_id=selected_id,
                agent_id="quality-reviewer",
                target_schema="QualityReview@1.0.0",
                code=ProviderErrorCode.CONTEXT_UNSAFE,
                message="No cloud-safe Python lines were available for Quality Review.",
            )
        quality_error = (
            None
            if quality_run.status is SkillStatus.SUCCESS
            else _record_agent_error(errors, RunStage.QUALITY_REVIEW, quality_run)
        )
        trace.add(
            stage=RunStage.QUALITY_REVIEW,
            actor="Quality Reviewer",
            status=TraceStatus.SUCCESS if quality_error is None else TraceStatus.FAILED,
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("quality-review.json",),
            error_code=quality_error,
            details={"model_calls": len(quality_run.calls)},
        )

        _ensure_before_deadline(deadline, RunStage.EVIDENCE_ASSURANCE)
        try:
            security_review, quality_review = assemble_review_artifacts(
                scan=scan,
                routing=routing,
                security_run=security_run,
                quality_run=quality_run,
                security_input_ids=security_input_ids,
                quality_input_ids=quality_input_ids,
                files_checked=files_checked,
            )
        except Exception as exc:
            raise LocalReviewRunError(
                "ARTIFACT_ASSEMBLY_ERROR",
                RunStage.EVIDENCE_ASSURANCE,
                "Review Agent outputs could not be assembled safely.",
            ) from exc

        policy_context = PolicyEvaluationContext(
            review_id=selected_id,
            trace_id=trace_id,
            decided_at=datetime.now(UTC),
            diff_analysis=diff_analysis,
            risk_map=routing.risk_map,
            artifacts=(security_review, quality_review),
            verified_e3_evidence_ids=scan.verified_e3_evidence_ids,
            conflicts=(),
            root_artifact_ids=(git_root_id, scan_root_id),
            schema_repair_exhausted=schema_repair_exhausted(
                diff_run,
                security_run,
                quality_run,
            ),
            recheck_exhausted=False,
        )

        _ensure_before_deadline(deadline, RunStage.RECHECK)
        stage_started = datetime.now(UTC)
        if allow_recheck:
            recheck = self._recheck.run_once(
                policy_context,
                self._policy,
                lambda request_: self._targeted_recheck(
                    request_,
                    git_diff,
                    routing,
                ),
            )
            final_context = recheck.context
            initial_decision = recheck.outcome.initial_decision
            decision = recheck.outcome.final_decision
            recheck_attempts = recheck.outcome.attempts
            recheck_exhausted = recheck.outcome.exhausted
        else:
            assured = self._assurance.validate(policy_context, self._policy)
            final_context = assured.context
            initial_decision = safe_evaluate_gate(final_context, self._policy)
            decision = initial_decision
            recheck_attempts = 0
            recheck_exhausted = False
        trace.add(
            stage=RunStage.RECHECK,
            actor="Gate Arbiter",
            status=(
                TraceStatus.SKIPPED
                if recheck_attempts == 0
                else TraceStatus.FAILED
                if recheck_exhausted
                else TraceStatus.SUCCESS
            ),
            started_at=stage_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("evidence-validation.json",),
            error_code="RECHECK_EXHAUSTED" if recheck_exhausted else None,
            details={"attempts": recheck_attempts, "exhausted": recheck_exhausted},
        )
        if recheck_exhausted:
            errors.append(
                RunError(
                    error_code="RECHECK_EXHAUSTED",
                    stage=RunStage.RECHECK,
                    message="The single targeted recheck did not close all review gaps.",
                    retryable=False,
                )
            )

        _ensure_before_deadline(deadline, RunStage.POLICY)
        final_assurance = self._assurance.validate(final_context, self._policy)
        decision = safe_evaluate_gate(final_assurance.context, self._policy)
        security_review = _artifact_by_schema(
            final_assurance.context.artifacts,
            "SecurityReview",
        )
        quality_review = _artifact_by_schema(
            final_assurance.context.artifacts,
            "QualityReview",
        )
        trace.add(
            stage=RunStage.POLICY,
            actor="Gate Arbiter",
            status=TraceStatus.SUCCESS,
            started_at=decision.decided_at,
            completed_at=datetime.now(UTC),
            artifact_refs=("gate-decision.json",),
            details={
                "decision": decision.status.value,
                "rules": ",".join(decision.matched_rule_ids),
            },
        )

        model_calls = tuple(
            call
            for run in (diff_run, security_run, quality_run)
            for call in run.calls
        )
        coverage = tuple(
            item
            for artifact in final_assurance.context.artifacts
            for item in artifact.coverage
        )
        completed_at = datetime.now(UTC)
        metrics = RunMetrics(
            duration_ms=max(0, (time.perf_counter_ns() - timer) // 1_000_000),
            changed_files=len(git_diff.files),
            changed_lines=git_diff.changed_lines,
            planned_skills=routing.risk_map.planned_skill_count,
            completed_skills=sum(
                item.status is CoverageStatus.COMPLETED for item in coverage
            ),
            skipped_skills=sum(item.status is CoverageStatus.SKIPPED for item in coverage),
            failed_skills=sum(item.status is CoverageStatus.FAILED for item in coverage),
            model_calls=len(model_calls),
            prompt_tokens=sum(item.prompt_tokens or 0 for item in model_calls),
            completion_tokens=sum(item.completion_tokens or 0 for item in model_calls),
            total_tokens=sum(item.total_tokens or 0 for item in model_calls),
            estimated_cost_usd=round(
                sum(item.estimated_cost_usd or 0 for item in model_calls),
                12,
            ),
        )
        report = ReviewReport(
            review_id=selected_id,
            trace_id=trace_id,
            status=decision.status,
            exit_code=EXIT_CODE_BY_STATUS[decision.status],
            decision=decision,
            initial_gate_status=initial_decision.status,
            recheck_attempts=recheck_attempts,
            recheck_exhausted=recheck_exhausted,
            errors=tuple(errors),
            metrics=metrics,
            started_at=started_at,
            completed_at=completed_at,
        )
        _ensure_before_deadline(deadline, RunStage.PERSISTENCE)
        persistence_started = datetime.now(UTC)
        trace.add(
            stage=RunStage.PERSISTENCE,
            actor="Artifact Store",
            status=TraceStatus.SUCCESS,
            started_at=persistence_started,
            completed_at=datetime.now(UTC),
            artifact_refs=("review.json", "report.md", "trace.jsonl", "manifest.json"),
            details={"atomic": True, "target_repository_writes": 0},
        )
        payload = ReviewArtifactPayload(
            git_diff=git_diff,
            sanitized_diff=sanitized,
            diff_analysis=diff_analysis,
            routing=routing,
            security_review=security_review,
            quality_review=quality_review,
            evidence_validation=final_assurance.report,
            report=report,
            model_calls=model_calls,
            trace=tuple(trace.events),
        )
        persisted = self._store.persist(
            payload,
            target_repository=request.repository_path,
        )
        return LocalReviewExecution(report=report, persisted=persisted, payload=payload)

    def _targeted_recheck(self, request, git_diff, routing) -> RecheckResult:
        targeted = {
            skill for target in request.targets for skill in target.skill_names
        } & {"detect_secret", "detect_injection", "detect_dangerous_call"}
        if not targeted:
            return RecheckResult(
                request_id=request.request_id,
                review_id=request.review_id,
                status="success",
            )
        secret, sanitized = self._security_suite.run_secret_boundary(git_diff)
        plan = {"detect_secret": ()}
        original_plan = deterministic_security_plan(routing)
        for skill in targeted:
            plan[skill] = original_plan.get(skill, ())
        scan = self._security_suite.run_routed(
            git_diff,
            secret_result=secret,
            sanitized_diff=sanitized,
            planned_route_ids=plan,
        )
        selected = tuple(
            item
            for item in scan.skill_results
            if item.manifest.name in targeted
        )
        if any(item.status is SkillStatus.FAILED for item in selected):
            return RecheckResult(
                request_id=request.request_id,
                review_id=request.review_id,
                status="failed",
                failure_reason="A targeted deterministic Skill failed again.",
            )
        if any(item.findings for item in selected):
            return RecheckResult(
                request_id=request.request_id,
                review_id=request.review_id,
                status="failed",
                failure_reason=(
                    "The targeted rerun discovered a new risk and requires manual review."
                ),
            )
        return RecheckResult(
            request_id=request.request_id,
            review_id=request.review_id,
            status="success",
            coverage_updates=tuple(item.coverage for item in selected),
        )


def _record_agent_error(
    errors: list[RunError],
    stage: RunStage,
    run: AgentRunResult,
) -> str:
    code = run.failure_code.value if run.failure_code is not None else "MODEL_ERROR"
    errors.append(
        RunError(
            error_code=code,
            stage=stage,
            message=run.failure_message or "Structured Agent review failed.",
            retryable=code
            in {
                "RATE_LIMIT",
                "TIMEOUT",
                "TRANSPORT_ERROR",
                "PROVIDER_ERROR",
            },
        )
    )
    return code


def _ensure_before_deadline(deadline: float, stage: RunStage) -> None:
    if time.monotonic() > deadline:
        raise LocalReviewRunError(
            "RUN_TIMEOUT",
            stage,
            "The configured whole-run deadline was exceeded; no PASS was emitted.",
        )


def _failed_agent_run(
    *,
    review_id: str,
    agent_id: str,
    target_schema: str,
    code: ProviderErrorCode,
    message: str,
) -> AgentRunResult:
    return AgentRunResult(
        review_id=review_id,
        agent_id=agent_id,
        status=SkillStatus.FAILED,
        target_schema=target_schema,
        output=None,
        calls=(),
        context_hash=_hash(review_id, agent_id, code.value),
        failure_code=code,
        failure_message=message,
    )


def _artifact_by_schema(
    artifacts: tuple[AgentArtifact, ...],
    schema_name: str,
) -> AgentArtifact:
    matches = [item for item in artifacts if item.schema_name == schema_name]
    if len(matches) != 1:
        raise LocalReviewRunError(
            "ARTIFACT_INTEGRITY_ERROR",
            RunStage.EVIDENCE_ASSURANCE,
            f"Expected exactly one {schema_name} artifact.",
        )
    return matches[0]


def _new_review_id(now: datetime) -> str:
    return f"cs-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def _hash(*parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
