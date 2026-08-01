"""P7 structured Agent runners over isolated, sanitized contexts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from codesentinel.domain import (
    AgentArtifact,
    CodeLocation,
    CoverageRecord,
    CoverageStatus,
    DiffAnalysis,
    Evidence,
    EvidenceLevel,
    EvidenceSource,
    Finding,
    FindingStatus,
    RiskCategory,
    Severity,
    SkillStatus,
)

from .contexts import DiffAnalyzerContext, QualityReviewerContext, SecurityReviewerContext
from .models import (
    AgentContextLine,
    AgentRunResult,
    DiffSemanticPayload,
    ProviderErrorCode,
    QualityReviewPayload,
    SecurityReviewPayload,
)
from .prompts import (
    DIFF_ANALYZER_PROMPT,
    QUALITY_REVIEWER_PROMPT,
    SECURITY_REVIEWER_PROMPT,
    PromptDefinition,
)
from .provider import DeepSeekProvider, ModelCallBudget, ProviderExecution


def _hash(*parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_hash(*parts)[:20]}"


def _context_hash(context: Any) -> str:
    return _hash(context.model_dump_json())


def _failed_result(
    *,
    review_id: str,
    agent_id: str,
    target_schema: str,
    context_hash: str,
    execution: ProviderExecution[Any],
) -> AgentRunResult:
    return AgentRunResult(
        review_id=review_id,
        agent_id=agent_id,
        status=SkillStatus.FAILED,
        target_schema=target_schema,
        output=None,
        calls=execution.calls,
        context_hash=context_hash,
        failure_code=execution.failure_code or ProviderErrorCode.PROVIDER_ERROR,
        failure_message=execution.failure_message or "Structured model execution failed.",
    )


def _contract_failure(
    *,
    review_id: str,
    agent_id: str,
    target_schema: str,
    context_hash: str,
    calls: tuple,
) -> AgentRunResult:
    return AgentRunResult(
        review_id=review_id,
        agent_id=agent_id,
        status=SkillStatus.FAILED,
        target_schema=target_schema,
        output=None,
        calls=calls,
        context_hash=context_hash,
        failure_code=ProviderErrorCode.OUTPUT_CONTRACT_ERROR,
        failure_message="Validated model output could not satisfy the domain contract.",
    )


class DiffAnalyzerAgent:
    agent_id = "diff-analyzer"
    prompt = DIFF_ANALYZER_PROMPT

    def __init__(self, provider: DeepSeekProvider) -> None:
        self._provider = provider

    def run(
        self,
        context: DiffAnalyzerContext,
        *,
        budget: ModelCallBudget,
    ) -> AgentRunResult:
        context_hash = _context_hash(context)
        execution = self._provider.generate(
            review_id=context.review_id,
            prompt=self.prompt,
            context=context,
            output_model=DiffSemanticPayload,
            budget=budget,
        )
        if not execution.succeeded or execution.output is None:
            return _failed_result(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema="DiffAnalysis@1.0.0",
                context_hash=context_hash,
                execution=execution,
            )
        try:
            output = DiffAnalysis(
                review_id=context.review_id,
                diff_hash=context.diff_hash,
                files=context.files,
                total_additions=context.total_additions,
                total_deletions=context.total_deletions,
                changed_lines=context.changed_lines,
                summary=execution.output.summary,
                change_intents=execution.output.change_intents,
                affected_symbols=execution.output.affected_symbols,
                truncated=False,
                unsupported_files=context.unsupported_files,
                parser_version=context.parser_version,
            )
        except Exception:
            return _contract_failure(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema="DiffAnalysis@1.0.0",
                context_hash=context_hash,
                calls=execution.calls,
            )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id=self.agent_id,
            status=SkillStatus.SUCCESS,
            target_schema="DiffAnalysis@1.0.0",
            output=output,
            calls=execution.calls,
            context_hash=context_hash,
            failure_code=None,
            failure_message=None,
        )


class SecuritySemanticAgent:
    agent_id = "security-scanner"
    agent_role = "Security Scanner"
    prompt = SECURITY_REVIEWER_PROMPT
    skill_name = "security_semantic_review"

    def __init__(self, provider: DeepSeekProvider) -> None:
        self._provider = provider

    def run(
        self,
        context: SecurityReviewerContext,
        *,
        budget: ModelCallBudget,
    ) -> AgentRunResult:
        return self._run_review(
            context=context,
            budget=budget,
            output_model=SecurityReviewPayload,
            schema_name="SecurityReview",
        )

    def _run_review(
        self,
        *,
        context: SecurityReviewerContext,
        budget: ModelCallBudget,
        output_model: type[SecurityReviewPayload],
        schema_name: str,
    ) -> AgentRunResult:
        context_hash = _context_hash(context)
        execution = self._provider.generate(
            review_id=context.review_id,
            prompt=self.prompt,
            context=context,
            output_model=output_model,
            budget=budget,
        )
        if not execution.succeeded or execution.output is None:
            return _failed_result(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema=f"{schema_name}@1.0.0",
                context_hash=context_hash,
                execution=execution,
            )
        try:
            artifact = _build_review_artifact(
                review_id=context.review_id,
                agent_id=self.agent_id,
                agent_role=self.agent_role,
                schema_name=schema_name,
                skill_name=self.skill_name,
                prompt=self.prompt,
                model_name=self._provider.settings.model,
                input_artifact_ids=context.input_artifact_ids,
                lines=context.lines,
                payload=execution.output,
                calls=execution.calls,
            )
        except Exception:
            return _contract_failure(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema=f"{schema_name}@1.0.0",
                context_hash=context_hash,
                calls=execution.calls,
            )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id=self.agent_id,
            status=SkillStatus.SUCCESS,
            target_schema=f"{schema_name}@1.0.0",
            output=artifact,
            calls=execution.calls,
            context_hash=context_hash,
            failure_code=None,
            failure_message=None,
        )


class QualityReviewerAgent:
    agent_id = "quality-reviewer"
    agent_role = "Quality Reviewer"
    prompt = QUALITY_REVIEWER_PROMPT
    skill_name = "review_code_quality"

    def __init__(self, provider: DeepSeekProvider) -> None:
        self._provider = provider

    def run(
        self,
        context: QualityReviewerContext,
        *,
        budget: ModelCallBudget,
    ) -> AgentRunResult:
        context_hash = _context_hash(context)
        execution = self._provider.generate(
            review_id=context.review_id,
            prompt=self.prompt,
            context=context,
            output_model=QualityReviewPayload,
            budget=budget,
        )
        if not execution.succeeded or execution.output is None:
            return _failed_result(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema="QualityReview@1.0.0",
                context_hash=context_hash,
                execution=execution,
            )
        try:
            artifact = _build_review_artifact(
                review_id=context.review_id,
                agent_id=self.agent_id,
                agent_role=self.agent_role,
                schema_name="QualityReview",
                skill_name=self.skill_name,
                prompt=self.prompt,
                model_name=self._provider.settings.model,
                input_artifact_ids=context.input_artifact_ids,
                lines=context.lines,
                payload=execution.output,
                calls=execution.calls,
            )
        except Exception:
            return _contract_failure(
                review_id=context.review_id,
                agent_id=self.agent_id,
                target_schema="QualityReview@1.0.0",
                context_hash=context_hash,
                calls=execution.calls,
            )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id=self.agent_id,
            status=SkillStatus.SUCCESS,
            target_schema="QualityReview@1.0.0",
            output=artifact,
            calls=execution.calls,
            context_hash=context_hash,
            failure_code=None,
            failure_message=None,
        )


def _build_review_artifact(
    *,
    review_id: str,
    agent_id: str,
    agent_role: str,
    schema_name: str,
    skill_name: str,
    prompt: PromptDefinition,
    model_name: str,
    input_artifact_ids: tuple[str, ...],
    lines: tuple[AgentContextLine, ...],
    payload: SecurityReviewPayload | QualityReviewPayload,
    calls: tuple,
) -> AgentArtifact:
    lines_by_ref = {line.line_ref: line for line in lines}
    started_at = calls[0].started_at if calls else datetime.now(UTC)
    completed_at = calls[-1].completed_at if calls else started_at
    findings = []
    evidence = []
    for draft in payload.findings:
        if any(line_ref not in lines_by_ref for line_ref in draft.line_refs):
            raise ValueError("model output referenced a line outside its isolated context")
        locations = tuple(_location(lines_by_ref[line_ref]) for line_ref in draft.line_refs)
        fingerprint = _hash(
            agent_id,
            prompt.version,
            draft.category,
            draft.claim,
            *(location.snippet_hash for location in locations),
        )
        evidence_ids = []
        for index, location in enumerate(locations, start=1):
            evidence_id = _stable_id(
                "evidence",
                review_id,
                fingerprint,
                index,
                location.snippet_hash,
            )
            evidence_ids.append(evidence_id)
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    level=EvidenceLevel.E1,
                    source=EvidenceSource.LLM,
                    detector_name=agent_id,
                    detector_version=prompt.version,
                    summary=draft.claim,
                    location=location,
                    reproducible=False,
                    confidence=draft.confidence,
                    artifact_ref=None,
                    content_hash=_hash(fingerprint, location.snippet_hash, draft.claim),
                    created_at=started_at,
                )
            )
        findings.append(
            Finding(
                finding_id=_stable_id("finding", review_id, fingerprint),
                category=RiskCategory(draft.category),
                title=draft.title,
                claim=draft.claim,
                severity=Severity(draft.severity),
                status=FindingStatus.SUSPECTED,
                locations=locations,
                evidence_ids=tuple(evidence_ids),
                confidence=draft.confidence,
                recommendation=draft.recommendation,
                agent_id=agent_id,
                fingerprint=fingerprint,
            )
        )
    files_checked = tuple(dict.fromkeys(line.file_path for line in lines))
    duration_ms = sum(call.latency_ms for call in calls)
    coverage = CoverageRecord(
        coverage_id=_stable_id("coverage", review_id, skill_name, prompt.version),
        skill_name=skill_name,
        skill_version="1.0.0",
        status=CoverageStatus.COMPLETED,
        mandatory=True,
        route_ids=(),
        files_checked=files_checked,
        reason="Structured semantic review completed over isolated sanitized context.",
        error_code=None,
        duration_ms=duration_ms,
    )
    return AgentArtifact(
        artifact_id=_stable_id(
            "artifact",
            review_id,
            agent_id,
            prompt.version,
            _hash(payload.model_dump_json()),
        ),
        review_id=review_id,
        agent_id=agent_id,
        agent_role=agent_role,
        schema_name=schema_name,
        schema_version="1.0.0",
        findings=tuple(findings),
        evidence=tuple(evidence),
        coverage=(coverage,),
        summary=payload.summary,
        input_artifact_ids=input_artifact_ids,
        model_name=model_name,
        prompt_version=prompt.version,
        started_at=started_at,
        completed_at=completed_at,
        status=SkillStatus.SUCCESS,
    )


def _location(line: AgentContextLine) -> CodeLocation:
    return CodeLocation(
        file_path=line.file_path,
        start_line=line.line_number,
        end_line=line.line_number,
        side=line.side,
        hunk_id=line.hunk_id,
        snippet_hash=line.content_hash,
    )
