"""Small, synthetic, secret-free live P7 structured Agent verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from codesentinel.agents import (
    AgentContextLine,
    CoverageSummary,
    DeepSeekProvider,
    DeepSeekProviderSettings,
    DiffAnalyzerAgent,
    DiffAnalyzerContext,
    ModelCallBudget,
    QualityReviewerAgent,
    QualityReviewerContext,
    SecurityReviewerContext,
    SecuritySemanticAgent,
    load_deepseek_provider_settings,
)
from codesentinel.domain import ChangeType, CoverageStatus, FileChange, SkillStatus
from codesentinel.gitdiff import DiffLineKind
from codesentinel.preflight.deepseek import MissingApiKeyError, public_base_url

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class LiveAgentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: Literal["diff-analyzer", "security-scanner", "quality-reviewer"]
    status: SkillStatus
    target_schema: NonEmptyStr
    call_count: int = Field(ge=0, le=4)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    finding_count: int = Field(ge=0)
    failure_code: str | None


class P7LiveReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["P7LiveReport"] = "P7LiveReport"
    schema_version: Literal["1.0.0"] = "1.0.0"
    status: Literal["passed", "failed"]
    provider_origin: NonEmptyStr
    requested_model: NonEmptyStr
    pricing_version: NonEmptyStr
    call_budget_limit: Literal[4] = 4
    calls_used: int = Field(ge=0, le=4)
    started_at: datetime
    completed_at: datetime
    agents: tuple[LiveAgentSummary, ...] = Field(min_length=3, max_length=3)


def _hash(*parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _synthetic_contexts() -> tuple[
    DiffAnalyzerContext,
    SecurityReviewerContext,
    QualityReviewerContext,
]:
    review_id = "p7-live-synthetic"
    diff_hash = _hash("p7-live", "synthetic-safe-diff-v1")
    hunk_id = f"hunk-{_hash(diff_hash, 'app.py')[:20]}"
    raw_lines = (
        (DiffLineKind.DELETION, "old", 2, "    return value"),
        (DiffLineKind.ADDITION, "new", 2, "    result = value + 1"),
        (DiffLineKind.ADDITION, "new", 3, "    return result"),
    )
    lines = tuple(
        AgentContextLine(
            line_ref=f"line-{_hash(diff_hash, side, number, content)[:20]}",
            file_path="app.py",
            hunk_id=hunk_id,
            kind=kind,
            side=side,
            line_number=number,
            content=content,
            content_hash=_hash(content),
        )
        for kind, side, number, content in raw_lines
    )
    file_change = FileChange(
        file_id=f"file-{_hash(diff_hash, 'app.py')[:20]}",
        old_path="app.py",
        new_path="app.py",
        change_type=ChangeType.MODIFIED,
        language="python",
        additions=2,
        deletions=1,
        is_binary=False,
        content_hash=_hash(*(line.content_hash for line in lines)),
        hunk_ids=(hunk_id,),
    )
    input_id = f"git-diff-{diff_hash[:20]}"
    diff = DiffAnalyzerContext(
        review_id=review_id,
        input_artifact_ids=(input_id,),
        diff_hash=diff_hash,
        files=(file_change,),
        lines=lines,
        total_additions=2,
        total_deletions=1,
        changed_lines=3,
        unsupported_files=(),
        parser_version="p5-1.0.0",
    )
    coverage = tuple(
        CoverageSummary(
            skill_name=name,
            skill_version="1.0.0",
            status=CoverageStatus.COMPLETED,
            error_code=None,
        )
        for name in ("detect_secret", "detect_injection", "detect_dangerous_call")
    )
    security = SecurityReviewerContext(
        review_id=review_id,
        input_artifact_ids=(input_id, f"security-scan-{diff_hash[:20]}"),
        diff_hash=diff_hash,
        lines=lines,
        deterministic_findings=(),
        deterministic_coverage=coverage,
    )
    quality = QualityReviewerContext(
        review_id=review_id,
        input_artifact_ids=(input_id,),
        diff_hash=diff_hash,
        lines=lines,
        ruff_summary="Ruff completed with no findings for the synthetic change.",
    )
    return diff, security, quality


def run_live_probe(
    settings: DeepSeekProviderSettings,
    *,
    provider_factory: Callable[[DeepSeekProviderSettings], DeepSeekProvider] = (
        DeepSeekProvider
    ),
) -> P7LiveReport:
    """Run exactly three normal-path Agent calls under one four-call budget."""

    started_at = datetime.now(UTC)
    provider = provider_factory(settings)
    budget = ModelCallBudget(max_calls=4)
    diff_context, security_context, quality_context = _synthetic_contexts()
    results = (
        DiffAnalyzerAgent(provider).run(diff_context, budget=budget),
        SecuritySemanticAgent(provider).run(security_context, budget=budget),
        QualityReviewerAgent(provider).run(quality_context, budget=budget),
    )
    summaries = []
    for result in results:
        calls = result.calls
        output = result.output
        findings = getattr(output, "findings", ()) if output is not None else ()
        summaries.append(
            LiveAgentSummary(
                agent_id=result.agent_id,
                status=result.status,
                target_schema=result.target_schema,
                call_count=len(calls),
                prompt_tokens=sum(call.prompt_tokens or 0 for call in calls),
                completion_tokens=sum(call.completion_tokens or 0 for call in calls),
                total_tokens=sum(call.total_tokens or 0 for call in calls),
                estimated_cost_usd=round(
                    sum(call.estimated_cost_usd or 0 for call in calls),
                    12,
                ),
                finding_count=len(findings),
                failure_code=(
                    result.failure_code.value if result.failure_code is not None else None
                ),
            )
        )
    return P7LiveReport(
        status=(
            "passed"
            if all(result.status is SkillStatus.SUCCESS for result in results)
            else "failed"
        ),
        provider_origin=public_base_url(settings.base_url),
        requested_model=settings.model,
        pricing_version=settings.pricing_version,
        calls_used=budget.used,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        agents=tuple(summaries),
    )


def write_live_report(report: P7LiveReport, report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / (
        f"p7-agent-live-{report.completed_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    target.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the synthetic CodeSentinel P7 structured Agent live probe."
    )
    parser.add_argument("--env-file", type=Path, default=Path.cwd() / ".env")
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path.cwd() / "artifacts" / "preflight",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        settings = load_deepseek_provider_settings(args.env_file)
    except (MissingApiKeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = run_live_probe(settings)
    report_path = write_live_report(report, args.report_dir)
    print(f"P7 structured Agent probe: {report.status.upper()}")
    for agent in report.agents:
        print(
            f"- {agent.agent_id}: {agent.status.value}; calls={agent.call_count}; "
            f"tokens={agent.total_tokens}; cost_usd={agent.estimated_cost_usd:.8f}"
        )
        if agent.failure_code:
            print(f"  failure={agent.failure_code}")
    print(f"Calls used: {report.calls_used}/{report.call_budget_limit}")
    print(f"Redacted metadata report: {report_path}")
    return 0 if report.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
