"""Command-line entry point for the P9 local reference runner."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from codesentinel.agents import (
    DeepSeekProvider,
    DeepSeekProviderSettings,
    DiffAnalyzerAgent,
    QualityReviewerAgent,
    SecuritySemanticAgent,
    load_deepseek_provider_settings,
)
from codesentinel.domain import ReviewRequest
from codesentinel.preflight.deepseek import MissingApiKeyError

from .artifacts import ReviewArtifactError
from .runner import LocalReviewExecution, LocalReviewRunError, LocalReviewRunner

SettingsLoader = Callable[[Path | None], DeepSeekProviderSettings]
RunnerFactory = Callable[[DeepSeekProviderSettings, Path], LocalReviewRunner]


def _changed_line_limit(value: str) -> int:
    try:
        selected = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= selected <= 5000:
        raise argparse.ArgumentTypeError("must be between 1 and 5000")
    return selected


def _run_timeout(value: str) -> int:
    try:
        selected = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 30 <= selected <= 600:
        raise argparse.ArgumentTypeError("must be between 30 and 600 seconds")
    return selected


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description=(
            "Review a local Git diff with the P9 single-process reference runner. "
            "The reviewed repository remains read-only."
        ),
    )
    parser.add_argument("repository", type=Path, help="Local Git worktree to review")
    parser.add_argument("--base", default="HEAD", help="Base revision (default: HEAD)")
    parser.add_argument("--target", help="Committed target revision")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--staged-only",
        action="store_true",
        help="Review only changes staged in the index",
    )
    mode.add_argument(
        "--unstaged-only",
        action="store_true",
        help="Review only unstaged worktree changes",
    )
    parser.add_argument(
        "--max-changed-lines",
        type=_changed_line_limit,
        default=1000,
        metavar="1..5000",
        help="Fail-closed cloud disclosure limit (default: 1000)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Existing CodeSentinel workspace for artifacts (default: current directory)",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path.cwd() / ".env",
        help="Ignored local DeepSeek environment file (default: ./.env)",
    )
    parser.add_argument("--review-id", help="Optional safe, unique artifact run ID")
    parser.add_argument(
        "--run-timeout-seconds",
        type=_run_timeout,
        default=240,
        metavar="30..600",
        help="Fail-closed whole-run soft deadline (default: 240)",
    )
    parser.add_argument(
        "--no-recheck",
        action="store_true",
        help="Disable the single deterministic targeted recheck",
    )
    return parser


def _default_runner_factory(
    settings: DeepSeekProviderSettings,
    workspace: Path,
) -> LocalReviewRunner:
    provider = DeepSeekProvider(settings)
    return LocalReviewRunner(
        workspace_root=workspace,
        diff_agent=DiffAnalyzerAgent(provider),
        security_agent=SecuritySemanticAgent(provider),
        quality_agent=QualityReviewerAgent(provider),
    )


def _request_from_args(args: argparse.Namespace) -> ReviewRequest:
    include_staged = not args.unstaged_only
    include_unstaged = not args.staged_only
    return ReviewRequest(
        repository_path=str(args.repository.resolve(strict=False)),
        base_revision=args.base,
        target_revision=args.target,
        include_staged=include_staged,
        include_unstaged=include_unstaged,
        include_untracked=False,
        max_changed_lines=args.max_changed_lines,
    )


def _print_execution(execution: LocalReviewExecution) -> None:
    report = execution.report
    print(f"CodeSentinel decision: {report.status.value}")
    print(f"Review ID: {report.review_id}")
    print(f"Exit code: {report.exit_code}")
    print(f"Policy rules: {', '.join(report.decision.matched_rule_ids) or 'none'}")
    print(
        "Coverage: "
        f"completed={report.metrics.completed_skills}, "
        f"skipped={report.metrics.skipped_skills}, "
        f"failed={report.metrics.failed_skills}"
    )
    print(
        "Model usage: "
        f"calls={report.metrics.model_calls}/4, "
        f"tokens={report.metrics.total_tokens}, "
        f"estimated_cost_usd={report.metrics.estimated_cost_usd:.8f}"
    )
    if report.errors:
        print("Errors: " + ", ".join(item.error_code for item in report.errors))
    print(f"Report: {execution.persisted.report_path}")
    print(f"Decision JSON: {execution.persisted.decision_path}")
    print(f"Trace: {execution.persisted.trace_path}")
    print(f"Manifest: {execution.persisted.manifest_path}")


def _safe_failure(exc: Exception) -> str:
    if isinstance(exc, LocalReviewRunError):
        return f"{exc.code} at {exc.stage.value}: {exc.safe_message}"
    if isinstance(exc, ReviewArtifactError):
        return f"ARTIFACT_ERROR: {exc}"
    if isinstance(exc, MissingApiKeyError):
        return f"CONFIG_ERROR: {exc}"
    if isinstance(exc, ValueError):
        return f"INPUT_ERROR: {exc}"
    return "UNEXPECTED_ERROR: review failed safely; no PASS was emitted."


def main(
    argv: Sequence[str] | None = None,
    *,
    settings_loader: SettingsLoader = load_deepseek_provider_settings,
    runner_factory: RunnerFactory = _default_runner_factory,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.target is not None and (args.staged_only or args.unstaged_only):
        parser.error("--target cannot be combined with staged/unstaged-only modes")
    try:
        settings = settings_loader(args.env_file)
        runner = runner_factory(settings, args.workspace.resolve(strict=False))
        execution = runner.run(
            _request_from_args(args),
            review_id=args.review_id,
            allow_recheck=not args.no_recheck,
            max_duration_seconds=args.run_timeout_seconds,
        )
    except Exception as exc:  # CLI must never turn an execution failure into PASS.
        print(f"CodeSentinel execution failed: {_safe_failure(exc)}", file=sys.stderr)
        return 3
    _print_execution(execution)
    return execution.report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
