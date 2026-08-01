from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codesentinel.agents import AgentRunResult, ProviderErrorCode
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
    GateStatus,
    ReviewRequest,
    RiskCategory,
    Severity,
    SkillStatus,
)
from codesentinel.runtime import (
    LocalReviewRunError,
    LocalReviewRunner,
    ReviewArtifactError,
    RunStage,
)
from codesentinel.skills.security import SecuritySkillSuite

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def run_git(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    return completed.stdout.strip()


def make_repository(tmp_path: Path, after: str) -> tuple[Path, Path]:
    repository = tmp_path / "target"
    workspace = tmp_path / "workspace"
    repository.mkdir()
    workspace.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main", str(repository)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    run_git(repository, "config", "user.name", "CodeSentinel Fixture")
    run_git(repository, "config", "user.email", "fixture@users.noreply.github.com")
    target = repository / "app.py"
    target.write_text(
        "def calculate(value):\n    return value\n",
        encoding="utf-8",
        newline="\n",
    )
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "base")
    target.write_text(after, encoding="utf-8", newline="\n")
    return repository, workspace


def make_coverage(context, skill_name: str) -> CoverageRecord:
    files = tuple(dict.fromkeys(item.file_path for item in context.lines))
    return CoverageRecord(
        coverage_id=f"coverage-{skill_name}-{context.review_id}",
        skill_name=skill_name,
        skill_version="1.0.0",
        status=CoverageStatus.COMPLETED,
        mandatory=True,
        route_ids=(),
        files_checked=files,
        reason="The isolated sanitized context was reviewed.",
        error_code=None,
        duration_ms=1,
    )


class FakeDiffAgent:
    def run(self, context, *, budget) -> AgentRunResult:
        analysis = DiffAnalysis(
            review_id=context.review_id,
            diff_hash=context.diff_hash,
            files=context.files,
            total_additions=context.total_additions,
            total_deletions=context.total_deletions,
            changed_lines=context.changed_lines,
            summary="A bounded application value changed.",
            change_intents=("update application behavior",),
            affected_symbols=("calculate",),
            truncated=False,
            unsupported_files=context.unsupported_files,
            parser_version=context.parser_version,
        )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id="diff-analyzer",
            status=SkillStatus.SUCCESS,
            target_schema="DiffAnalysis@1.0.0",
            output=analysis,
            calls=(),
            context_hash="fake-diff-context",
            failure_code=None,
            failure_message=None,
        )


class FakeSecurityAgent:
    def __init__(self, *, failure: ProviderErrorCode | None = None) -> None:
        self._failure = failure

    def run(self, context, *, budget) -> AgentRunResult:
        if self._failure is not None:
            return AgentRunResult(
                review_id=context.review_id,
                agent_id="security-scanner",
                status=SkillStatus.FAILED,
                target_schema="SecurityReview@1.0.0",
                output=None,
                calls=(),
                context_hash="fake-security-context",
                failure_code=self._failure,
                failure_message="Synthetic provider failure.",
            )
        artifact = AgentArtifact(
            artifact_id=f"artifact-security-{context.review_id}",
            review_id=context.review_id,
            agent_id="security-scanner",
            agent_role="Security Scanner",
            schema_name="SecurityReview",
            findings=(),
            evidence=(),
            coverage=(make_coverage(context, "security_semantic_review"),),
            summary="No semantic security concern was emitted.",
            input_artifact_ids=context.input_artifact_ids,
            model_name="deepseek-v4-pro",
            prompt_version="security-semantic-1.0.0",
            started_at=NOW,
            completed_at=NOW + timedelta(milliseconds=1),
            status=SkillStatus.SUCCESS,
        )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id="security-scanner",
            status=SkillStatus.SUCCESS,
            target_schema="SecurityReview@1.0.0",
            output=artifact,
            calls=(),
            context_hash="fake-security-context",
            failure_code=None,
            failure_message=None,
        )


class FakeQualityAgent:
    def __init__(self, *, medium_finding: bool = False) -> None:
        self._medium_finding = medium_finding

    def run(self, context, *, budget) -> AgentRunResult:
        findings = ()
        evidence = ()
        if self._medium_finding:
            line = next(item for item in context.lines if item.side == "new")
            location = CodeLocation(
                file_path=line.file_path,
                start_line=line.line_number,
                end_line=line.line_number,
                side=line.side,
                hunk_id=line.hunk_id,
                snippet_hash=line.content_hash,
            )
            proof = Evidence(
                evidence_id=f"evidence-quality-{context.review_id}",
                level=EvidenceLevel.E1,
                source=EvidenceSource.LLM,
                detector_name="quality-reviewer",
                detector_version="quality-review-1.0.0",
                summary="The behavioral change may need a focused regression test.",
                location=location,
                reproducible=False,
                confidence=0.8,
                artifact_ref=None,
                content_hash=f"quality-hash-{context.review_id}",
                created_at=NOW,
            )
            finding = Finding(
                finding_id=f"finding-quality-{context.review_id}",
                category=RiskCategory.TEST_GAP,
                title="Focused regression test may be missing",
                claim="The changed behavior has no matching test in this diff.",
                severity=Severity.MEDIUM,
                status=FindingStatus.SUSPECTED,
                locations=(location,),
                evidence_ids=(proof.evidence_id,),
                confidence=0.8,
                recommendation="Add a focused regression test.",
                agent_id="quality-reviewer",
                fingerprint=f"quality-fingerprint-{context.review_id}",
            )
            findings = (finding,)
            evidence = (proof,)
        artifact = AgentArtifact(
            artifact_id=f"artifact-quality-{context.review_id}",
            review_id=context.review_id,
            agent_id="quality-reviewer",
            agent_role="Quality Reviewer",
            schema_name="QualityReview",
            findings=findings,
            evidence=evidence,
            coverage=(make_coverage(context, "review_code_quality"),),
            summary="Quality semantic review completed.",
            input_artifact_ids=context.input_artifact_ids,
            model_name="deepseek-v4-pro",
            prompt_version="quality-review-1.0.0",
            started_at=NOW,
            completed_at=NOW + timedelta(milliseconds=1),
            status=SkillStatus.SUCCESS,
        )
        return AgentRunResult(
            review_id=context.review_id,
            agent_id="quality-reviewer",
            status=SkillStatus.SUCCESS,
            target_schema="QualityReview@1.0.0",
            output=artifact,
            calls=(),
            context_hash="fake-quality-context",
            failure_code=None,
            failure_message=None,
        )


def make_runner(
    workspace: Path,
    *,
    medium_finding: bool = False,
    security_failure: ProviderErrorCode | None = None,
) -> LocalReviewRunner:
    return LocalReviewRunner(
        workspace_root=workspace,
        diff_agent=FakeDiffAgent(),
        security_agent=FakeSecurityAgent(failure=security_failure),
        quality_agent=FakeQualityAgent(medium_finding=medium_finding),
    )


def make_request(repository: Path) -> ReviewRequest:
    return ReviewRequest(repository_path=str(repository.resolve()))


def test_routed_suite_skips_unplanned_security_skills(tmp_path: Path) -> None:
    repository, _ = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    from codesentinel.gitdiff import GitDiffReader

    artifact = GitDiffReader().read(make_request(repository), review_id="routed-suite")
    suite = SecuritySkillSuite()
    secret, sanitized = suite.run_secret_boundary(artifact, now=NOW)
    scan = suite.run_routed(
        artifact,
        secret_result=secret,
        sanitized_diff=sanitized,
        planned_route_ids={"detect_secret": ()},
        now=NOW,
    )
    assert [item.status for item in scan.coverage] == [
        CoverageStatus.COMPLETED,
        CoverageStatus.SKIPPED,
        CoverageStatus.SKIPPED,
    ]
    assert all(item.reason for item in scan.coverage)


def test_pass_run_is_read_only_and_persists_verifiable_artifacts(tmp_path: Path) -> None:
    repository, workspace = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    before_status = run_git(repository, "status", "--porcelain=v1")
    before_diff = run_git(repository, "diff", "--binary")
    before_source = (repository / "app.py").read_bytes()

    execution = make_runner(workspace).run(
        make_request(repository),
        review_id="p9-pass",
    )

    assert execution.report.status is GateStatus.PASS, (
        execution.report.decision.model_dump(mode="json"),
        tuple(item.model_dump(mode="json") for item in execution.report.errors),
    )
    assert execution.report.exit_code == 0
    assert execution.report.recheck_attempts == 0
    assert run_git(repository, "status", "--porcelain=v1") == before_status
    assert run_git(repository, "diff", "--binary") == before_diff
    assert (repository / "app.py").read_bytes() == before_source
    assert not (repository / "artifacts").exists()

    run_dir = execution.persisted.run_directory
    expected = {
        "input-summary.json",
        "sanitized-diff.json",
        "diff-analysis.json",
        "risk-routing.json",
        "security-review.json",
        "quality-review.json",
        "evidence-validation.json",
        "gate-decision.json",
        "model-calls.json",
        "review.json",
        "trace.jsonl",
        "report.md",
        "manifest.json",
    }
    assert {item.name for item in run_dir.iterdir()} == expected
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    for name, expected_hash in manifest["files"].items():
        assert hashlib.sha256((run_dir / name).read_bytes()).hexdigest() == expected_hash
    trace_lines = (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    sequences = [json.loads(item)["sequence"] for item in trace_lines]
    assert sequences == list(range(1, len(sequences) + 1))


def test_deterministic_secret_blocks_and_never_persists_plaintext(tmp_path: Path) -> None:
    secret = "sk-" + ("S" * 32)
    repository, workspace = make_repository(
        tmp_path,
        (
            "def calculate(value):\n"
            "    result = value + 1\n"
            "    return result\n"
            f"API_KEY = {secret!r}\n"
        ),
    )
    execution = make_runner(workspace).run(
        make_request(repository),
        review_id="p9-block",
    )
    assert execution.report.status is GateStatus.BLOCK
    assert execution.report.exit_code == 1
    persisted = b"".join(
        item.read_bytes() for item in execution.persisted.run_directory.iterdir()
    )
    assert secret.encode() not in persisted
    assert "B001" in execution.report.decision.matched_rule_ids


def test_medium_model_finding_needs_review_and_exhausts_one_recheck(tmp_path: Path) -> None:
    repository, workspace = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    execution = make_runner(workspace, medium_finding=True).run(
        make_request(repository),
        review_id="p9-needs",
    )
    assert execution.report.status is GateStatus.NEEDS_REVIEW
    assert execution.report.exit_code == 2
    assert execution.report.recheck_attempts == 1
    assert execution.report.recheck_exhausted is True
    assert {"N005", "N008"} <= set(execution.report.decision.matched_rule_ids)


def test_provider_failure_cannot_produce_pass(tmp_path: Path) -> None:
    repository, workspace = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    execution = make_runner(
        workspace,
        security_failure=ProviderErrorCode.TIMEOUT,
    ).run(make_request(repository), review_id="p9-timeout")
    assert execution.report.status is GateStatus.NEEDS_REVIEW
    assert execution.report.exit_code == 2
    assert {"N001", "N006", "N007", "N008"} <= set(
        execution.report.decision.matched_rule_ids
    )
    assert any(item.error_code == "TIMEOUT" for item in execution.report.errors)
    markdown = execution.persisted.report_path.read_text(encoding="utf-8")
    assert "## Execution errors" in markdown
    assert "`TIMEOUT`" in markdown


def test_artifact_workspace_inside_target_fails_without_false_pass(tmp_path: Path) -> None:
    repository, _ = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    runner = make_runner(repository)
    with pytest.raises(ReviewArtifactError, match="would modify"):
        runner.run(make_request(repository), review_id="p9-boundary")
    assert not (repository / "artifacts").exists()


def test_unsafe_review_id_fails_before_any_agent_call(tmp_path: Path) -> None:
    repository, workspace = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )

    class ForbiddenAgent:
        def run(self, *_, **__):
            raise AssertionError("an invalid review ID must fail before Agent execution")

    runner = LocalReviewRunner(
        workspace_root=workspace,
        diff_agent=ForbiddenAgent(),
        security_agent=ForbiddenAgent(),
        quality_agent=ForbiddenAgent(),
    )
    with pytest.raises(ReviewArtifactError, match="review_id"):
        runner.run(make_request(repository), review_id="../unsafe")
    assert not (workspace / "artifacts").exists()


def test_whole_run_deadline_fails_closed_before_next_stage(
    tmp_path: Path, monkeypatch
) -> None:
    repository, workspace = make_repository(
        tmp_path,
        "def calculate(value):\n    result = value + 1\n    return result\n",
    )
    ticks = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr("codesentinel.runtime.runner.time.monotonic", lambda: next(ticks))

    with pytest.raises(LocalReviewRunError, match="deadline") as captured:
        make_runner(workspace).run(
            make_request(repository),
            review_id="p9-deadline",
            max_duration_seconds=1,
        )

    assert captured.value.code == "RUN_TIMEOUT"
    assert captured.value.stage is RunStage.SECRET_BOUNDARY
    assert not (workspace / "artifacts").exists()
