from __future__ import annotations

from types import SimpleNamespace

import pytest

from codesentinel.domain import GateStatus
from codesentinel.preflight.deepseek import MissingApiKeyError
from codesentinel.runtime import LocalReviewRunError, RunStage
from codesentinel.runtime.cli import main


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [
        (GateStatus.PASS, 0),
        (GateStatus.BLOCK, 1),
        (GateStatus.NEEDS_REVIEW, 2),
    ],
)
def test_cli_returns_gate_exit_code_and_builds_requested_mode(
    tmp_path, capsys, status, expected_exit
) -> None:
    repository = tmp_path / "target"
    workspace = tmp_path / "workspace"
    repository.mkdir()
    workspace.mkdir()
    captured = {}

    class FakeRunner:
        def run(
            self,
            request,
            *,
            review_id,
            allow_recheck,
            max_duration_seconds,
        ):
            captured["request"] = request
            captured["review_id"] = review_id
            captured["allow_recheck"] = allow_recheck
            captured["max_duration_seconds"] = max_duration_seconds
            metrics = SimpleNamespace(
                completed_skills=3,
                skipped_skills=1,
                failed_skills=0,
                model_calls=3,
                total_tokens=90,
                estimated_cost_usd=0.0001,
            )
            report = SimpleNamespace(
                status=status,
                review_id="cli-contract",
                exit_code=expected_exit,
                decision=SimpleNamespace(matched_rule_ids=("P001",)),
                metrics=metrics,
                errors=(),
            )
            persisted = SimpleNamespace(
                report_path=workspace / "report.md",
                decision_path=workspace / "gate-decision.json",
                trace_path=workspace / "trace.jsonl",
                manifest_path=workspace / "manifest.json",
            )
            return SimpleNamespace(report=report, persisted=persisted)

    code = main(
        [
            str(repository),
            "--workspace",
            str(workspace),
            "--staged-only",
            "--no-recheck",
            "--review-id",
            "cli-contract",
        ],
        settings_loader=lambda _: object(),
        runner_factory=lambda settings, selected: FakeRunner(),
    )

    assert code == expected_exit
    assert captured["request"].repository_path == str(repository.resolve())
    assert captured["request"].include_staged is True
    assert captured["request"].include_unstaged is False
    assert captured["request"].include_untracked is False
    assert captured["review_id"] == "cli-contract"
    assert captured["allow_recheck"] is False
    assert captured["max_duration_seconds"] == 240
    output = capsys.readouterr()
    assert f"CodeSentinel decision: {status.value}" in output.out
    assert output.err == ""


def test_cli_missing_key_exits_three_without_calling_runner(tmp_path, capsys) -> None:
    repository = tmp_path / "target"
    repository.mkdir()

    def missing_key(_):
        raise MissingApiKeyError("DEEPSEEK_API_KEY is not configured.")

    def forbidden_runner(*_):
        raise AssertionError("runner must not be constructed")

    code = main(
        [str(repository)],
        settings_loader=missing_key,
        runner_factory=forbidden_runner,
    )

    assert code == 3
    output = capsys.readouterr()
    assert "CONFIG_ERROR" in output.err
    assert "PASS" not in output.err


def test_cli_runtime_failure_is_fail_closed_and_does_not_leak_exception(
    tmp_path, capsys
) -> None:
    repository = tmp_path / "target"
    workspace = tmp_path / "workspace"
    repository.mkdir()
    workspace.mkdir()

    class BrokenRunner:
        def run(self, *_, **__):
            raise LocalReviewRunError(
                "GIT_INPUT_ERROR",
                RunStage.DIFF,
                "The selected worktree could not be read.",
            )

    code = main(
        [str(repository), "--workspace", str(workspace)],
        settings_loader=lambda _: object(),
        runner_factory=lambda *_: BrokenRunner(),
    )

    assert code == 3
    output = capsys.readouterr()
    assert "GIT_INPUT_ERROR" in output.err
    assert "no PASS" not in output.err
    assert output.out == ""


def test_cli_rejects_revision_and_worktree_mode_mix(tmp_path, capsys) -> None:
    repository = tmp_path / "target"
    repository.mkdir()

    with pytest.raises(SystemExit) as captured:
        main([str(repository), "--target", "main", "--staged-only"])

    assert captured.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err
