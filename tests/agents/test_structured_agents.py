from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codesentinel.agents import (
    CallPurpose,
    ContextBuildError,
    DeepSeekProvider,
    DeepSeekProviderSettings,
    DiffAnalyzerAgent,
    DiffAnalyzerContext,
    ModelCallBudget,
    ProviderErrorCode,
    QualityReviewerAgent,
    QualityReviewerContext,
    SecurityReviewerContext,
    SecuritySemanticAgent,
)
from codesentinel.domain import (
    AgentArtifact,
    DiffAnalysis,
    EvidenceLevel,
    EvidenceSource,
    FindingStatus,
    ReviewRequest,
    SkillStatus,
)
from codesentinel.gitdiff import GitDiffReader
from codesentinel.skills.security import (
    BanditObservation,
    DetectDangerousCallSkill,
    DetectSecretSkill,
    SecretObservation,
    SecuritySkillSuite,
)
from codesentinel.skills.security.base import SkillExecutionError
from codesentinel.skills.security.models import SkillErrorCode


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


def make_artifact(tmp_path: Path, before: str, after: str, *, review_id: str):
    repository = tmp_path / review_id
    repository.mkdir()
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
    target.write_text(before, encoding="utf-8", newline="\n")
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "base")
    base_oid = run_git(repository, "rev-parse", "HEAD")
    target.write_text(after, encoding="utf-8", newline="\n")
    run_git(repository, "add", "app.py")
    run_git(repository, "commit", "-m", "target")
    target_oid = run_git(repository, "rev-parse", "HEAD")
    return GitDiffReader().read(
        ReviewRequest(
            repository_path=str(repository.resolve()),
            base_revision=base_oid,
            target_revision=target_oid,
        ),
        review_id=review_id,
    )


class EmptySecretsAdapter:
    version = "test-empty"

    def scan(self, lines) -> tuple[SecretObservation, ...]:
        return ()


class FailingSecretsAdapter:
    version = "test-failure"

    def scan(self, lines) -> tuple[SecretObservation, ...]:
        raise SkillExecutionError(SkillErrorCode.TOOL_ERROR, "test adapter failed")


class EmptyBanditAdapter:
    version = "test-empty"

    def scan(self, lines) -> tuple[BanditObservation, ...]:
        return ()


def security_suite(secret_adapter=None) -> SecuritySkillSuite:
    return SecuritySkillSuite(
        secret_skill=DetectSecretSkill(adapter=secret_adapter or EmptySecretsAdapter()),
        dangerous_call_skill=DetectDangerousCallSkill(adapter=EmptyBanditAdapter()),
    )


def make_contexts(tmp_path: Path, *, review_id: str = "p7-context"):
    artifact = make_artifact(
        tmp_path,
        "def calculate(value):\n    return value\n",
        "def calculate(value):\n    result = value + 1\n    return result\n",
        review_id=review_id,
    )
    scan = security_suite().run(artifact)
    return (
        artifact,
        scan,
        DiffAnalyzerContext.from_artifacts(artifact, scan.sanitized_diff),
        SecurityReviewerContext.from_scan(artifact, scan),
        QualityReviewerContext.from_artifacts(
            artifact,
            scan.sanitized_diff,
            ruff_summary="Ruff completed with no findings.",
        ),
    )


def fake_response(
    content: str,
    *,
    finish_reason: str = "stop",
    reasoning_content: str | None = None,
):
    message = SimpleNamespace(content=content, reasoning_content=reasoning_content)
    usage = SimpleNamespace(
        prompt_tokens=100,
        prompt_cache_hit_tokens=20,
        prompt_cache_miss_tokens=80,
        completion_tokens=50,
        total_tokens=150,
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason=finish_reason)],
        usage=usage,
        model="deepseek-v4-pro",
    )


class SequencedCompletions:
    def __init__(self, *items: object) -> None:
        self._items = list(items)
        self.requests: list[dict[str, object]] = []

    def create(self, **kwargs: object):
        self.requests.append(kwargs)
        if not self._items:
            raise AssertionError("unexpected model call")
        item = self._items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def provider_with(completions: SequencedCompletions, *, key: str = "unit-test-key"):
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = DeepSeekProvider(
        DeepSeekProviderSettings(api_key=key),
        client_factory=lambda **_: client,
        sleeper=lambda _: None,
    )
    return provider


def diff_payload() -> str:
    return json.dumps(
        {
            "summary": "The calculation now stores an incremented intermediate result.",
            "change_intents": ["increment the supplied value"],
            "affected_symbols": ["calculate"],
        }
    )


def security_payload(line_ref: str, *, extra: dict[str, object] | None = None) -> str:
    finding: dict[str, object] = {
        "category": "auth_boundary",
        "severity": "medium",
        "title": "Authorization semantics require review",
        "claim": "The changed line may affect a trusted value before authorization.",
        "recommendation": "Confirm authorization before using the transformed value.",
        "confidence": 0.72,
        "line_refs": [line_ref],
    }
    if extra:
        finding.update(extra)
    return json.dumps({"findings": [finding], "summary": "One semantic risk found."})


def quality_payload(line_ref: str) -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "category": "test_gap",
                    "severity": "medium",
                    "title": "Changed branch lacks a focused test",
                    "claim": "The new result path has no corresponding test in this diff.",
                    "recommendation": "Add a test for the incremented result.",
                    "confidence": 0.8,
                    "line_refs": [line_ref],
                }
            ],
            "summary": "A focused regression test is recommended.",
        }
    )


def test_diff_analyzer_returns_frozen_domain_schema_and_call_metadata(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    completions = SequencedCompletions(fake_response(diff_payload()))
    provider = provider_with(completions)
    budget = ModelCallBudget()

    result = DiffAnalyzerAgent(provider).run(diff_context, budget=budget)

    assert result.status is SkillStatus.SUCCESS
    assert isinstance(result.output, DiffAnalysis)
    assert result.output.summary.startswith("The calculation")
    assert result.output.diff_hash == diff_context.diff_hash
    assert budget.used == 1
    call = result.calls[0]
    assert call.target_schema == "DiffSemanticPayload@1.0.0"
    assert call.prompt_tokens == 100
    assert call.estimated_cost_usd == pytest.approx(
        (20 * 0.003625 + 80 * 0.435 + 50 * 0.87) / 1_000_000
    )
    assert "content" not in call.model_dump()
    assert completions.requests[0]["temperature"] == 0.1
    assert completions.requests[0]["extra_body"]["thinking"] == {"type": "disabled"}


def test_security_agent_forces_llm_evidence_to_e1(tmp_path: Path) -> None:
    _, _, _, security_context, _ = make_contexts(tmp_path)
    line_ref = security_context.lines[0].line_ref
    completions = SequencedCompletions(fake_response(security_payload(line_ref)))
    result = SecuritySemanticAgent(provider_with(completions)).run(
        security_context,
        budget=ModelCallBudget(),
    )

    assert result.status is SkillStatus.SUCCESS
    assert isinstance(result.output, AgentArtifact)
    assert result.output.schema_name == "SecurityReview"
    assert result.output.agent_id == "security-scanner"
    assert result.output.findings[0].status is FindingStatus.SUSPECTED
    assert all(item.level is EvidenceLevel.E1 for item in result.output.evidence)
    assert all(item.source is EvidenceSource.LLM for item in result.output.evidence)
    assert result.output.prompt_version == "security-semantic-1.0.0"


def test_quality_agent_returns_quality_artifact(tmp_path: Path) -> None:
    _, _, _, _, quality_context = make_contexts(tmp_path)
    line_ref = quality_context.lines[0].line_ref
    result = QualityReviewerAgent(
        provider_with(SequencedCompletions(fake_response(quality_payload(line_ref))))
    ).run(quality_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.SUCCESS
    assert isinstance(result.output, AgentArtifact)
    assert result.output.schema_name == "QualityReview"
    assert result.output.agent_id == "quality-reviewer"
    assert result.output.coverage[0].skill_name == "review_code_quality"
    assert all(item.level is EvidenceLevel.E1 for item in result.output.evidence)


def test_three_agent_normal_path_uses_three_of_four_calls(tmp_path: Path) -> None:
    _, _, diff_context, security_context, quality_context = make_contexts(tmp_path)
    completions = SequencedCompletions(
        fake_response(diff_payload()),
        fake_response(security_payload(security_context.lines[0].line_ref)),
        fake_response(quality_payload(quality_context.lines[0].line_ref)),
    )
    provider = provider_with(completions)
    budget = ModelCallBudget()

    results = (
        DiffAnalyzerAgent(provider).run(diff_context, budget=budget),
        SecuritySemanticAgent(provider).run(security_context, budget=budget),
        QualityReviewerAgent(provider).run(quality_context, budget=budget),
    )

    assert all(item.status is SkillStatus.SUCCESS for item in results)
    assert budget.used == 3
    assert budget.remaining == 1
    assert len(completions.requests) == 3
    assert [result.calls[0].review_call_index for result in results] == [1, 2, 3]


def test_agent_contexts_and_cloud_payloads_are_role_isolated(tmp_path: Path) -> None:
    _, _, diff_context, security_context, quality_context = make_contexts(tmp_path)
    completions = SequencedCompletions(
        fake_response(diff_payload()),
        fake_response(security_payload(security_context.lines[0].line_ref)),
        fake_response(quality_payload(quality_context.lines[0].line_ref)),
    )
    provider = provider_with(completions)
    budget = ModelCallBudget()
    DiffAnalyzerAgent(provider).run(diff_context, budget=budget)
    SecuritySemanticAgent(provider).run(security_context, budget=budget)
    QualityReviewerAgent(provider).run(quality_context, budget=budget)

    user_payloads = [request["messages"][1]["content"] for request in completions.requests]
    assert "deterministic_findings" not in user_payloads[0]
    assert "ruff_summary" not in user_payloads[0]
    assert "deterministic_findings" in user_payloads[1]
    assert "ruff_summary" not in user_payloads[1]
    assert "ruff_summary" in user_payloads[2]
    assert "deterministic_findings" not in user_payloads[2]
    assert all(diff_context.review_id not in item for item in user_payloads)


def test_invalid_json_gets_exactly_one_schema_repair(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    completions = SequencedCompletions(
        fake_response("not-json"),
        fake_response(diff_payload()),
    )
    result = DiffAnalyzerAgent(provider_with(completions)).run(
        diff_context,
        budget=ModelCallBudget(),
    )

    assert result.status is SkillStatus.SUCCESS
    assert [item.purpose for item in result.calls] == [
        CallPurpose.INITIAL,
        CallPurpose.SCHEMA_REPAIR,
    ]
    assert result.calls[0].failure_code is ProviderErrorCode.INVALID_JSON
    assert len(completions.requests) == 2


@pytest.mark.parametrize("invalid", ["not-json", "{}", ""])
def test_second_invalid_schema_response_fails_closed(tmp_path: Path, invalid: str) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path, review_id=f"invalid-{len(invalid)}")
    completions = SequencedCompletions(fake_response(invalid), fake_response(invalid))
    result = DiffAnalyzerAgent(provider_with(completions)).run(
        diff_context,
        budget=ModelCallBudget(),
    )

    assert result.status is SkillStatus.FAILED
    assert result.output is None
    assert result.failure_code in {
        ProviderErrorCode.INVALID_JSON,
        ProviderErrorCode.SCHEMA_ERROR,
        ProviderErrorCode.EMPTY_RESPONSE,
    }
    assert len(result.calls) == 2


def test_timeout_retries_once_then_succeeds(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    sleeps: list[float] = []
    completions = SequencedCompletions(
        TimeoutError("provider timed out"),
        fake_response(diff_payload()),
    )
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = DeepSeekProvider(
        DeepSeekProviderSettings(api_key="unit-test-key"),
        client_factory=lambda **_: client,
        sleeper=sleeps.append,
    )
    result = DiffAnalyzerAgent(provider).run(diff_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.SUCCESS
    assert result.calls[0].failure_code is ProviderErrorCode.TIMEOUT
    assert result.calls[1].purpose is CallPurpose.NETWORK_RETRY
    assert sleeps == [0.25]


class FakeRateLimitError(RuntimeError):
    status_code = 429

    def __init__(self, message: str, retry_after: str = "9") -> None:
        super().__init__(message)
        self.response = SimpleNamespace(status_code=429, headers={"Retry-After": retry_after})


def test_rate_limit_honors_bounded_retry_after(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    sleeps: list[float] = []
    completions = SequencedCompletions(
        FakeRateLimitError("slow down"),
        fake_response(diff_payload()),
    )
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = DeepSeekProvider(
        DeepSeekProviderSettings(api_key="unit-test-key"),
        client_factory=lambda **_: client,
        sleeper=sleeps.append,
    )
    result = DiffAnalyzerAgent(provider).run(diff_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.SUCCESS
    assert result.calls[0].failure_code is ProviderErrorCode.RATE_LIMIT
    assert sleeps == [2.0]


def test_repeated_rate_limit_fails_without_output(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    result = DiffAnalyzerAgent(
        provider_with(
            SequencedCompletions(
                FakeRateLimitError("first"),
                FakeRateLimitError("second"),
            )
        )
    ).run(diff_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.FAILED
    assert result.failure_code is ProviderErrorCode.RATE_LIMIT
    assert result.output is None
    assert len(result.calls) == 2


def test_budget_exhaustion_prevents_another_network_call(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    completions = SequencedCompletions(fake_response(diff_payload()))
    budget = ModelCallBudget(max_calls=1)
    provider = provider_with(completions)
    first = DiffAnalyzerAgent(provider).run(diff_context, budget=budget)
    second = DiffAnalyzerAgent(provider).run(diff_context, budget=budget)

    assert first.status is SkillStatus.SUCCESS
    assert second.status is SkillStatus.FAILED
    assert second.failure_code is ProviderErrorCode.BUDGET_EXCEEDED
    assert second.calls == ()
    assert len(completions.requests) == 1


def test_model_cannot_self_promote_evidence_to_e3(tmp_path: Path) -> None:
    _, _, _, security_context, _ = make_contexts(tmp_path)
    line_ref = security_context.lines[0].line_ref
    invalid = security_payload(line_ref, extra={"evidence_level": "E3"})
    valid = security_payload(line_ref)
    result = SecuritySemanticAgent(
        provider_with(
            SequencedCompletions(fake_response(invalid), fake_response(valid))
        )
    ).run(security_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.SUCCESS
    assert len(result.calls) == 2
    assert result.calls[0].failure_code is ProviderErrorCode.SCHEMA_ERROR
    assert isinstance(result.output, AgentArtifact)
    assert all(item.level is EvidenceLevel.E1 for item in result.output.evidence)


def test_unknown_line_reference_fails_domain_conversion(tmp_path: Path) -> None:
    _, _, _, security_context, _ = make_contexts(tmp_path)
    result = SecuritySemanticAgent(
        provider_with(
            SequencedCompletions(fake_response(security_payload("line-not-in-context")))
        )
    ).run(security_context, budget=ModelCallBudget())

    assert result.status is SkillStatus.FAILED
    assert result.failure_code is ProviderErrorCode.OUTPUT_CONTRACT_ERROR
    assert result.output is None


def test_secret_is_masked_before_any_provider_request(tmp_path: Path) -> None:
    secret = "sk-" + ("P" * 32)
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        f"VALUE = 1\nAPI_KEY = {secret!r}\n",
        review_id="p7-secret",
    )
    scan = security_suite().run(artifact)
    context = SecurityReviewerContext.from_scan(artifact, scan)
    completions = SequencedCompletions(
        fake_response(json.dumps({"findings": [], "summary": "No semantic additions."}))
    )
    result = SecuritySemanticAgent(provider_with(completions)).run(
        context,
        budget=ModelCallBudget(),
    )

    assert result.status is SkillStatus.SUCCESS
    serialized_request = json.dumps(completions.requests)
    assert secret not in serialized_request
    assert "<REDACTED:" in serialized_request


def test_secret_scan_failure_blocks_context_before_model_call(tmp_path: Path) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 2\n",
        review_id="p7-unsafe",
    )
    scan = security_suite(FailingSecretsAdapter()).run(artifact)

    with pytest.raises(ContextBuildError) as captured:
        SecurityReviewerContext.from_scan(artifact, scan)

    assert captured.value.code is ProviderErrorCode.CONTEXT_UNSAFE


def test_provider_failure_redacts_api_key_and_discards_reasoning(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)
    key = "sk-" + ("K" * 24)
    failure = RuntimeError(f"Authorization: Bearer {key}")
    failed = DiffAnalyzerAgent(
        provider_with(SequencedCompletions(failure), key=key)
    ).run(diff_context, budget=ModelCallBudget())
    assert failed.status is SkillStatus.FAILED
    assert key not in failed.model_dump_json()

    reasoning = "private hidden reasoning that must never be stored"
    successful = DiffAnalyzerAgent(
        provider_with(
            SequencedCompletions(
                fake_response(diff_payload(), reasoning_content=reasoning)
            )
        )
    ).run(diff_context, budget=ModelCallBudget())
    assert successful.status is SkillStatus.SUCCESS
    assert reasoning not in successful.model_dump_json()


def test_python_indentation_survives_p6_to_p7_context(tmp_path: Path) -> None:
    _, _, diff_context, _, _ = make_contexts(tmp_path)

    assert any(line.content.startswith("    ") for line in diff_context.lines)
