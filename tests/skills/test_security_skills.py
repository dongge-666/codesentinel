from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from codesentinel.domain import (
    CoverageStatus,
    EvidenceLevel,
    FindingStatus,
    ReviewRequest,
    RiskCategory,
    Severity,
    SkillStatus,
)
from codesentinel.gitdiff import GitDiffReader
from codesentinel.skills.security import (
    BanditObservation,
    DetectDangerousCallSkill,
    DetectInjectionSkill,
    DetectSecretSkill,
    SecretObservation,
    SecuritySkillSuite,
)
from codesentinel.skills.security.base import SkillExecutionError
from codesentinel.skills.security.models import SkillErrorCode

FIXED_TIME = datetime(2026, 7, 31, 8, 0, tzinfo=UTC)


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


def make_artifact(
    tmp_path: Path,
    before: str,
    after: str,
    *,
    review_id: str,
    max_changed_lines: int = 1000,
):
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
            max_changed_lines=max_changed_lines,
        ),
        review_id=review_id,
    )


class EmptySecretsAdapter:
    version = "test-empty"

    def scan(self, lines) -> tuple[SecretObservation, ...]:
        return ()


class EmptyBanditAdapter:
    version = "test-empty"

    def scan(self, lines) -> tuple[BanditObservation, ...]:
        return ()


class FailingSecretsAdapter:
    version = "test-failure"

    def scan(self, lines) -> tuple[SecretObservation, ...]:
        raise SkillExecutionError(SkillErrorCode.TOOL_ERROR, "test adapter failed")


class FailingBanditAdapter:
    version = "test-failure"

    def scan(self, lines) -> tuple[BanditObservation, ...]:
        raise RuntimeError("private tool exception")


def test_exact_secret_is_confirmed_masked_and_never_serialized(tmp_path: Path) -> None:
    secret = "sk-" + ("A" * 32)
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        f"VALUE = 1\nAPI_KEY = {secret!r}\n",
        review_id="secret-added",
    )
    result = DetectSecretSkill(adapter=EmptySecretsAdapter()).run(
        artifact,
        now=FIXED_TIME,
    )

    assert result.status is SkillStatus.SUCCESS
    assert len(result.findings) == len(result.evidence) == len(result.redactions) == 1
    finding = result.findings[0]
    assert finding.category is RiskCategory.SECRET
    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.CONFIRMED
    assert result.evidence[0].level is EvidenceLevel.E3
    assert result.verified_e3_evidence_ids == (result.evidence[0].evidence_id,)
    assert secret not in result.model_dump_json()
    assert secret not in result.redactions[0].masked_content
    assert "<REDACTED:OPENAI_STYLE_API_KEY:" in result.redactions[0].masked_content


def test_secret_deleted_from_existing_code_does_not_create_finding(tmp_path: Path) -> None:
    secret = "sk-" + ("D" * 32)
    artifact = make_artifact(
        tmp_path,
        f"API_KEY = {secret!r}\n",
        "API_KEY = load_from_environment()\n",
        review_id="secret-deleted",
    )
    result = DetectSecretSkill(adapter=EmptySecretsAdapter()).run(
        artifact,
        now=FIXED_TIME,
    )

    assert result.status is SkillStatus.SUCCESS
    assert result.findings == ()
    assert len(result.redactions) == 1
    assert result.redactions[0].side == "old"
    assert secret not in result.model_dump_json()


@pytest.mark.parametrize(
    ("source", "category"),
    [
        ('query = "SELECT * FROM users WHERE id=" + user_id\n', RiskCategory.SQL_INJECTION),
        ('query = f"SELECT * FROM users WHERE id={user_id}"\n', RiskCategory.SQL_INJECTION),
        ('os.system("deploy " + branch)\n', RiskCategory.COMMAND_INJECTION),
        ('subprocess.run(command, shell=True)\n', RiskCategory.COMMAND_INJECTION),
    ],
)
def test_injection_rules_locate_added_python_line(
    tmp_path: Path,
    source: str,
    category: RiskCategory,
) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 1\n" + source,
        review_id=f"injection-{category.value}-{len(source)}",
    )
    result = DetectInjectionSkill().run(artifact, now=FIXED_TIME)

    matching = [finding for finding in result.findings if finding.category is category]
    assert len(matching) == 1
    assert matching[0].locations[0].file_path == "app.py"
    assert matching[0].locations[0].side == "new"
    assert matching[0].locations[0].start_line == 2
    proof = next(item for item in result.evidence if item.evidence_id in matching[0].evidence_ids)
    assert proof.level is EvidenceLevel.E3
    assert proof.detector_version == "1.0.0"


def test_safe_subprocess_argument_list_is_not_high_risk(tmp_path: Path) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        'VALUE = 1\nsubprocess.run(["git", "status"], check=True)\n',
        review_id="safe-subprocess",
    )
    injection = DetectInjectionSkill().run(artifact, now=FIXED_TIME)
    dangerous = DetectDangerousCallSkill(adapter=EmptyBanditAdapter()).run(
        artifact,
        now=FIXED_TIME,
    )

    assert not any(item.severity is Severity.HIGH for item in injection.findings)
    assert not any(item.severity is Severity.HIGH for item in dangerous.findings)


@pytest.mark.parametrize(
    "source",
    [
        "eval(user_input)\n",
        "exec(payload)\n",
        'os.system("echo safe-looking")\n',
        'subprocess.run("echo ok", shell=True)\n',
    ],
)
def test_dangerous_builtin_rules_are_confirmed_e3(tmp_path: Path, source: str) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 1\n" + source,
        review_id=f"dangerous-{len(source)}-{source[:2]}",
    )
    result = DetectDangerousCallSkill(adapter=EmptyBanditAdapter()).run(
        artifact,
        now=FIXED_TIME,
    )

    assert len(result.findings) == len(result.evidence) == 1
    assert result.findings[0].category is RiskCategory.DANGEROUS_CALL
    assert result.findings[0].status is FindingStatus.CONFIRMED
    assert result.evidence[0].level is EvidenceLevel.E3
    assert result.evidence[0].evidence_id in result.verified_e3_evidence_ids


def test_deleted_dangerous_call_is_outside_finding_scope(tmp_path: Path) -> None:
    artifact = make_artifact(
        tmp_path,
        "eval(user_input)\n",
        "safe_parse(user_input)\n",
        review_id="dangerous-deleted",
    )
    result = DetectDangerousCallSkill(adapter=EmptyBanditAdapter()).run(
        artifact,
        now=FIXED_TIME,
    )

    assert result.findings == ()
    assert result.verified_e3_evidence_ids == ()


@pytest.mark.parametrize(
    "skill",
    [
        DetectSecretSkill(adapter=FailingSecretsAdapter()),
        DetectDangerousCallSkill(adapter=FailingBanditAdapter()),
    ],
)
def test_tool_failure_emits_e0_and_failed_coverage(tmp_path: Path, skill) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 2\n",
        review_id=f"failure-{skill.manifest.name}",
    )
    result = skill.run(artifact, now=FIXED_TIME)

    assert result.status is SkillStatus.FAILED
    assert result.coverage.status is CoverageStatus.FAILED
    assert result.coverage.error_code == SkillErrorCode.TOOL_ERROR.value
    assert result.findings == ()
    assert result.verified_e3_evidence_ids == ()
    assert len(result.evidence) == 1
    assert result.evidence[0].level is EvidenceLevel.E0
    assert "private tool exception" not in result.model_dump_json()


def test_suite_is_ordered_aggregated_and_cloud_safe_after_masking(tmp_path: Path) -> None:
    secret = "sk-" + ("S" * 32)
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        f"VALUE = 1\nAPI_KEY = {secret!r}\neval(user_input)\n",
        review_id="suite-success",
    )
    suite = SecuritySkillSuite(
        secret_skill=DetectSecretSkill(adapter=EmptySecretsAdapter()),
        dangerous_call_skill=DetectDangerousCallSkill(adapter=EmptyBanditAdapter()),
    )
    result = suite.run(artifact, now=FIXED_TIME)

    assert result.status is SkillStatus.SUCCESS
    assert tuple(item.manifest.name for item in result.skill_results) == (
        "detect_secret",
        "detect_injection",
        "detect_dangerous_call",
    )
    assert result.sanitized_diff.cloud_safe is True
    assert secret not in result.model_dump_json()
    assert any("<REDACTED:" in line.content for line in result.sanitized_diff.lines)
    assert set(result.verified_e3_evidence_ids) == {
        proof.evidence_id
        for proof in result.evidence
        if proof.level is EvidenceLevel.E3
    }


def test_suite_denies_source_disclosure_when_secret_scan_fails(tmp_path: Path) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 2\n",
        review_id="suite-failed",
    )
    suite = SecuritySkillSuite(
        secret_skill=DetectSecretSkill(adapter=FailingSecretsAdapter()),
        dangerous_call_skill=DetectDangerousCallSkill(adapter=EmptyBanditAdapter()),
    )
    result = suite.run(artifact, now=FIXED_TIME)

    assert result.status is SkillStatus.FAILED
    assert result.sanitized_diff.cloud_safe is False
    assert result.sanitized_diff.lines == ()


def test_skill_outputs_are_reproducible_for_same_diff_and_time(tmp_path: Path) -> None:
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        'VALUE = 1\nquery = "DELETE FROM users WHERE id=" + user_id\n',
        review_id="reproducible",
    )
    skill = DetectInjectionSkill()
    first = skill.run(artifact, now=FIXED_TIME)
    second = skill.run(artifact, now=FIXED_TIME)

    assert first.findings == second.findings
    assert first.evidence == second.evidence
    assert first.coverage.coverage_id == second.coverage.coverage_id


def test_manifests_publish_strict_versioned_contracts() -> None:
    manifests = (
        DetectSecretSkill(adapter=EmptySecretsAdapter()).manifest,
        DetectInjectionSkill().manifest,
        DetectDangerousCallSkill(adapter=EmptyBanditAdapter()).manifest,
    )

    assert {item.name for item in manifests} == {
        "detect_secret",
        "detect_injection",
        "detect_dangerous_call",
    }
    assert all(item.version == "1.0.0" for item in manifests)
    assert all(item.deterministic is True for item in manifests)
    assert all(item.max_retries == 0 for item in manifests)
    assert all(item.failure_behavior == "emit_e0_and_failed_coverage" for item in manifests)


def test_real_adapters_execute_without_failure(tmp_path: Path) -> None:
    secret = "AKIA" + ("Z" * 16)
    artifact = make_artifact(
        tmp_path,
        "VALUE = 1\n",
        f"VALUE = 1\nACCESS_KEY = {secret!r}\neval(user_input)\n",
        review_id="real-adapters",
    )
    result = SecuritySkillSuite().run(artifact, now=FIXED_TIME)

    assert result.status is SkillStatus.SUCCESS
    assert all(item.coverage.status is CoverageStatus.COMPLETED for item in result.skill_results)
    assert any(item.category is RiskCategory.SECRET for item in result.findings)
    assert any(item.category is RiskCategory.DANGEROUS_CALL for item in result.findings)
    assert secret not in result.model_dump_json()
