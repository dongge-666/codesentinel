from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from codesentinel.agentteams import (
    ReviewRequestEnvelope,
    WorkerDeliveryEnvelope,
    build_assignment_control,
    load_and_validate_delivery,
    load_and_validate_request,
    validate_delivery_against_request,
)
from codesentinel.agentteams.bundle import build_runtime_bundle
from codesentinel.agentteams.matrix_probe import (
    MatrixProbeError,
    validate_control_output,
)
from codesentinel.agentteams.validation import AgentTeamsValidationError

FIXTURES = Path(__file__).parent / "fixtures"
REQUEST = FIXTURES / "review-request.json"
ARTIFACT = FIXTURES / "sanitized-diff.json"
DELIVERY = FIXTURES / "worker-delivery.json"
NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
TASK_ID = "task-20260801-120001-diff-p10fixture"


def load_fixture(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_fixture_request_and_delivery_validate_fail_closed() -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    delivery = load_and_validate_delivery(DELIVERY)
    validate_delivery_against_request(
        delivery,
        request,
        expected_role="diff_analyzer",
        expected_task_id=TASK_ID,
    )

    assert request.budget.max_domain_model_calls == 4
    assert request.budget.max_total_model_calls == 8
    assert delivery.model_usage.calls == 0


def test_request_rejects_unsafe_or_unfrozen_values(tmp_path: Path) -> None:
    payload = load_fixture(REQUEST)
    payload["cloud_safe"] = False
    with pytest.raises(ValidationError):
        ReviewRequestEnvelope.model_validate_json(json.dumps(payload))

    payload = load_fixture(REQUEST)
    payload["budget"]["max_domain_model_calls"] = 5  # type: ignore[index]
    with pytest.raises(ValidationError):
        ReviewRequestEnvelope.model_validate_json(json.dumps(payload))

    payload = load_fixture(REQUEST)
    payload["input_artifact_ref"] = "shared/../escaped.json"
    with pytest.raises(ValidationError):
        ReviewRequestEnvelope.model_validate_json(json.dumps(payload))

    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    with pytest.raises(ValueError, match="expired"):
        request.assert_admissible(now=datetime(2100, 1, 1, tzinfo=UTC))

    request_path = tmp_path / "request.json"
    payload = load_fixture(REQUEST)
    payload["input_sha256"] = "0" * 64
    request_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AgentTeamsValidationError, match="digest"):
        load_and_validate_request(request_path, ARTIFACT, now=NOW)


def test_input_requires_canonical_json_and_rejects_duplicate_keys(tmp_path: Path) -> None:
    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(
        json.dumps(load_fixture(ARTIFACT), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(AgentTeamsValidationError, match="canonical"):
        load_and_validate_request(REQUEST, noncanonical, now=NOW)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_name":"CodeSentinelAgentTeamsReviewRequest",'
        '"schema_name":"duplicate"}',
        encoding="utf-8",
    )
    with pytest.raises(AgentTeamsValidationError, match="duplicate"):
        load_and_validate_request(duplicate, ARTIFACT, now=NOW)


def test_delivery_rejects_output_or_assignment_tampering() -> None:
    payload = load_fixture(DELIVERY)
    payload["output_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="output_sha256"):
        WorkerDeliveryEnvelope.model_validate_json(json.dumps(payload))

    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    delivery = load_and_validate_delivery(DELIVERY)
    with pytest.raises(AgentTeamsValidationError, match="role or task"):
        validate_delivery_against_request(
            delivery,
            request,
            expected_role="security_scanner",
            expected_task_id=TASK_ID,
        )


def test_control_message_contains_metadata_not_artifact_content() -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    control = build_assignment_control(
        request,
        task_id=TASK_ID,
        role="diff_analyzer",
    )
    matrix_text = control.to_matrix_text()
    content = json.loads(matrix_text)

    assert set(content) == {
        "schema_name",
        "schema_version",
        "event_type",
        "review_id",
        "trace_id",
        "task_id",
        "parent_task_id",
        "role",
        "attempt",
        "input_artifact",
        "deadline_at",
    }
    assert content["input_artifact"]["sha256"] == request.input_sha256
    assert "patch" not in matrix_text
    assert "value = 2" not in matrix_text
    assert str(ARTIFACT.resolve()) not in matrix_text
    assert len(matrix_text.encode("utf-8")) < 4096


def test_matrix_probe_rejects_data_plane_or_nonzero_model_wrapper(tmp_path: Path) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    control = build_assignment_control(
        request,
        task_id=TASK_ID,
        role="diff_analyzer",
    )
    output = tmp_path / "control-output.json"
    wrapper = {
        "ok": True,
        "operation": "build-control",
        "matrix_text": control.to_matrix_text(),
        "artifact_transport": "minio",
        "model_calls": 0,
    }
    output.write_text(json.dumps(wrapper), encoding="utf-8")
    assert validate_control_output(output) == control.to_matrix_text()

    wrapper["model_calls"] = 1
    output.write_text(json.dumps(wrapper), encoding="utf-8")
    with pytest.raises(MatrixProbeError, match="boundary"):
        validate_control_output(output)

    content = json.loads(control.to_matrix_text())
    content["patch"] = "not allowed"
    wrapper["model_calls"] = 0
    wrapper["matrix_text"] = json.dumps(content)
    output.write_text(json.dumps(wrapper), encoding="utf-8")
    with pytest.raises(MatrixProbeError, match="allow-list"):
        validate_control_output(output)


def test_bundle_is_reproducible_minimal_and_runs_isolated(tmp_path: Path) -> None:
    repository = Path(__file__).parents[2]
    first = build_runtime_bundle(repository, tmp_path / "first")
    second = build_runtime_bundle(repository, tmp_path / "second")

    assert first.archive_sha256 == second.archive_sha256
    assert first.archive_path.read_bytes() == second.archive_path.read_bytes()
    assert first.archive_sha256 == hashlib.sha256(first.archive_path.read_bytes()).hexdigest()
    manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
    assert manifest["archive_sha256"] == first.archive_sha256
    assert manifest["source_revision"] == first.source_revision
    assert manifest["source_dirty"] is True

    with zipfile.ZipFile(first.archive_path) as archive:
        names = set(archive.namelist())
    assert names == {
        "LICENSE",
        "__main__.py",
        "codesentinel/__init__.py",
        "codesentinel/agentteams/__init__.py",
        "codesentinel/agentteams/__main__.py",
        "codesentinel/agentteams/cli.py",
        "codesentinel/agentteams/models.py",
        "codesentinel/agentteams/runtime-manifest.json",
        "codesentinel/agentteams/serialization.py",
        "codesentinel/agentteams/validation.py",
    }
    assert not any(
        forbidden in name
        for name in names
        for forbidden in ("provider", "skills/security", ".env", "credential")
    )

    self_check = subprocess.run(
        [sys.executable, "-I", str(first.archive_path), "self-check"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    result = json.loads(self_check.stdout)
    assert result["ok"] is True
    assert result["model_calls"] == 0
    assert result["contract_version"] == "1.0.0"

    validation = subprocess.run(
        [
            sys.executable,
            "-I",
            str(first.archive_path),
            "validate-delivery",
            "--request",
            str(REQUEST),
            "--artifact",
            str(ARTIFACT),
            "--delivery",
            str(DELIVERY),
            "--task-id",
            TASK_ID,
            "--role",
            "diff_analyzer",
            "--now",
            "2026-08-01T12:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert json.loads(validation.stdout)["model_calls"] == 0
