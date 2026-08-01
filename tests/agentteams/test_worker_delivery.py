from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import codesentinel.agentteams.delivery as delivery_module
from codesentinel.agentteams import (
    DiffSemanticPayload,
    QualityReviewPayload,
    RoleContextArtifact,
    SecurityReviewPayload,
    WorkerAssignmentEnvelope,
    WorkerDeliveryEnvelope,
    build_worker_delivery,
    load_and_validate_assignment,
    load_and_validate_delivery,
    load_and_validate_request,
    load_and_validate_role_context,
    load_role_payload,
    validate_delivery_against_assignment,
    write_delivery_atomic,
)
from codesentinel.agentteams.bundle import build_runtime_bundle
from codesentinel.agentteams.models import ArtifactPointer, worker_evidence_content_hash
from codesentinel.agentteams.serialization import canonical_json_bytes, sha256_hex
from codesentinel.agentteams.validation import AgentTeamsValidationError

FIXTURES = Path(__file__).parent / "fixtures"
REQUEST = FIXTURES / "review-request.json"
ARTIFACT = FIXTURES / "sanitized-diff.json"
NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
STARTED = datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC)
FINISHED = datetime(2026, 8, 1, 12, 0, 2, tzinfo=UTC)
CONTEXT_CONTENT = "value = validate(raw_value)"
CONTEXT_CONTENT_HASH = hashlib.sha256(CONTEXT_CONTENT.encode("utf-8")).hexdigest()
LINE_NUMBERS = {"diff_analyzer": 11, "security_scanner": 41, "quality_reviewer": 52}


def context_line_ref(role: str) -> str:
    material = "\0".join(
        str(part)
        for part in (
            "a" * 64,
            "src/example.py",
            "hunk-example",
            "new",
            LINE_NUMBERS[role],
            CONTEXT_CONTENT_HASH,
        )
    )
    return f"line-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


LINE_REFS = {role: context_line_ref(role) for role in LINE_NUMBERS}
SKILL_NAMES = {
    "diff_analyzer": "codesentinel-diff-review",
    "security_scanner": "codesentinel-security-review",
    "quality_reviewer": "codesentinel-quality-review",
}


def payload_for(role: str) -> dict[str, object]:
    if role == "diff_analyzer":
        return {
            "summary": "The change validates input before execution.",
            "change_intents": ["reject malformed input"],
            "affected_symbols": ["validate_request"],
        }
    if role == "security_scanner":
        return {
            "findings": [
                {
                    "category": "command_injection",
                    "severity": "high",
                    "title": "Shell argument may cross a trust boundary",
                    "claim": "A changed argument reaches a shell execution boundary.",
                    "recommendation": "Use an argument vector and validate the value.",
                    "confidence": 0.88,
                    "line_refs": [LINE_REFS[role]],
                }
            ],
            "summary": "One semantic command-execution risk requires review.",
        }
    if role == "quality_reviewer":
        return {
            "findings": [
                {
                    "category": "test_gap",
                    "severity": "medium",
                    "title": "Failure branch lacks a focused test",
                    "claim": "The new error branch is not covered in the supplied context.",
                    "recommendation": "Add a regression test for the error result.",
                    "confidence": 0.8,
                    "line_refs": [LINE_REFS[role]],
                }
            ],
            "summary": "One focused regression test is recommended.",
        }
    raise AssertionError(f"unsupported test role: {role}")


def context_metadata(role: str) -> dict[str, object]:
    if role == "diff_analyzer":
        return {
            "diff_hash": "a" * 64,
            "changed_files": ["src/example.py"],
            "total_additions": 1,
            "total_deletions": 1,
            "unsupported_files": [],
            "parser_version": "p5-1.0.0",
        }
    if role == "security_scanner":
        return {
            "diff_hash": "a" * 64,
            "deterministic_findings": [],
            "deterministic_coverage": [
                {
                    "skill_name": name,
                    "skill_version": "1.0.0",
                    "status": "completed",
                    "error_code": None,
                }
                for name in ("detect_secret", "detect_injection", "detect_dangerous_call")
            ],
        }
    if role == "quality_reviewer":
        return {
            "diff_hash": "a" * 64,
            "ruff_summary": "Ruff completed with no findings.",
        }
    raise AssertionError(f"unsupported test role: {role}")


def write_payload(tmp_path: Path, role: str, payload: dict[str, object] | None = None) -> Path:
    path = tmp_path / f"{role}-payload.json"
    path.write_text(
        json.dumps(payload or payload_for(role), ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )
    return path


def make_assignment_context(
    tmp_path: Path,
    role: str,
    task_id: str,
    *,
    attempt: int = 1,
) -> tuple[WorkerAssignmentEnvelope, RoleContextArtifact, Path, Path]:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    context = RoleContextArtifact.model_validate_json(
        canonical_json_bytes(
            {
                "schema_name": "CodeSentinelAgentTeamsRoleContext",
                "schema_version": "1.0.0",
                "review_id": request.review_id,
                "role": role,
                "source_artifact_ids": (
                    ["git-diff-fixture", "security-scan-fixture"]
                    if role == "security_scanner"
                    else ["git-diff-fixture"]
                ),
                "lines": [
                    {
                        "line_ref": LINE_REFS[role],
                        "file_path": "src/example.py",
                        "hunk_id": "hunk-example",
                        "kind": "addition",
                        "side": "new",
                        "line_number": LINE_NUMBERS[role],
                        "content": CONTEXT_CONTENT,
                        "content_hash": CONTEXT_CONTENT_HASH,
                    }
                ],
                "metadata": context_metadata(role),
                "cloud_safe": True,
            }
        )
    )
    context_path = tmp_path / f"{role}-context.json"
    context_path.write_bytes(canonical_json_bytes(context))
    assignment = WorkerAssignmentEnvelope(
        review_id=request.review_id,
        trace_id=request.trace_id,
        task_id=task_id,
        parent_task_id=request.root_task_id,
        role=role,
        attempt=attempt,
        skill_name=SKILL_NAMES[role],
        review_input=ArtifactPointer(
            ref=request.input_artifact_ref,
            sha256=request.input_sha256,
        ),
        role_context=ArtifactPointer(
            ref=f"shared/tasks/{task_id}/base/role-context.json",
            sha256=sha256_hex(context_path.read_bytes()),
        ),
        deadline_at=request.deadline_at,
        delivery_ref=f"shared/tasks/{task_id}/workspace/delivery.json",
    )
    assignment_path = tmp_path / f"{role}-assignment.json"
    assignment_path.write_bytes(canonical_json_bytes(assignment))
    return assignment, context, assignment_path, context_path


def delivery_path(tmp_path: Path, task_id: str) -> Path:
    destination = tmp_path / "shared" / "tasks" / task_id / "workspace" / "delivery.json"
    destination.parent.mkdir(parents=True)
    return destination


@pytest.mark.parametrize(
    ("role", "model_type"),
    [
        ("diff_analyzer", DiffSemanticPayload),
        ("security_scanner", SecurityReviewPayload),
        ("quality_reviewer", QualityReviewPayload),
    ],
)
def test_three_role_deliveries_are_correlated_and_authoritative(
    tmp_path: Path,
    role: str,
    model_type: type,
) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = f"task-20260801-120001-{role.replace('_', '-')}-fixture"
    _, _, assignment_path, context_path = make_assignment_context(tmp_path, role, task_id)
    assignment = load_and_validate_assignment(assignment_path, request, now=NOW)
    context = load_and_validate_role_context(context_path, assignment)
    payload = load_role_payload(write_payload(tmp_path, role), role=assignment.role)
    assert isinstance(payload, model_type)

    delivery = build_worker_delivery(
        request,
        assignment=assignment,
        context=context,
        payload=payload,
        started_at=STARTED,
        finished_at=FINISHED,
    )
    destination = delivery_path(tmp_path, task_id)
    write_delivery_atomic(
        delivery,
        destination,
        assignment=assignment,
        artifact_root=tmp_path,
    )

    assert destination.read_bytes() == canonical_json_bytes(delivery)
    loaded = load_and_validate_delivery(destination)
    validate_delivery_against_assignment(loaded, request, assignment, context)
    assert loaded.input_artifacts == (assignment.review_input, assignment.role_context)
    assert loaded.attempt == assignment.attempt
    assert loaded.evidence
    assert all(item.level == "E1" and item.source == "llm" for item in loaded.evidence)
    assert all(item.input_artifact == assignment.role_context for item in loaded.evidence)
    with pytest.raises(AgentTeamsValidationError, match="already exists"):
        write_delivery_atomic(
            delivery,
            destination,
            assignment=assignment,
            artifact_root=tmp_path,
        )


def test_role_payload_rejects_cross_role_and_authoritative_fields(tmp_path: Path) -> None:
    security = payload_for("security_scanner")
    with pytest.raises(AgentTeamsValidationError, match="quality_reviewer"):
        load_role_payload(
            write_payload(tmp_path, "security-as-quality", security),
            role="quality_reviewer",
        )

    diff = payload_for("diff_analyzer")
    diff.update(
        {
            "role": "security_scanner",
            "task_id": "task-model-authored",
            "gate_status": "PASS",
            "evidence_level": "E3",
            "output_sha256": "0" * 64,
        }
    )
    with pytest.raises(AgentTeamsValidationError, match="diff_analyzer"):
        load_role_payload(write_payload(tmp_path, "diff-overclaim", diff), role="diff_analyzer")


def test_builder_rejects_unknown_line_ref_and_late_delivery(tmp_path: Path) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-security-boundary"
    assignment, context, _, _ = make_assignment_context(
        tmp_path,
        "security_scanner",
        task_id,
    )
    payload_value = payload_for("security_scanner")
    payload_value["findings"][0]["line_refs"] = ["line-does-not-exist"]  # type: ignore[index]
    payload = load_role_payload(
        write_payload(tmp_path, "security-foreign-line", payload_value),
        role="security_scanner",
    )
    with pytest.raises(AgentTeamsValidationError, match="foreign context line"):
        build_worker_delivery(
            request,
            assignment=assignment,
            context=context,
            payload=payload,
            started_at=STARTED,
            finished_at=FINISHED,
        )

    valid_payload = load_role_payload(
        write_payload(tmp_path, "security_scanner"),
        role="security_scanner",
    )
    with pytest.raises(AgentTeamsValidationError, match="deadline"):
        build_worker_delivery(
            request,
            assignment=assignment,
            context=context,
            payload=valid_payload,
            started_at=STARTED,
            finished_at=datetime(2100, 1, 1, tzinfo=UTC),
        )


def test_assignment_and_context_reject_correlation_and_digest_tampering(
    tmp_path: Path,
) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-quality-assignment"
    assignment, _, assignment_path, context_path = make_assignment_context(
        tmp_path,
        "quality_reviewer",
        task_id,
    )

    assignment_value = assignment.model_dump(mode="json")
    assignment_value["review_id"] = "foreign-review"
    assignment_path.write_bytes(canonical_json_bytes(assignment_value))
    with pytest.raises(AgentTeamsValidationError, match="correlation"):
        load_and_validate_assignment(assignment_path, request, now=NOW)

    assignment_path.write_bytes(canonical_json_bytes(assignment))
    accepted_assignment = load_and_validate_assignment(assignment_path, request, now=NOW)
    context_value = json.loads(context_path.read_text(encoding="utf-8"))
    context_value["metadata"]["ruff_summary"] = "Tampered Ruff summary."
    context_path.write_bytes(canonical_json_bytes(context_value))
    with pytest.raises(AgentTeamsValidationError, match="digest"):
        load_and_validate_role_context(context_path, accepted_assignment)
    tampered_context = RoleContextArtifact.model_validate_json(
        canonical_json_bytes(context_value)
    )
    payload = load_role_payload(
        write_payload(tmp_path, "quality_reviewer"),
        role="quality_reviewer",
    )
    with pytest.raises(AgentTeamsValidationError, match="assignment digest"):
        build_worker_delivery(
            request,
            assignment=accepted_assignment,
            context=tampered_context,
            payload=payload,
            started_at=STARTED,
            finished_at=FINISHED,
        )


def test_security_context_requires_exact_trusted_source_and_coverage_set() -> None:
    base = {
        "schema_name": "CodeSentinelAgentTeamsRoleContext",
        "schema_version": "1.0.0",
        "review_id": "review-security-context",
        "role": "security_scanner",
        "source_artifact_ids": ["git-diff-only"],
        "lines": [
            {
                "line_ref": LINE_REFS["security_scanner"],
                "file_path": "src/example.py",
                "hunk_id": "hunk-example",
                "kind": "addition",
                "side": "new",
                "line_number": LINE_NUMBERS["security_scanner"],
                "content": CONTEXT_CONTENT,
                "content_hash": CONTEXT_CONTENT_HASH,
            }
        ],
        "metadata": context_metadata("security_scanner"),
        "cloud_safe": True,
    }
    with pytest.raises(ValidationError, match="source artifact count"):
        RoleContextArtifact.model_validate_json(json.dumps(base))

    base["source_artifact_ids"] = ["git-diff", "security-scan"]
    base["metadata"]["deterministic_coverage"][0]["skill_name"] = "renamed-skill"
    with pytest.raises(ValidationError, match="frozen deterministic coverage"):
        RoleContextArtifact.model_validate_json(json.dumps(base))


def test_security_delivery_fails_closed_on_failed_deterministic_coverage(
    tmp_path: Path,
) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-security-failed-coverage"
    assignment, context, _, _ = make_assignment_context(
        tmp_path,
        "security_scanner",
        task_id,
    )
    value = context.model_dump(mode="json")
    metadata = value["metadata"]
    assert isinstance(metadata, dict)
    coverage = metadata["deterministic_coverage"]
    assert isinstance(coverage, list)
    first = coverage[0]
    assert isinstance(first, dict)
    first["status"] = "failed"
    first["error_code"] = "TOOL_FAILURE"
    failed_context = RoleContextArtifact.model_validate_json(canonical_json_bytes(value))
    failed_assignment = assignment.model_copy(
        update={
            "role_context": ArtifactPointer(
                ref=assignment.role_context.ref,
                sha256=sha256_hex(canonical_json_bytes(failed_context)),
            )
        }
    )
    payload = load_role_payload(
        write_payload(tmp_path, "security_scanner"),
        role="security_scanner",
    )

    with pytest.raises(AgentTeamsValidationError, match="coverage blocks"):
        build_worker_delivery(
            request,
            assignment=failed_assignment,
            context=failed_context,
            payload=payload,
            started_at=STARTED,
            finished_at=FINISHED,
        )


def test_assigned_validator_rejects_attempt_and_foreign_lineage(tmp_path: Path) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-security-lineage"
    assignment, context, _, _ = make_assignment_context(
        tmp_path,
        "security_scanner",
        task_id,
    )
    payload = load_role_payload(
        write_payload(tmp_path, "security_scanner"),
        role="security_scanner",
    )
    delivery = build_worker_delivery(
        request,
        assignment=assignment,
        context=context,
        payload=payload,
        started_at=STARTED,
        finished_at=FINISHED,
    )

    value = delivery.model_dump(mode="json")
    value["attempt"] = 2
    wrong_attempt = WorkerDeliveryEnvelope.model_validate_json(json.dumps(value))
    with pytest.raises(AgentTeamsValidationError, match="identity"):
        validate_delivery_against_assignment(
            wrong_attempt,
            request,
            assignment,
            context,
        )

    foreign = ArtifactPointer(
        ref="shared/projects/codesentinel/reviews/foreign-review/input/foreign.json",
        sha256="1" * 64,
    )
    value = delivery.model_dump(mode="json")
    value["input_artifacts"].append(foreign.model_dump(mode="json"))
    evidence = value["evidence"][0]
    evidence["input_artifact"] = foreign.model_dump(mode="json")
    evidence["content_hash"] = worker_evidence_content_hash(
        role="security_scanner",
        summary=evidence["summary"],
        line_refs=tuple(evidence["line_refs"]),
        confidence=evidence["confidence"],
        input_artifact=foreign,
    )
    evidence["evidence_id"] = f"evidence-{evidence['content_hash'][:20]}"
    foreign_delivery = WorkerDeliveryEnvelope.model_validate_json(json.dumps(value))
    with pytest.raises(AgentTeamsValidationError, match="exactly match"):
        validate_delivery_against_assignment(
            foreign_delivery,
            request,
            assignment,
            context,
        )


def test_delivery_model_rejects_evidence_tampering(tmp_path: Path) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-security-tamper"
    assignment, context, _, _ = make_assignment_context(
        tmp_path,
        "security_scanner",
        task_id,
    )
    payload = load_role_payload(
        write_payload(tmp_path, "security_scanner"),
        role="security_scanner",
    )
    delivery = build_worker_delivery(
        request,
        assignment=assignment,
        context=context,
        payload=payload,
        started_at=STARTED,
        finished_at=FINISHED,
    )
    value = delivery.model_dump(mode="json")
    value["evidence"][0]["level"] = "E3"
    with pytest.raises(ValidationError):
        WorkerDeliveryEnvelope.model_validate_json(json.dumps(value))

    value = delivery.model_dump(mode="json")
    value["evidence"][0]["confidence"] = 0.01
    with pytest.raises(ValidationError, match="content_hash"):
        WorkerDeliveryEnvelope.model_validate_json(json.dumps(value))

    value = delivery.model_dump(mode="json")
    value["evidence"][0]["evidence_id"] = "evidence-relabelled"
    with pytest.raises(ValidationError, match="evidence_id"):
        WorkerDeliveryEnvelope.model_validate_json(json.dumps(value))

    with pytest.raises(AgentTeamsValidationError, match="one domain analysis"):
        build_worker_delivery(
            request,
            assignment=assignment,
            context=context,
            payload=payload,
            started_at=STARTED,
            finished_at=FINISHED,
            model_calls=0,
        )
    with pytest.raises(AgentTeamsValidationError, match="blocked"):
        build_worker_delivery(
            request,
            assignment=assignment,
            context=context,
            payload=payload,
            started_at=STARTED,
            finished_at=FINISHED,
            status="BLOCKED",
        )


def test_writer_rejects_cross_root_path_and_removes_partial_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = load_and_validate_request(REQUEST, ARTIFACT, now=NOW)
    task_id = "task-20260801-120001-diff-atomic"
    assignment, context, _, _ = make_assignment_context(tmp_path, "diff_analyzer", task_id)
    payload = load_role_payload(
        write_payload(tmp_path, "diff_analyzer"),
        role="diff_analyzer",
    )
    delivery = build_worker_delivery(
        request,
        assignment=assignment,
        context=context,
        payload=payload,
        started_at=STARTED,
        finished_at=FINISHED,
    )
    cross_root = (
        tmp_path
        / "other-root"
        / "shared"
        / "tasks"
        / task_id
        / "workspace"
        / "delivery.json"
    )
    cross_root.parent.mkdir(parents=True)
    with pytest.raises(AgentTeamsValidationError, match="artifact root"):
        write_delivery_atomic(
            delivery,
            cross_root,
            assignment=assignment,
            artifact_root=tmp_path,
        )

    destination = delivery_path(tmp_path, task_id)

    def fail_replace(_: object, __: object) -> None:
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(delivery_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        write_delivery_atomic(
            delivery,
            destination,
            assignment=assignment,
            artifact_root=tmp_path,
        )

    assert not destination.exists()
    assert list(destination.parent.iterdir()) == []


def test_isolated_runtime_builds_and_validates_assigned_delivery(tmp_path: Path) -> None:
    repository = Path(__file__).parents[2]
    bundle = build_runtime_bundle(repository, tmp_path / "bundle")
    task_id = "task-20260801-120001-diff-isolated"
    _, _, assignment_path, context_path = make_assignment_context(
        tmp_path,
        "diff_analyzer",
        task_id,
    )
    payload = write_payload(tmp_path, "diff_analyzer")
    delivery = delivery_path(tmp_path, task_id)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bundle.archive_path),
            "build-delivery",
            "--request",
            str(REQUEST),
            "--artifact",
            str(ARTIFACT),
            "--assignment",
            str(assignment_path),
            "--context",
            str(context_path),
            "--payload",
            str(payload),
            "--delivery",
            str(delivery),
            "--artifact-root",
            str(tmp_path),
            "--now",
            "2026-08-01T12:00:00Z",
            "--started-at",
            "2026-08-01T12:00:01Z",
            "--finished-at",
            "2026-08-01T12:00:02Z",
            "--model-calls",
            "1",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    wrapper = json.loads(completed.stdout)
    assert wrapper["ok"] is True
    assert wrapper["operation"] == "build-delivery"
    assert wrapper["model_calls"] == 0
    validation = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bundle.archive_path),
            "validate-assigned-delivery",
            "--request",
            str(REQUEST),
            "--artifact",
            str(ARTIFACT),
            "--assignment",
            str(assignment_path),
            "--context",
            str(context_path),
            "--delivery",
            str(delivery),
            "--now",
            "2026-08-01T12:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert json.loads(validation.stdout)["operation"] == "validate-assigned-delivery"
    loaded = load_and_validate_delivery(delivery)
    assert loaded.role == "diff_analyzer"
    assert loaded.input_artifacts[1].ref == (
        f"shared/tasks/{task_id}/base/role-context.json"
    )
