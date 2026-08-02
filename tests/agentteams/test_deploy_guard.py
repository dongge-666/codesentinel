from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from codesentinel.agentteams.deploy_guard import (
    APPROVED_SKILL,
    APPROVED_WORKER,
    EXPECTED_OFFICIAL_SCRIPT_SHA256,
    EXPECTED_PACKAGE_FILES,
    EXPECTED_ROUTE,
    MAX_COMMAND_OUTPUT_CHARS,
    CommandResult,
    DeploymentBinding,
    DeploymentGuardError,
    GuardRequest,
    HeartbeatSnapshot,
    PackageManifest,
    QuietSample,
    QuietWindow,
    RouteSnapshot,
    UsageSnapshot,
    build_package_manifest_from_directory,
    command_evidence,
    execute_guarded_probe,
    redact_sensitive_text,
    registry_semantic_sha256,
    validate_command_result,
    validate_registry_restored,
)
from codesentinel.agentteams.serialization import sha256_hex

REPOSITORY = Path(__file__).parents[2]
ENTRY_POINT = (
    REPOSITORY
    / "deploy"
    / "agentteams"
    / "operations"
    / "guarded_skill_deploy.py"
)


def package_files() -> dict[str, str]:
    return {
        path: sha256_hex(f"content:{path}".encode())
        for path in EXPECTED_PACKAGE_FILES
    }


def deployment_binding(source_revision: str = "c" * 40) -> DeploymentBinding:
    return DeploymentBinding(
        schema_name="CodeSentinelWorkerSkillDeployment",
        schema_version="1.0.0",
        skill_name=APPROVED_SKILL,
        skill_version="1.0.0",
        source_revision=source_revision,
        source_dirty=False,
        runtime_bundle_ref=(
            "shared/projects/codesentinel/runtime/"
            f"{source_revision}/codesentinel-agentteams-runtime-0.1.0.pyz"
        ),
        runtime_bundle_sha256="a" * 64,
    )


def package_manifest(files: dict[str, str] | None = None) -> PackageManifest:
    return PackageManifest.from_mapping(
        worker_name=APPROVED_WORKER,
        skill_name=APPROVED_SKILL,
        deployment=deployment_binding(),
        files=package_files() if files is None else files,
    )


def registry(skills: list[str] | None = None, *, timestamp: str = "before") -> dict:
    return {
        "version": 1,
        "updated_at": timestamp,
        "workers": {
            APPROVED_WORKER: {
                "name": APPROVED_WORKER,
                "room_id": "diff-room",
                "runtime": "copaw",
                "skills": skills,
                "skills_updated_at": timestamp,
            },
            "cs-security-scanner": {
                "name": "cs-security-scanner",
                "room_id": "security-room",
                "runtime": "copaw",
                "skills": None,
                "skills_updated_at": timestamp,
            },
            "cs-quality-reviewer": {
                "name": "cs-quality-reviewer",
                "room_id": "quality-room",
                "runtime": "copaw",
                "skills": None,
                "skills_updated_at": timestamp,
            },
        },
    }


def request(
    *,
    worker_name: str = APPROVED_WORKER,
    skill_name: str = APPROVED_SKILL,
    script_sha256: str = EXPECTED_OFFICIAL_SCRIPT_SHA256,
) -> GuardRequest:
    return GuardRequest(
        worker_name=worker_name,
        skill_name=skill_name,
        source_revision="c" * 40,
        source_dirty=False,
        official_script_sha256=script_sha256,
    )


class FakeBackend:
    def __init__(self, fault: str | None = None) -> None:
        self.fault = fault
        self.events: list[str] = []
        self.backend_exception_raised = False
        self.staged = package_manifest()
        self.remote_manager: PackageManifest | None = None
        self.remote_worker: PackageManifest | None = None
        self.local: PackageManifest | None = None
        self.registry_value = registry()
        self.usage = UsageSnapshot(
            manager_calls=14,
            diff_calls=2,
            security_calls=3,
            quality_calls=4,
        )
        self.routes = RouteSnapshot(
            manager=EXPECTED_ROUTE,
            diff=EXPECTED_ROUTE,
            security=EXPECTED_ROUTE,
            quality=EXPECTED_ROUTE,
        )
        self.heartbeat = HeartbeatSnapshot(
            enabled=True,
            every="30m",
            target="main",
            activeHours=None,
        )
        if fault == "preexisting_remote":
            self.remote_manager = self.staged
            self.remote_worker = self.staged
        if fault == "preexisting_local":
            self.local = self.staged

    def read_staged_package(self) -> PackageManifest:
        self.events.append("read_staged")
        return self.staged

    def read_remote_package(self, identity: str) -> PackageManifest | None:
        self.events.append(f"read_remote:{identity}")
        if (
            self.fault == "backend_exception_after_add"
            and "official_add" in self.events
            and identity == "manager"
            and not self.backend_exception_raised
        ):
            self.backend_exception_raised = True
            raise RuntimeError("api_key=backend-secret remote read failed")
        return self.remote_manager if identity == "manager" else self.remote_worker

    def read_local_package(self) -> PackageManifest | None:
        self.events.append("read_local")
        return self.local

    def read_registry(self) -> dict:
        self.events.append("read_registry")
        return deepcopy(self.registry_value)

    def read_active_task_count(self) -> int:
        self.events.append("read_tasks")
        if self.fault == "active_task":
            return 1
        if (
            self.fault == "active_task_after_restore"
            and "heartbeat:restore" in self.events
        ):
            return 1
        return 0

    def read_routes(self) -> RouteSnapshot:
        self.events.append("read_routes")
        if self.fault == "route_changed_after_add" and "official_add" in self.events:
            return self.routes.model_copy(update={"diff": "other/model"})
        if (
            self.fault == "route_changed_after_restore"
            and "heartbeat:restore" in self.events
        ):
            return self.routes.model_copy(update={"diff": "other/model"})
        return self.routes

    def read_usage(self) -> UsageSnapshot:
        self.events.append("read_usage")
        if self.fault == "usage_changed_after_add" and "official_add" in self.events:
            return self.usage.model_copy(update={"diff_calls": self.usage.diff_calls + 1})
        if (
            self.fault == "usage_changed_after_heartbeat_restore"
            and "heartbeat:restore" in self.events
        ):
            return self.usage.model_copy(update={"manager_calls": self.usage.manager_calls + 1})
        return self.usage

    def read_heartbeat(self) -> HeartbeatSnapshot:
        self.events.append("read_heartbeat")
        return self.heartbeat

    def write_heartbeat(self, value: HeartbeatSnapshot) -> CommandResult:
        action = "restore" if value.enabled else "disable"
        self.events.append(f"heartbeat:{action}")
        if self.fault == "heartbeat_disable_failure" and not value.enabled:
            return CommandResult(1, stderr="scheduler unavailable")
        if self.fault == "heartbeat_restore_failure" and value.enabled:
            return CommandResult(1, stderr="scheduler unavailable")
        self.heartbeat = value
        return CommandResult(0, stdout=f"heartbeat {action}d")

    def heartbeat_job_removed(self) -> bool:
        self.events.append("heartbeat_removed_check")
        return not self.heartbeat.enabled and self.fault != "heartbeat_job_remains"

    def heartbeat_runtime_matches(self, value: HeartbeatSnapshot) -> bool:
        self.events.append("heartbeat_runtime_check")
        if self.fault == "heartbeat_restore_runtime_missing" and value.enabled:
            return False
        return self.heartbeat == value

    def measure_quiet_window(self) -> QuietWindow:
        self.events.append("quiet_window")
        final = self.usage
        if self.fault == "usage_drift_in_quiet_window":
            final = self.usage.model_copy(
                update={"manager_calls": self.usage.manager_calls + 1}
            )
        return QuietWindow(
            samples=(
                QuietSample(elapsed_seconds=0, usage=self.usage),
                QuietSample(elapsed_seconds=65, usage=self.usage),
                QuietSample(elapsed_seconds=130, usage=final),
            )
        )

    def invoke_official_add(self, worker_name: str, skill_name: str) -> CommandResult:
        assert (worker_name, skill_name) == (APPROVED_WORKER, APPROVED_SKILL)
        self.events.append("official_add")
        self.registry_value = registry([APPROVED_SKILL], timestamp="after-add")
        if self.fault == "access_denied":
            return CommandResult(
                0,
                stdout="0 B transferred AccessDenied api_key=plain-secret",
                stderr="Authorization: Bearer bearer-secret",
            )
        if self.fault == "zero_bytes":
            return CommandResult(0, stdout="0 B transferred")
        if self.fault == "missing_remote":
            return CommandResult(0, stdout="Done")

        files = package_files()
        if self.fault == "partial_upload":
            files.pop("SKILL.md")
        elif self.fault == "unexpected_object":
            files["unexpected.txt"] = "f" * 64
        elif self.fault == "hash_mismatch":
            files["SKILL.md"] = "0" * 64
        self.remote_manager = package_manifest(files)
        self.remote_worker = self.remote_manager
        if self.fault == "registry_extra_change":
            self.registry_value["workers"]["cs-security-scanner"]["skills"] = [
                "codesentinel-security-review"
            ]
        return CommandResult(0, stdout="9 files transferred")

    def sync_worker(self, worker_name: str) -> CommandResult:
        assert worker_name == APPROVED_WORKER
        self.events.append("worker_sync")
        if self.fault == "sync_failure":
            return CommandResult(1, stderr="sync failed")
        self.local = self.staged
        if self.fault == "local_hash_mismatch":
            files = package_files()
            files["SKILL.md"] = "1" * 64
            self.local = package_manifest(files)
        return CommandResult(0, stdout="Config sync completed")

    def rollback(
        self,
        worker_name: str,
        skill_name: str,
        registry_preimage: dict,
    ) -> CommandResult:
        assert (worker_name, skill_name) == (APPROVED_WORKER, APPROVED_SKILL)
        self.events.append("rollback")
        if self.fault == "rollback_command_failure":
            raise RuntimeError("secret_key=rollback-secret cleanup unavailable")
        self.registry_value = deepcopy(registry_preimage)
        self.local = None
        self.remote_worker = None
        if self.fault != "rollback_incomplete":
            self.remote_manager = None
        return CommandResult(0, stdout="exact rollback complete")


def assert_heartbeat_restored(backend: FakeBackend) -> None:
    assert backend.heartbeat == HeartbeatSnapshot(
        enabled=True,
        every="30m",
        target="main",
        activeHours=None,
    )
    restore_index = len(backend.events) - 1 - backend.events[::-1].index(
        "heartbeat:restore"
    )
    assert backend.events[restore_index + 1] == "read_heartbeat"


def test_guarded_probe_passes_only_after_deploy_sync_and_rollback() -> None:
    backend = FakeBackend()
    evidence = execute_guarded_probe(request(), backend)

    assert evidence.result == "PASS"
    assert evidence.model_calls == 0
    assert evidence.rollback_verified is True
    assert evidence.staged_tree_sha256 == evidence.manager_remote_tree_sha256
    assert evidence.staged_tree_sha256 == evidence.worker_remote_tree_sha256
    assert evidence.staged_tree_sha256 == evidence.worker_local_tree_sha256
    assert evidence.registry_before_sha256 == evidence.registry_restored_sha256
    assert evidence.heartbeat_before_sha256 == evidence.heartbeat_restored_sha256
    assert evidence.routes_sha256 == evidence.routes_after_sha256
    assert evidence.active_task_count_before == evidence.active_task_count_after == 0
    assert evidence.usage_before == evidence.usage_after == backend.usage
    assert backend.remote_manager is backend.remote_worker is backend.local is None
    assert backend.registry_value["workers"][APPROVED_WORKER]["skills"] is None
    assert_heartbeat_restored(backend)


@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("access_denied", "official_command_rejected"),
        ("zero_bytes", "official_command_rejected"),
        ("missing_remote", "remote_missing"),
        ("partial_upload", "package_allowlist_mismatch"),
        ("unexpected_object", "package_allowlist_mismatch"),
        ("hash_mismatch", "package_hash_mismatch"),
        ("registry_extra_change", "registry_assignment_mismatch"),
        ("sync_failure", "official_command_rejected"),
        ("local_hash_mismatch", "package_hash_mismatch"),
        ("usage_changed_after_add", "usage_changed"),
        ("route_changed_after_add", "route_mismatch"),
    ],
)
def test_faults_fail_closed_and_restore_state(fault: str, expected_code: str) -> None:
    backend = FakeBackend(fault)
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == expected_code
    assert "rollback" in backend.events
    assert backend.remote_manager is backend.remote_worker is backend.local is None
    assert backend.registry_value["workers"][APPROVED_WORKER]["skills"] is None
    assert_heartbeat_restored(backend)


def test_false_success_error_redacts_all_credential_values() -> None:
    backend = FakeBackend("access_denied")
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    message = str(captured.value)
    assert "plain-secret" not in message
    assert "bearer-secret" not in message
    assert "<redacted>" in message


@pytest.mark.parametrize("fault", ["rollback_command_failure", "rollback_incomplete"])
def test_cleanup_failure_is_reported_as_rollback_failure(fault: str) -> None:
    backend = FakeBackend(fault)
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == "rollback_failed"
    assert "rollback-secret" not in str(captured.value)
    assert_heartbeat_restored(backend)


@pytest.mark.parametrize("fault", ["preexisting_remote", "preexisting_local"])
def test_preexisting_target_stops_before_heartbeat_or_mutation(fault: str) -> None:
    backend = FakeBackend(fault)
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == "preexisting_target"
    assert "heartbeat:disable" not in backend.events
    assert "official_add" not in backend.events
    assert "rollback" not in backend.events


def test_wrong_mapping_and_changed_vendor_script_stop_before_backend_access() -> None:
    backend = FakeBackend()
    with pytest.raises(DeploymentGuardError, match="mapping_not_approved"):
        execute_guarded_probe(
            request(
                worker_name="cs-security-scanner",
                skill_name="codesentinel-security-review",
            ),
            backend,
        )
    assert backend.events == []

    with pytest.raises(DeploymentGuardError, match="official_script_changed"):
        execute_guarded_probe(request(script_sha256="0" * 64), backend)
    assert backend.events == []


def test_stale_staged_binding_stops_before_heartbeat() -> None:
    backend = FakeBackend()
    backend.staged = PackageManifest.from_mapping(
        worker_name=APPROVED_WORKER,
        skill_name=APPROVED_SKILL,
        deployment=deployment_binding("d" * 40),
        files=package_files(),
    )
    with pytest.raises(DeploymentGuardError, match="source_binding_mismatch"):
        execute_guarded_probe(request(), backend)
    assert "heartbeat:disable" not in backend.events


@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("heartbeat_disable_failure", "official_command_rejected"),
        ("heartbeat_job_remains", "heartbeat_not_disabled"),
        ("usage_drift_in_quiet_window", "usage_not_quiescent"),
        ("heartbeat_restore_failure", "heartbeat_restore_failed"),
        ("heartbeat_restore_runtime_missing", "heartbeat_restore_failed"),
    ],
)
def test_heartbeat_failures_are_fail_closed(fault: str, expected_code: str) -> None:
    backend = FakeBackend(fault)
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)
    assert captured.value.code == expected_code
    assert "official_add" not in backend.events or fault in {
        "heartbeat_restore_failure",
        "heartbeat_restore_runtime_missing",
    }


def test_registry_semantics_ignore_only_managed_timestamps() -> None:
    before = registry(timestamp="before")
    timestamp_only = registry(timestamp="after")
    assert registry_semantic_sha256(before) == registry_semantic_sha256(timestamp_only)
    validate_registry_restored(before, timestamp_only)

    assignment_changed = registry([], timestamp="after")
    with pytest.raises(DeploymentGuardError, match="registry_restore_mismatch"):
        validate_registry_restored(before, assignment_changed)


def test_redaction_covers_assignment_bearer_and_known_token_shapes() -> None:
    value = (
        "api_key=alpha secret-key:bravo access_key='charlie' "
        "Authorization: Bearer delta token=echo HICLAW_FS_SECRET_KEY=foxtrot "
        "HICLAW_MANAGER_GATEWAY_KEY=golf password=hotel "
        "gho_123456789 sk-abcdefghijk"
    )
    redacted = redact_sensitive_text(value)
    for secret in (
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "golf",
        "hotel",
        "gho_123456789",
        "sk-abcdefghijk",
    ):
        assert secret not in redacted


def test_persisted_command_output_is_redacted_and_bounded() -> None:
    evidence = command_evidence(
        CommandResult(
            0,
            stdout="HICLAW_FS_SECRET_KEY=secret " + "x" * 20_000,
            stderr="Authorization: Bearer another-secret",
        )
    )
    assert "secret" not in evidence.stdout
    assert "another-secret" not in evidence.stderr
    assert evidence.stdout.endswith("<truncated>")
    assert len(evidence.stdout) <= MAX_COMMAND_OUTPUT_CHARS + len("\n<truncated>")


def test_failure_marker_after_persisted_output_limit_is_still_rejected() -> None:
    result = CommandResult(
        0,
        stdout="x" * (MAX_COMMAND_OUTPUT_CHARS + 100) + " Access Denied",
    )
    with pytest.raises(DeploymentGuardError, match="official_command_rejected"):
        validate_command_result(
            result,
            operation="official Skill add",
            reject_zero_bytes=True,
        )


def test_backend_exception_is_redacted_after_verified_rollback() -> None:
    backend = FakeBackend("backend_exception_after_add")
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == "backend_failure"
    assert "backend-secret" not in str(captured.value)
    assert "<redacted>" in str(captured.value)
    assert "rollback" in backend.events
    assert_heartbeat_restored(backend)


def test_usage_drift_after_heartbeat_restore_blocks_pass_evidence() -> None:
    backend = FakeBackend("usage_changed_after_heartbeat_restore")
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == "usage_changed"
    assert backend.remote_manager is backend.remote_worker is backend.local is None
    assert_heartbeat_restored(backend)


@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("active_task_after_restore", "active_task_changed"),
        ("route_changed_after_restore", "route_mismatch"),
    ],
)
def test_final_environment_drift_blocks_pass_evidence(
    fault: str,
    expected_code: str,
) -> None:
    backend = FakeBackend(fault)
    with pytest.raises(DeploymentGuardError) as captured:
        execute_guarded_probe(request(), backend)

    assert captured.value.code == expected_code
    assert backend.remote_manager is backend.remote_worker is backend.local is None
    assert_heartbeat_restored(backend)


def test_package_model_rejects_unsafe_duplicate_or_wrong_tree() -> None:
    files = package_files()
    with pytest.raises(ValidationError, match="relative POSIX"):
        PackageManifest.from_mapping(
            worker_name=APPROVED_WORKER,
            skill_name=APPROVED_SKILL,
            deployment=deployment_binding(),
            files={"../SKILL.md": "0" * 64},
        )

    manifest = package_manifest(files)
    value = manifest.model_dump(mode="json")
    value["files"] = (value["files"][0], value["files"][0])
    with pytest.raises(ValidationError, match="unique and sorted"):
        PackageManifest.model_validate(value)

    value = manifest.model_dump(mode="json")
    value["files"] = tuple(value["files"])
    value["tree_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="tree_sha256"):
        PackageManifest.model_validate(value)


def test_directory_inspection_requires_materialized_exact_package(tmp_path: Path) -> None:
    for relative in EXPECTED_PACKAGE_FILES:
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "deployment-manifest.json":
            path.write_text(
                json.dumps(deployment_binding().model_dump(mode="json")),
                encoding="utf-8",
                newline="\n",
            )
        else:
            path.write_text(f"content:{relative}\n", encoding="utf-8", newline="\n")

    manifest = build_package_manifest_from_directory(tmp_path)
    assert set(manifest.digest_map()) == EXPECTED_PACKAGE_FILES

    (tmp_path / "deployment-manifest.json").unlink()
    with pytest.raises(DeploymentGuardError, match="package_binding_invalid"):
        build_package_manifest_from_directory(tmp_path)


def test_offline_entry_point_has_no_live_execution_action(tmp_path: Path) -> None:
    self_check = subprocess.run(
        [sys.executable, str(ENTRY_POINT), "self-check"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    payload = json.loads(self_check.stdout)
    assert payload["ok"] is True
    assert payload["model_calls"] == 0
    assert payload["live_execution_available"] is False
    assert payload["approved_mapping"] == {
        "skill": APPROVED_SKILL,
        "worker": APPROVED_WORKER,
    }

    rejected = subprocess.run(
        [sys.executable, str(ENTRY_POINT), "execute", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert rejected.returncode != 0
    assert "invalid choice" in rejected.stderr
