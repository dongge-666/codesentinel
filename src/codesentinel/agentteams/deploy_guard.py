"""Fail-closed, zero-model guard for one AgentTeams Skill transaction.

The module contains no Docker, MinIO, Matrix, or HTTP implementation.  Live
operations are represented by an injected backend so the state machine and
all rollback paths can be exercised offline before a separately approved live
adapter is allowed to exist.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .serialization import canonical_json_bytes, sha256_hex
from .validation import read_json_object

GUARD_SCHEMA_VERSION = "1.0.0"
APPROVED_WORKER = "cs-diff-analyzer"
APPROVED_SKILL = "codesentinel-diff-review"
EXPECTED_OFFICIAL_SCRIPT_SHA256 = (
    "71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c"
)
EXPECTED_ROUTE = "hiclaw-gateway/deepseek-v4-pro"
QUIET_WINDOW_SECONDS = 130
MAX_COMMAND_OUTPUT_CHARS = 16_000

EXPECTED_PACKAGE_FILES = frozenset(
    {
        "SKILL.md",
        "deployment-manifest.json",
        "deployment-manifest.template.json",
        "references/example-payload.json",
        "references/input-contract.md",
        "references/payload.schema.json",
        "scripts/build-delivery.sh",
        "scripts/verify-runtime-binding.py",
        "skill-manifest.json",
    }
)

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitRevision = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
SafeName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    ),
]

_REJECTED_COMMAND_OUTPUT = re.compile(
    r"access\s*denied|insufficient\s+permissions|unable\s+to\s+(?:list|stat)|"
    r"object\s+does\s+not\s+exist|\bpermission\s+denied\b|"
    r"authorization\s+failed|invalid\s+access\s+key|signature\s+does\s+not\s+match",
    re.IGNORECASE,
)
_ZERO_BYTES = re.compile(r"(?:^|\s)0\s+B(?:\s|$)", re.IGNORECASE)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[a-z0-9]+[_-])*(?:api[_-]?key|secret[_-]?key|"
    r"access[_-]?key|gateway[_-]?key|token|password)|authorization)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+")
_KNOWN_TOKEN = re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9_-]{8,})\b")


class GuardModel(BaseModel):
    """Strict immutable base for R2 guard evidence."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class DeploymentGuardError(RuntimeError):
    """A guarded deployment step could not be proven safe."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class FileDigest(GuardModel):
    path: str
    sha256: Sha256Digest

    @field_validator("path")
    @classmethod
    def path_must_be_relative_posix(cls, value: str) -> str:
        windows = PureWindowsPath(value)
        posix = PurePosixPath(value)
        if (
            not value
            or "\\" in value
            or "\x00" in value
            or value.startswith("/")
            or ":" in value
            or windows.is_absolute()
            or bool(windows.drive)
            or posix.as_posix() != value
            or any(part in {"", ".", ".."} for part in posix.parts)
        ):
            raise ValueError("package path must be a safe relative POSIX path")
        return value


class DeploymentBinding(GuardModel):
    schema_name: Literal["CodeSentinelWorkerSkillDeployment"]
    schema_version: Literal["1.0.0"]
    skill_name: Literal[APPROVED_SKILL]
    skill_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    source_revision: GitRevision
    source_dirty: Literal[False]
    runtime_bundle_ref: str
    runtime_bundle_sha256: Sha256Digest

    @field_validator("runtime_bundle_ref")
    @classmethod
    def runtime_ref_must_be_safe(cls, value: str) -> str:
        windows = PureWindowsPath(value)
        path = PurePosixPath(value)
        if (
            "\\" in value
            or "\x00" in value
            or value.startswith("/")
            or ":" in value
            or windows.is_absolute()
            or bool(windows.drive)
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
            or not value.startswith("shared/projects/codesentinel/runtime/")
            or not value.endswith(".pyz")
        ):
            raise ValueError("runtime bundle ref must be a safe CodeSentinel path")
        return value

    @model_validator(mode="after")
    def runtime_ref_must_bind_revision(self) -> DeploymentBinding:
        if f"/{self.source_revision}/" not in self.runtime_bundle_ref:
            raise ValueError("runtime bundle ref does not contain source_revision")
        return self


def package_tree_sha256(files: tuple[FileDigest, ...]) -> str:
    """Hash a canonical, UTF-8 list of POSIX paths and file digests."""

    return sha256_hex(
        canonical_json_bytes(
            {
                "algorithm": "codesentinel-posix-sha256-v1",
                "files": [item.model_dump(mode="json") for item in files],
            }
        )
    )


class PackageManifest(GuardModel):
    schema_name: Literal["CodeSentinelR2PackageManifest"] = (
        "CodeSentinelR2PackageManifest"
    )
    schema_version: Literal[GUARD_SCHEMA_VERSION] = GUARD_SCHEMA_VERSION
    worker_name: SafeName
    skill_name: SafeName
    deployment: DeploymentBinding
    files: tuple[FileDigest, ...] = Field(min_length=1, max_length=64)
    tree_sha256: Sha256Digest

    @model_validator(mode="after")
    def files_must_be_canonical(self) -> PackageManifest:
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("package files must be unique and sorted by POSIX path")
        if package_tree_sha256(self.files) != self.tree_sha256:
            raise ValueError("package tree_sha256 does not match files")
        return self

    @classmethod
    def from_mapping(
        cls,
        *,
        worker_name: str,
        skill_name: str,
        deployment: DeploymentBinding,
        files: Mapping[str, str],
    ) -> PackageManifest:
        entries = tuple(
            FileDigest(path=path, sha256=digest)
            for path, digest in sorted(files.items())
        )
        return cls(
            worker_name=worker_name,
            skill_name=skill_name,
            deployment=deployment,
            files=entries,
            tree_sha256=package_tree_sha256(entries),
        )

    def digest_map(self) -> dict[str, str]:
        return {item.path: item.sha256 for item in self.files}


class UsageSnapshot(GuardModel):
    manager_calls: int = Field(ge=0)
    diff_calls: int = Field(ge=0)
    security_calls: int = Field(ge=0)
    quality_calls: int = Field(ge=0)


class RouteSnapshot(GuardModel):
    manager: str
    diff: str
    security: str
    quality: str


class HeartbeatSnapshot(GuardModel):
    enabled: bool
    every: str = Field(min_length=2, max_length=64)
    target: str = Field(min_length=1, max_length=64)
    active_hours: dict[str, str] | None = Field(default=None, alias="activeHours")


class QuietSample(GuardModel):
    elapsed_seconds: int = Field(ge=0)
    usage: UsageSnapshot


class QuietWindow(GuardModel):
    samples: tuple[QuietSample, QuietSample, QuietSample]

    @model_validator(mode="after")
    def samples_must_prove_quiescence(self) -> QuietWindow:
        elapsed = tuple(item.elapsed_seconds for item in self.samples)
        if elapsed[0] != 0 or elapsed[1] < 65 or elapsed[2] < QUIET_WINDOW_SECONDS:
            raise ValueError("quiet window must contain 0s, 65s, and 130s samples")
        if len({item.usage for item in self.samples}) != 1:
            raise ValueError("usage changed during the Manager quiet window")
        return self


class GuardRequest(GuardModel):
    schema_name: Literal["CodeSentinelR2GuardRequest"] = "CodeSentinelR2GuardRequest"
    schema_version: Literal[GUARD_SCHEMA_VERSION] = GUARD_SCHEMA_VERSION
    worker_name: SafeName
    skill_name: SafeName
    source_revision: GitRevision
    source_dirty: Literal[False]
    official_script_sha256: Sha256Digest


class CommandEvidence(GuardModel):
    returncode: int
    stdout: str
    stderr: str


class DeploymentGuardEvidence(GuardModel):
    schema_name: Literal["CodeSentinelR2DeploymentGuardEvidence"] = (
        "CodeSentinelR2DeploymentGuardEvidence"
    )
    schema_version: Literal[GUARD_SCHEMA_VERSION] = GUARD_SCHEMA_VERSION
    result: Literal["PASS"] = "PASS"
    worker_name: Literal[APPROVED_WORKER]
    skill_name: Literal[APPROVED_SKILL]
    source_revision: GitRevision
    official_script_sha256: Literal[EXPECTED_OFFICIAL_SCRIPT_SHA256]
    staged_tree_sha256: Sha256Digest
    manager_remote_tree_sha256: Sha256Digest
    worker_remote_tree_sha256: Sha256Digest
    worker_local_tree_sha256: Sha256Digest
    registry_before_sha256: Sha256Digest
    registry_restored_sha256: Sha256Digest
    heartbeat_before_sha256: Sha256Digest
    heartbeat_restored_sha256: Sha256Digest
    routes_sha256: Sha256Digest
    routes_after_sha256: Sha256Digest
    active_task_count_before: Literal[0] = 0
    active_task_count_after: Literal[0] = 0
    usage_before: UsageSnapshot
    usage_after: UsageSnapshot
    quiet_window: QuietWindow
    official_add: CommandEvidence
    worker_sync: CommandEvidence
    rollback: CommandEvidence
    rollback_verified: Literal[True] = True
    model_calls: Literal[0] = 0


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class DeploymentBackend(Protocol):
    """Side-effect boundary injected only by a separately approved live slice."""

    def read_staged_package(self) -> PackageManifest: ...

    def read_remote_package(
        self, identity: Literal["manager", "worker"]
    ) -> PackageManifest | None: ...

    def read_local_package(self) -> PackageManifest | None: ...

    def read_registry(self) -> dict[str, Any]: ...

    def read_active_task_count(self) -> int: ...

    def read_routes(self) -> RouteSnapshot: ...

    def read_usage(self) -> UsageSnapshot: ...

    def read_heartbeat(self) -> HeartbeatSnapshot: ...

    def write_heartbeat(self, value: HeartbeatSnapshot) -> CommandResult: ...

    def heartbeat_job_removed(self) -> bool: ...

    def heartbeat_runtime_matches(self, value: HeartbeatSnapshot) -> bool: ...

    def measure_quiet_window(self) -> QuietWindow: ...

    def invoke_official_add(self, worker_name: str, skill_name: str) -> CommandResult: ...

    def sync_worker(self, worker_name: str) -> CommandResult: ...

    def rollback(
        self,
        worker_name: str,
        skill_name: str,
        registry_preimage: dict[str, Any],
    ) -> CommandResult: ...


def redact_sensitive_text(value: str) -> str:
    """Redact credential-shaped command output before persistence or errors."""

    redacted = _BEARER.sub(lambda match: f"{match.group(1)}<redacted>", value)
    redacted = _CREDENTIAL_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", redacted
    )
    return _KNOWN_TOKEN.sub("<redacted-token>", redacted)


def command_evidence(result: CommandResult) -> CommandEvidence:
    def bounded(value: str) -> str:
        redacted = redact_sensitive_text(value)
        if len(redacted) <= MAX_COMMAND_OUTPUT_CHARS:
            return redacted
        return f"{redacted[:MAX_COMMAND_OUTPUT_CHARS]}\n<truncated>"

    return CommandEvidence(
        returncode=result.returncode,
        stdout=bounded(result.stdout),
        stderr=bounded(result.stderr),
    )


def validate_command_result(
    result: CommandResult,
    *,
    operation: str,
    reject_zero_bytes: bool = False,
) -> CommandEvidence:
    evidence = command_evidence(result)
    # Inspect the complete redacted output.  Persisted evidence is bounded, but
    # truncation must never hide a failure marker near the end of vendor output.
    complete = redact_sensitive_text(f"{result.stdout}\n{result.stderr}")
    rejected_marker = _REJECTED_COMMAND_OUTPUT.search(complete)
    zero_bytes = reject_zero_bytes and _ZERO_BYTES.search(complete)
    if result.returncode != 0 or rejected_marker or zero_bytes:
        compact = " ".join(complete.split())[:1000]
        raise DeploymentGuardError(
            "official_command_rejected",
            f"{operation} was not authoritative: rc={result.returncode}; {compact}",
        )
    return evidence


def _safe_guard_error(exc: BaseException) -> DeploymentGuardError:
    """Return a redacted public error for an arbitrary backend exception."""

    if isinstance(exc, DeploymentGuardError):
        return exc
    detail = redact_sensitive_text(f"{type(exc).__name__}: {exc}")
    return DeploymentGuardError("backend_failure", detail)


def _canonical_hash(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return sha256_hex(canonical_json_bytes(value))


def _normalized_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        normalized = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise DeploymentGuardError(
            "registry_invalid", "registry is not a JSON-compatible object"
        ) from exc
    if not isinstance(normalized, dict):
        raise DeploymentGuardError("registry_invalid", "registry root is not an object")
    normalized.pop("updated_at", None)
    workers = normalized.get("workers")
    if not isinstance(workers, dict):
        raise DeploymentGuardError("registry_invalid", "registry workers are missing")
    for worker in workers.values():
        if not isinstance(worker, dict):
            raise DeploymentGuardError(
                "registry_invalid", "registry Worker entry is not an object"
            )
        worker.pop("skills_updated_at", None)
    return normalized


def registry_semantic_sha256(value: Mapping[str, Any]) -> str:
    return _canonical_hash(_normalized_registry(value))


def validate_approved_mapping(request: GuardRequest) -> None:
    if request.worker_name != APPROVED_WORKER or request.skill_name != APPROVED_SKILL:
        raise DeploymentGuardError(
            "mapping_not_approved",
            "R2-1 permits only cs-diff-analyzer -> codesentinel-diff-review",
        )
    if request.official_script_sha256 != EXPECTED_OFFICIAL_SCRIPT_SHA256:
        raise DeploymentGuardError(
            "official_script_changed", "official deployment script hash is not pinned"
        )


def validate_approved_package(manifest: PackageManifest) -> None:
    if manifest.worker_name != APPROVED_WORKER or manifest.skill_name != APPROVED_SKILL:
        raise DeploymentGuardError(
            "package_identity_mismatch", "package Worker or Skill is not approved"
        )
    if manifest.deployment.skill_name != manifest.skill_name:
        raise DeploymentGuardError(
            "package_binding_mismatch", "deployment binding names another Skill"
        )
    paths = set(manifest.digest_map())
    if paths != EXPECTED_PACKAGE_FILES:
        missing = sorted(EXPECTED_PACKAGE_FILES - paths)
        unexpected = sorted(paths - EXPECTED_PACKAGE_FILES)
        raise DeploymentGuardError(
            "package_allowlist_mismatch",
            f"package files differ; missing={missing}; unexpected={unexpected}",
        )


def validate_package_copy(
    expected: PackageManifest,
    actual: PackageManifest | None,
    *,
    location: str,
) -> None:
    if actual is None:
        raise DeploymentGuardError("remote_missing", f"{location} package is absent")
    validate_approved_package(actual)
    if actual.deployment != expected.deployment:
        raise DeploymentGuardError(
            "package_binding_mismatch", f"{location} deployment binding differs"
        )
    if actual.digest_map() != expected.digest_map():
        raise DeploymentGuardError(
            "package_hash_mismatch", f"{location} package hashes differ from staging"
        )


def _baseline_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalized_registry(value)
    worker = normalized["workers"].get(APPROVED_WORKER)
    if not isinstance(worker, dict):
        raise DeploymentGuardError("registry_invalid", "approved Worker is missing")
    skills = worker.get("skills")
    if skills not in (None, []):
        raise DeploymentGuardError(
            "preexisting_assignment", "approved Worker already has assigned Skills"
        )
    return normalized


def validate_registry_after_add(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> None:
    expected = deepcopy(_baseline_registry(before))
    expected["workers"][APPROVED_WORKER]["skills"] = [APPROVED_SKILL]
    if _normalized_registry(after) != expected:
        raise DeploymentGuardError(
            "registry_assignment_mismatch",
            "registry contains changes beyond the exact approved Skill assignment",
        )


def validate_registry_restored(
    before: Mapping[str, Any],
    restored: Mapping[str, Any],
) -> None:
    if _normalized_registry(restored) != _normalized_registry(before):
        raise DeploymentGuardError(
            "registry_restore_mismatch",
            "registry did not return to its pre-transaction semantics",
        )


def validate_routes(routes: RouteSnapshot) -> None:
    values = (routes.manager, routes.diff, routes.security, routes.quality)
    if any(value != EXPECTED_ROUTE for value in values):
        raise DeploymentGuardError(
            "route_mismatch", "all AgentTeams roles must remain on the frozen route"
        )


def build_package_manifest_from_directory(
    package_root: str | Path,
    *,
    worker_name: str = APPROVED_WORKER,
    skill_name: str = APPROVED_SKILL,
) -> PackageManifest:
    """Inspect a materialized package without following symlinks."""

    root = Path(package_root)
    if not root.is_dir() or root.is_symlink():
        raise DeploymentGuardError(
            "package_root_unsafe", "package root must be an existing real directory"
        )
    files: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise DeploymentGuardError(
                "package_symlink", "package must not contain symbolic links"
            )
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files[relative] = sha256_hex(path.read_bytes())
    try:
        deployment = DeploymentBinding.model_validate(
            read_json_object(root / "deployment-manifest.json")[0]
        )
    except Exception as exc:
        raise DeploymentGuardError(
            "package_binding_invalid",
            "deployment-manifest.json does not satisfy the frozen binding contract",
        ) from exc
    manifest = PackageManifest.from_mapping(
        worker_name=worker_name,
        skill_name=skill_name,
        deployment=deployment,
        files=files,
    )
    validate_approved_package(manifest)
    return manifest


def _verify_no_preexisting_target(backend: DeploymentBackend) -> None:
    if backend.read_remote_package("manager") is not None:
        raise DeploymentGuardError(
            "preexisting_target", "Manager-visible remote Skill already exists"
        )
    if backend.read_remote_package("worker") is not None:
        raise DeploymentGuardError(
            "preexisting_target", "Worker-visible remote Skill already exists"
        )
    if backend.read_local_package() is not None:
        raise DeploymentGuardError(
            "preexisting_target", "Worker-local Skill already exists"
        )


def _verify_environment(
    backend: DeploymentBackend,
    *,
    expected_usage: UsageSnapshot,
    expected_routes: RouteSnapshot,
) -> None:
    if backend.read_active_task_count() != 0:
        raise DeploymentGuardError("active_task_changed", "active task count is not zero")
    current_routes = backend.read_routes()
    validate_routes(current_routes)
    if current_routes != expected_routes:
        raise DeploymentGuardError("route_changed", "route snapshot changed")
    if backend.read_usage() != expected_usage:
        raise DeploymentGuardError("usage_changed", "a model usage counter changed")


def _verify_rollback(
    backend: DeploymentBackend,
    *,
    registry_before: Mapping[str, Any],
) -> None:
    if backend.read_remote_package("manager") is not None:
        raise DeploymentGuardError("rollback_failed", "Manager remote Skill remains")
    if backend.read_remote_package("worker") is not None:
        raise DeploymentGuardError("rollback_failed", "Worker remote Skill remains")
    if backend.read_local_package() is not None:
        raise DeploymentGuardError("rollback_failed", "Worker-local Skill remains")
    validate_registry_restored(registry_before, backend.read_registry())


def execute_guarded_probe(
    request: GuardRequest,
    backend: DeploymentBackend,
) -> DeploymentGuardEvidence:
    """Execute a deploy/sync/rollback proof through an injected backend.

    R2-1 exercises this function only with fake backends. A concrete backend
    must not be supplied until the later live approval gates are satisfied.
    """

    validate_approved_mapping(request)
    staged = backend.read_staged_package()
    validate_approved_package(staged)
    if staged.deployment.source_revision != request.source_revision:
        raise DeploymentGuardError(
            "source_binding_mismatch",
            "staged deployment is not bound to the accepted source revision",
        )
    _verify_no_preexisting_target(backend)
    registry_before = deepcopy(backend.read_registry())
    _baseline_registry(registry_before)
    if backend.read_active_task_count() != 0:
        raise DeploymentGuardError("active_task_present", "preflight found an active task")
    routes_before = backend.read_routes()
    validate_routes(routes_before)
    usage_before = backend.read_usage()
    heartbeat_before = backend.read_heartbeat()

    heartbeat_touched = False
    mutation_started = False
    rollback_invoked = False
    rollback_verified = False
    primary_error: BaseException | None = None
    add_evidence: CommandEvidence | None = None
    sync_evidence: CommandEvidence | None = None
    rollback_evidence: CommandEvidence | None = None
    quiet_window: QuietWindow | None = None
    manager_remote: PackageManifest | None = None
    worker_remote: PackageManifest | None = None
    worker_local: PackageManifest | None = None

    try:
        disabled = heartbeat_before.model_copy(update={"enabled": False})
        heartbeat_touched = True
        validate_command_result(
            backend.write_heartbeat(disabled),
            operation="disable heartbeat",
        )
        if backend.read_heartbeat() != disabled or not backend.heartbeat_job_removed():
            raise DeploymentGuardError(
                "heartbeat_not_disabled", "Heartbeat removal was not independently proven"
            )
        try:
            quiet_window = backend.measure_quiet_window()
        except ValueError as exc:
            raise DeploymentGuardError(
                "usage_not_quiescent", "Manager usage changed during the quiet window"
            ) from exc
        if quiet_window.samples[0].usage != usage_before:
            raise DeploymentGuardError(
                "usage_baseline_changed", "quiet window does not start at the baseline"
            )

        mutation_started = True
        add_result = backend.invoke_official_add(request.worker_name, request.skill_name)
        add_evidence = validate_command_result(
            add_result,
            operation="official Skill add",
            reject_zero_bytes=True,
        )

        manager_remote = backend.read_remote_package("manager")
        validate_package_copy(staged, manager_remote, location="Manager remote")
        worker_remote = backend.read_remote_package("worker")
        validate_package_copy(staged, worker_remote, location="Worker remote")
        validate_registry_after_add(registry_before, backend.read_registry())

        sync_evidence = validate_command_result(
            backend.sync_worker(request.worker_name),
            operation="Worker file sync",
        )
        worker_local = backend.read_local_package()
        validate_package_copy(staged, worker_local, location="Worker local")
        _verify_environment(
            backend,
            expected_usage=usage_before,
            expected_routes=routes_before,
        )

        rollback_invoked = True
        rollback_evidence = validate_command_result(
            backend.rollback(
                request.worker_name,
                request.skill_name,
                deepcopy(registry_before),
            ),
            operation="guarded rollback",
        )
        _verify_rollback(
            backend,
            registry_before=registry_before,
        )
        rollback_verified = True
        _verify_environment(
            backend,
            expected_usage=usage_before,
            expected_routes=routes_before,
        )
    except Exception as exc:
        primary_error = _safe_guard_error(exc)
        if mutation_started and not rollback_invoked:
            rollback_invoked = True
            try:
                rollback_evidence = validate_command_result(
                    backend.rollback(
                        request.worker_name,
                        request.skill_name,
                        deepcopy(registry_before),
                    ),
                    operation="guarded rollback",
                )
                _verify_rollback(
                    backend,
                    registry_before=registry_before,
                )
                rollback_verified = True
            except Exception as rollback_exc:
                primary_error = DeploymentGuardError(
                    "rollback_failed",
                    f"rollback could not be proven after {type(primary_error).__name__}: "
                    f"{redact_sensitive_text(str(rollback_exc))}",
                )
        elif mutation_started and rollback_invoked and not rollback_verified:
            primary_error = DeploymentGuardError(
                "rollback_failed",
                f"rollback could not be proven: {redact_sensitive_text(str(exc))}",
            )
    finally:
        if heartbeat_touched:
            try:
                validate_command_result(
                    backend.write_heartbeat(heartbeat_before),
                    operation="restore heartbeat",
                )
                if backend.read_heartbeat() != heartbeat_before:
                    raise DeploymentGuardError(
                        "heartbeat_restore_mismatch",
                        "Heartbeat settings differ from the pre-transaction snapshot",
                    )
                if not backend.heartbeat_runtime_matches(heartbeat_before):
                    raise DeploymentGuardError(
                        "heartbeat_restore_mismatch",
                        "Heartbeat scheduler state does not match the restored snapshot",
                    )
            except Exception as restore_exc:
                primary_error = DeploymentGuardError(
                    "heartbeat_restore_failed",
                    f"Heartbeat restoration was not proven: "
                    f"{redact_sensitive_text(str(restore_exc))}",
                )

    if primary_error is not None:
        raise primary_error
    if not all(
        (
            add_evidence,
            sync_evidence,
            rollback_evidence,
            quiet_window,
            manager_remote,
            worker_remote,
            worker_local,
            rollback_verified,
        )
    ):
        raise DeploymentGuardError(
            "incomplete_evidence", "successful transaction evidence is incomplete"
        )

    try:
        registry_restored = backend.read_registry()
        validate_registry_restored(registry_before, registry_restored)
        active_task_count_after = backend.read_active_task_count()
        if active_task_count_after != 0:
            raise DeploymentGuardError(
                "active_task_changed", "active task count changed after restoration"
            )
        routes_after = backend.read_routes()
        validate_routes(routes_after)
        if routes_after != routes_before:
            raise DeploymentGuardError("route_changed", "route snapshot changed")
        usage_after = backend.read_usage()
        if usage_after != usage_before:
            raise DeploymentGuardError(
                "usage_changed", "a model usage counter changed after restoration"
            )
        heartbeat_restored = backend.read_heartbeat()
        if heartbeat_restored != heartbeat_before:
            raise DeploymentGuardError(
                "heartbeat_restore_mismatch",
                "Heartbeat changed after restoration evidence was collected",
            )
    except Exception as exc:
        raise _safe_guard_error(exc) from None
    return DeploymentGuardEvidence(
        worker_name=APPROVED_WORKER,
        skill_name=APPROVED_SKILL,
        source_revision=request.source_revision,
        official_script_sha256=EXPECTED_OFFICIAL_SCRIPT_SHA256,
        staged_tree_sha256=staged.tree_sha256,
        manager_remote_tree_sha256=manager_remote.tree_sha256,
        worker_remote_tree_sha256=worker_remote.tree_sha256,
        worker_local_tree_sha256=worker_local.tree_sha256,
        registry_before_sha256=registry_semantic_sha256(registry_before),
        registry_restored_sha256=registry_semantic_sha256(registry_restored),
        heartbeat_before_sha256=_canonical_hash(heartbeat_before),
        heartbeat_restored_sha256=_canonical_hash(heartbeat_restored),
        routes_sha256=_canonical_hash(routes_before),
        routes_after_sha256=_canonical_hash(routes_after),
        active_task_count_after=active_task_count_after,
        usage_before=usage_before,
        usage_after=usage_after,
        quiet_window=quiet_window,
        official_add=add_evidence,
        worker_sync=sync_evidence,
        rollback=rollback_evidence,
    )
