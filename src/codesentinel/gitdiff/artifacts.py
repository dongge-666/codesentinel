"""Artifact Store and append-only JSONL trace foundation for P5."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import ArtifactBoundaryError
from .models import GitDiffArtifact, TraceEvent, utc_now

_SAFE_REVIEW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass(frozen=True)
class PersistedRun:
    """Resolved paths and hashes for one local P5 run."""

    run_directory: Path
    diff_artifact_path: Path
    trace_path: Path
    manifest_path: Path
    diff_artifact_hash: str
    trace_hash: str


class ArtifactStore:
    """Write review artifacts below CodeSentinel's own workspace only."""

    def __init__(self, workspace_root: str | Path) -> None:
        try:
            root = Path(workspace_root).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ArtifactBoundaryError("workspace root does not exist") from exc
        if not root.is_dir():
            raise ArtifactBoundaryError("workspace root must be a directory")
        self._workspace_root = root
        self._runs_root = root / "artifacts" / "runs"

    @property
    def runs_root(self) -> Path:
        return self._runs_root

    @staticmethod
    def _is_relative_to(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
        except ValueError:
            return False
        return True

    def _validate_boundary(
        self,
        artifact: GitDiffArtifact,
        target_repository: Path,
    ) -> Path:
        if _SAFE_REVIEW_ID.fullmatch(artifact.review_id) is None:
            raise ArtifactBoundaryError("review_id is unsafe for an artifact directory")
        try:
            target = target_repository.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ArtifactBoundaryError("target repository cannot be resolved") from exc
        target_fingerprint = hashlib.sha256(
            os.path.normcase(str(target)).encode("utf-8")
        ).hexdigest()
        if target_fingerprint != artifact.repository_fingerprint:
            raise ArtifactBoundaryError(
                "target repository does not match the diff artifact fingerprint"
            )
        planned_run = self._runs_root / artifact.review_id
        for directory in (self._workspace_root / "artifacts", self._runs_root):
            if directory.exists() and directory.is_symlink():
                raise ArtifactBoundaryError("artifact directories must not be symlinks")
            resolved = directory.resolve(strict=False)
            if not self._is_relative_to(resolved, self._workspace_root):
                raise ArtifactBoundaryError("artifact directory escaped the workspace")
        resolved_plan = planned_run.resolve(strict=False)
        if self._is_relative_to(resolved_plan, target):
            raise ArtifactBoundaryError(
                "artifact output would modify the reviewed target repository"
            )
        if planned_run.exists() and planned_run.is_symlink():
            raise ArtifactBoundaryError("artifact run directory must not be a symlink")
        if planned_run.exists():
            raise ArtifactBoundaryError("review artifact directory already exists")
        return planned_run

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                separators=(",", ": "),
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _trace_bytes(events: tuple[TraceEvent, ...]) -> bytes:
        return (
            "".join(
                json.dumps(
                    event.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
                for event in events
            )
        ).encode("utf-8")

    def persist(
        self,
        artifact: GitDiffArtifact,
        *,
        target_repository: str | Path,
    ) -> PersistedRun:
        """Persist a complete artifact and three auditable lifecycle events."""

        target = Path(target_repository)
        run_directory = self._validate_boundary(artifact, target)
        (self._workspace_root / "artifacts").mkdir(exist_ok=True)
        self._runs_root.mkdir(exist_ok=True)
        if self._runs_root.is_symlink():
            raise ArtifactBoundaryError("artifacts/runs must not be a symlink")
        run_directory.mkdir(exist_ok=False)
        resolved_run = run_directory.resolve(strict=True)
        if not self._is_relative_to(resolved_run, self._workspace_root):
            raise ArtifactBoundaryError("artifact directory escaped the workspace")

        artifact_path = resolved_run / "git-diff.json"
        trace_path = resolved_run / "trace.jsonl"
        manifest_path = resolved_run / "manifest.json"
        artifact_bytes = self._json_bytes(artifact.model_dump(mode="json"))
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        now = utc_now()
        events = (
            TraceEvent(
                event_id=f"{artifact.review_id}-event-001",
                review_id=artifact.review_id,
                sequence=1,
                event_type="review_created",
                status="success",
                occurred_at=artifact.created_at,
                details={
                    "source": artifact.source.value,
                    "base_oid": artifact.base_oid,
                    "target_oid": artifact.target_oid,
                },
            ),
            TraceEvent(
                event_id=f"{artifact.review_id}-event-002",
                review_id=artifact.review_id,
                sequence=2,
                event_type="diff_parsed",
                status="success",
                occurred_at=artifact.created_at,
                details={
                    "diff_hash": artifact.diff_hash,
                    "files": len(artifact.files),
                    "changed_lines": artifact.changed_lines,
                    "exceeds_changed_line_limit": artifact.exceeds_changed_line_limit,
                    "cloud_safe": artifact.cloud_safe,
                },
            ),
            TraceEvent(
                event_id=f"{artifact.review_id}-event-003",
                review_id=artifact.review_id,
                sequence=3,
                event_type="artifact_persisted",
                status="success",
                occurred_at=now,
                details={
                    "artifact": "git-diff.json",
                    "artifact_sha256": artifact_hash,
                    "trace": "trace.jsonl",
                },
            ),
        )
        trace_bytes = self._trace_bytes(events)
        trace_hash = hashlib.sha256(trace_bytes).hexdigest()
        manifest = {
            "schema_version": "1.0.0",
            "review_id": artifact.review_id,
            "cloud_safe": False,
            "files": {
                "git-diff.json": artifact_hash,
                "trace.jsonl": trace_hash,
            },
        }

        self._atomic_write(artifact_path, artifact_bytes)
        self._atomic_write(trace_path, trace_bytes)
        self._atomic_write(manifest_path, self._json_bytes(manifest))
        return PersistedRun(
            run_directory=resolved_run,
            diff_artifact_path=artifact_path,
            trace_path=trace_path,
            manifest_path=manifest_path,
            diff_artifact_hash=artifact_hash,
            trace_hash=trace_hash,
        )
