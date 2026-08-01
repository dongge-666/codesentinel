"""Atomic, target-repository-safe P9 review artifact persistence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from codesentinel.agents import ModelCallRecord
from codesentinel.assurance import EvidenceValidationReport, RiskRoutingResult
from codesentinel.domain import AgentArtifact, DiffAnalysis
from codesentinel.gitdiff import GitDiffArtifact
from codesentinel.skills.security import SanitizedDiffView

from .models import ReviewReport, ReviewTraceEvent

_SAFE_REVIEW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ReviewArtifactError(RuntimeError):
    """The final P9 artifact set could not be persisted safely."""


@dataclass(frozen=True, slots=True)
class ReviewArtifactPayload:
    git_diff: GitDiffArtifact
    sanitized_diff: SanitizedDiffView
    diff_analysis: DiffAnalysis
    routing: RiskRoutingResult
    security_review: AgentArtifact
    quality_review: AgentArtifact
    evidence_validation: EvidenceValidationReport
    report: ReviewReport
    model_calls: tuple[ModelCallRecord, ...]
    trace: tuple[ReviewTraceEvent, ...]


@dataclass(frozen=True, slots=True)
class PersistedReview:
    run_directory: Path
    report_path: Path
    decision_path: Path
    trace_path: Path
    manifest_path: Path
    file_hashes: dict[str, str]


class ReviewArtifactStore:
    """Persist a complete run outside the reviewed target, or persist nothing."""

    def __init__(self, workspace_root: str | Path) -> None:
        try:
            root = Path(workspace_root).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ReviewArtifactError("artifact workspace does not exist") from exc
        if not root.is_dir():
            raise ReviewArtifactError("artifact workspace must be a directory")
        self._workspace_root = root
        self._runs_root = root / "artifacts" / "runs"

    def preflight(
        self,
        review_id: str,
        *,
        target_repository: str | Path,
    ) -> None:
        """Reject unsafe output boundaries before any model call is attempted."""

        if _SAFE_REVIEW_ID.fullmatch(review_id) is None:
            raise ReviewArtifactError("review_id is unsafe for artifact paths")
        try:
            target = Path(target_repository).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ReviewArtifactError("reviewed repository cannot be resolved") from exc
        planned = (self._runs_root / review_id).resolve(strict=False)
        if self._is_relative_to(planned, target):
            raise ReviewArtifactError("artifact output would modify the reviewed repository")
        if planned.exists():
            raise ReviewArtifactError("review artifact directory already exists")
        for path in (self._workspace_root / "artifacts", self._runs_root):
            if path.exists() and path.is_symlink():
                raise ReviewArtifactError("artifact directories must not be symlinks")
            if not self._is_relative_to(path.resolve(strict=False), self._workspace_root):
                raise ReviewArtifactError("artifact directory escaped the workspace")

    def persist(
        self,
        payload: ReviewArtifactPayload,
        *,
        target_repository: str | Path,
    ) -> PersistedReview:
        self._validate_boundary(payload, Path(target_repository))
        final_directory = self._runs_root / payload.report.review_id
        temporary = self._runs_root / f".{payload.report.review_id}.{uuid.uuid4().hex}.tmp"
        self._runs_root.mkdir(parents=True, exist_ok=True)
        if self._runs_root.is_symlink():
            raise ReviewArtifactError("artifact runs directory must not be a symlink")
        try:
            temporary.mkdir(exist_ok=False)
            files = self._build_files(payload)
            hashes: dict[str, str] = {}
            for name, content in files.items():
                path = temporary / name
                self._write_private(path, content)
                hashes[name] = hashlib.sha256(content).hexdigest()
            manifest = self._json_bytes(
                {
                    "schema_version": "1.0.0",
                    "review_id": payload.report.review_id,
                    "trace_id": payload.report.trace_id,
                    "status": payload.report.status.value,
                    "cloud_safe": payload.sanitized_diff.cloud_safe,
                    "files": hashes,
                }
            )
            self._write_private(temporary / "manifest.json", manifest)
            temporary.rename(final_directory)
        except Exception as exc:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            if isinstance(exc, ReviewArtifactError):
                raise
            raise ReviewArtifactError("complete review artifacts could not be written") from exc
        return PersistedReview(
            run_directory=final_directory,
            report_path=final_directory / "report.md",
            decision_path=final_directory / "gate-decision.json",
            trace_path=final_directory / "trace.jsonl",
            manifest_path=final_directory / "manifest.json",
            file_hashes=hashes,
        )

    def _validate_boundary(
        self,
        payload: ReviewArtifactPayload,
        target_repository: Path,
    ) -> Path:
        review_id = payload.report.review_id
        self.preflight(review_id, target_repository=target_repository)
        try:
            target = target_repository.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ReviewArtifactError("reviewed repository cannot be resolved") from exc
        expected_fingerprint = hashlib.sha256(
            os.path.normcase(str(target)).encode("utf-8")
        ).hexdigest()
        if expected_fingerprint != payload.git_diff.repository_fingerprint:
            raise ReviewArtifactError("reviewed repository does not match the Git artifact")
        return target

    def _build_files(self, payload: ReviewArtifactPayload) -> dict[str, bytes]:
        input_summary = {
            "schema_version": "1.0.0",
            "review_id": payload.git_diff.review_id,
            "repository_name": payload.git_diff.repository_name,
            "repository_fingerprint": payload.git_diff.repository_fingerprint,
            "source": payload.git_diff.source.value,
            "base_revision": payload.git_diff.base_revision,
            "base_oid": payload.git_diff.base_oid,
            "target_revision": payload.git_diff.target_revision,
            "target_oid": payload.git_diff.target_oid,
            "diff_hash": payload.git_diff.diff_hash,
            "files": [
                item.change.model_dump(mode="json") for item in payload.git_diff.files
            ],
            "changed_lines": payload.git_diff.changed_lines,
            "raw_diff_bytes": payload.git_diff.raw_diff_bytes,
            "exceeds_changed_line_limit": payload.git_diff.exceeds_changed_line_limit,
        }
        return {
            "input-summary.json": self._json_bytes(input_summary),
            "sanitized-diff.json": self._json_bytes(
                payload.sanitized_diff.model_dump(mode="json")
            ),
            "diff-analysis.json": self._json_bytes(
                payload.diff_analysis.model_dump(mode="json")
            ),
            "risk-routing.json": self._json_bytes(
                payload.routing.model_dump(mode="json")
            ),
            "security-review.json": self._json_bytes(
                payload.security_review.model_dump(mode="json")
            ),
            "quality-review.json": self._json_bytes(
                payload.quality_review.model_dump(mode="json")
            ),
            "evidence-validation.json": self._json_bytes(
                payload.evidence_validation.model_dump(mode="json")
            ),
            "gate-decision.json": self._json_bytes(
                payload.report.decision.model_dump(mode="json")
            ),
            "model-calls.json": self._json_bytes(
                [item.model_dump(mode="json") for item in payload.model_calls]
            ),
            "review.json": self._json_bytes(payload.report.model_dump(mode="json")),
            "trace.jsonl": self._trace_bytes(payload.trace),
            "report.md": self._markdown_bytes(payload),
        }

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @staticmethod
    def _trace_bytes(events: tuple[ReviewTraceEvent, ...]) -> bytes:
        return "".join(
            json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for event in events
        ).encode("utf-8")

    @staticmethod
    def _markdown_bytes(payload: ReviewArtifactPayload) -> bytes:
        decision = payload.report.decision
        findings = (
            *payload.security_review.findings,
            *payload.quality_review.findings,
        )
        lines = [
            "# CodeSentinel review",
            "",
            "> Generated by the P9 single-process reference runner; this is not an "
            "AgentTeams business trace.",
            "",
            f"- Review: `{_md(payload.report.review_id)}`",
            f"- Decision: **{decision.status.value}**",
            f"- Policy: `{_md(decision.policy_version)}`",
            f"- Rules: `{_md(', '.join(decision.matched_rule_ids))}`",
            f"- Coverage complete: `{str(decision.coverage_complete).lower()}`",
            f"- Recheck attempts: `{payload.report.recheck_attempts}`",
            "",
            "## Decision",
            "",
            _md(decision.reason_summary),
            "",
            "## Findings",
            "",
        ]
        if findings:
            lines.extend(
                [
                    "| Severity | Status | Category | Location | Title |",
                    "|---|---|---|---|---|",
                ]
            )
            for finding in sorted(findings, key=lambda item: item.finding_id):
                location = finding.locations[0] if finding.locations else None
                location_text = (
                    f"{location.file_path}:{location.start_line}" if location else "system"
                )
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            _md(finding.severity.value),
                            _md(finding.status.value),
                            _md(finding.category.value),
                            _md(location_text),
                            _md(finding.title),
                        )
                    )
                    + " |"
                )
        else:
            lines.append("No active findings were emitted.")
        lines.extend(["", "## Manual actions", ""])
        lines.extend(
            f"- {_md(item)}" for item in decision.manual_actions
        )
        if not decision.manual_actions:
            lines.append("No manual action is required by the current policy.")
        lines.extend(["", "## Execution errors", ""])
        if payload.report.errors:
            lines.extend(
                f"- `{_md(item.error_code)}` at `{_md(item.stage.value)}`: "
                f"{_md(item.message)}"
                for item in payload.report.errors
            )
        else:
            lines.append("No execution error was recorded.")
        lines.extend(
            [
                "",
                "## Metrics",
                "",
                f"- Duration: `{payload.report.metrics.duration_ms} ms`",
                f"- Model calls: `{payload.report.metrics.model_calls}/4`",
                f"- Total tokens: `{payload.report.metrics.total_tokens}`",
                f"- Estimated cost: `${payload.report.metrics.estimated_cost_usd:.8f}`",
                "",
            ]
        )
        return ("\n".join(lines) + "\n").encode("utf-8")

    @staticmethod
    def _write_private(path: Path, content: bytes) -> None:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _is_relative_to(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
        except ValueError:
            return False
        return True


def _md(value: object) -> str:
    text = " ".join(str(value).replace("\x00", "").split())[:500]
    for character in ("\\", "|", "<", ">", "`", "[", "]"):
        text = text.replace(character, f"\\{character}")
    return text
