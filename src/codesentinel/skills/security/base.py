"""Fail-closed execution shell for deterministic security Skills."""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError

from codesentinel.domain import (
    CoverageRecord,
    CoverageStatus,
    Evidence,
    EvidenceLevel,
    EvidenceSource,
    Finding,
    SkillStatus,
)
from codesentinel.gitdiff import GitDiffArtifact

from .models import RedactionRecord, SecuritySkillResult, SkillErrorCode, SkillManifest


def stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def content_hash(*parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DetectionOutput:
    findings: tuple[Finding, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    redactions: tuple[RedactionRecord, ...] = ()


class SkillExecutionError(RuntimeError):
    def __init__(self, code: SkillErrorCode, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class DeterministicSecuritySkill(ABC):
    manifest: SkillManifest

    @abstractmethod
    def _detect(self, artifact: GitDiffArtifact, *, now: datetime) -> DetectionOutput:
        """Return validated deterministic observations or raise a safe typed error."""

    def _files_in_scope(self, artifact: GitDiffArtifact) -> tuple[str, ...]:
        return tuple(
            item.change.new_path or item.change.old_path
            for item in artifact.files
            if not item.change.is_binary
        )

    def run(
        self,
        artifact: GitDiffArtifact,
        *,
        mandatory: bool = True,
        route_ids: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> SecuritySkillResult:
        started = now or datetime.now(UTC)
        timer = time.perf_counter_ns()
        try:
            output = self._detect(artifact, now=started)
            return self._success_result(
                artifact,
                output=output,
                mandatory=mandatory,
                route_ids=route_ids,
                started=started,
                timer=timer,
            )
        except SkillExecutionError as exc:
            return self._failure_result(
                artifact,
                mandatory=mandatory,
                route_ids=route_ids,
                started=started,
                timer=timer,
                error_code=exc.code,
                safe_message=exc.safe_message,
            )
        except ValidationError:
            return self._failure_result(
                artifact,
                mandatory=mandatory,
                route_ids=route_ids,
                started=started,
                timer=timer,
                error_code=SkillErrorCode.SCHEMA_ERROR,
                safe_message="deterministic security output violated its schema",
            )
        except Exception:
            return self._failure_result(
                artifact,
                mandatory=mandatory,
                route_ids=route_ids,
                started=started,
                timer=timer,
                error_code=SkillErrorCode.TOOL_ERROR,
                safe_message="deterministic security tool failed",
            )

    def _success_result(
        self,
        artifact: GitDiffArtifact,
        *,
        output: DetectionOutput,
        mandatory: bool,
        route_ids: tuple[str, ...],
        started: datetime,
        timer: int,
    ) -> SecuritySkillResult:
        completed = datetime.now(UTC)
        if completed < started:
            completed = started
        duration_ms = max(0, (time.perf_counter_ns() - timer) // 1_000_000)
        verified_ids = tuple(
            item.evidence_id
            for item in output.evidence
            if item.level is EvidenceLevel.E3
            and item.source in {EvidenceSource.RULE, EvidenceSource.STATIC_TOOL}
        )
        coverage = CoverageRecord(
            coverage_id=stable_id(
                "coverage", artifact.diff_hash, self.manifest.name, self.manifest.version
            ),
            skill_name=self.manifest.name,
            skill_version=self.manifest.version,
            status=CoverageStatus.COMPLETED,
            mandatory=mandatory,
            route_ids=route_ids,
            files_checked=self._files_in_scope(artifact),
            reason="Deterministic Skill completed over the provided diff only.",
            error_code=None,
            duration_ms=duration_ms,
        )
        return SecuritySkillResult(
            review_id=artifact.review_id,
            manifest=self.manifest,
            status=SkillStatus.SUCCESS,
            findings=output.findings,
            evidence=output.evidence,
            coverage=coverage,
            verified_e3_evidence_ids=verified_ids,
            redactions=output.redactions,
            started_at=started,
            completed_at=completed,
        )

    def _failure_result(
        self,
        artifact: GitDiffArtifact,
        *,
        mandatory: bool,
        route_ids: tuple[str, ...],
        started: datetime,
        timer: int,
        error_code: SkillErrorCode,
        safe_message: str,
    ) -> SecuritySkillResult:
        completed = datetime.now(UTC)
        if completed < started:
            completed = started
        duration_ms = max(0, (time.perf_counter_ns() - timer) // 1_000_000)
        evidence_id = stable_id(
            "evidence",
            artifact.diff_hash,
            self.manifest.name,
            self.manifest.version,
            error_code.value,
        )
        evidence = Evidence(
            evidence_id=evidence_id,
            level=EvidenceLevel.E0,
            source=EvidenceSource.SYSTEM,
            detector_name=self.manifest.name,
            detector_version=self.manifest.version,
            summary=f"{error_code.value}: {safe_message}",
            location=None,
            reproducible=False,
            confidence=0.0,
            artifact_ref=None,
            content_hash=content_hash(
                self.manifest.name, self.manifest.version, error_code.value, safe_message
            ),
            created_at=started,
        )
        coverage = CoverageRecord(
            coverage_id=stable_id(
                "coverage", artifact.diff_hash, self.manifest.name, self.manifest.version
            ),
            skill_name=self.manifest.name,
            skill_version=self.manifest.version,
            status=CoverageStatus.FAILED,
            mandatory=mandatory,
            route_ids=route_ids,
            files_checked=self._files_in_scope(artifact),
            reason=safe_message,
            error_code=error_code.value,
            duration_ms=duration_ms,
        )
        return SecuritySkillResult(
            review_id=artifact.review_id,
            manifest=self.manifest,
            status=SkillStatus.FAILED,
            findings=(),
            evidence=(evidence,),
            coverage=coverage,
            verified_e3_evidence_ids=(),
            redactions=(),
            started_at=started,
            completed_at=completed,
        )
