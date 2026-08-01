"""Ordered P6 security suite and sanitized diff boundary."""

from __future__ import annotations

from datetime import UTC, datetime

from codesentinel.domain import CoverageRecord, CoverageStatus, SkillStatus
from codesentinel.gitdiff import GitDiffArtifact

from .base import content_hash, stable_id
from .common import iter_source_lines
from .dangerous import DetectDangerousCallSkill
from .injection import DetectInjectionSkill
from .models import (
    SanitizedDiffLine,
    SanitizedDiffView,
    SecurityScanResult,
    SecuritySkillResult,
)
from .secret import DetectSecretSkill


class SecuritySkillSuite:
    """Run all mandatory P6 Skills in their frozen order and fail closed."""

    def __init__(
        self,
        *,
        secret_skill: DetectSecretSkill | None = None,
        injection_skill: DetectInjectionSkill | None = None,
        dangerous_call_skill: DetectDangerousCallSkill | None = None,
    ) -> None:
        self._secret = secret_skill or DetectSecretSkill()
        self._injection = injection_skill or DetectInjectionSkill()
        self._dangerous = dangerous_call_skill or DetectDangerousCallSkill()

    def run(
        self,
        artifact: GitDiffArtifact,
        *,
        now: datetime | None = None,
    ) -> SecurityScanResult:
        """Run the original P6 all-Skill profile for backward compatibility."""

        started = now or datetime.now(UTC)
        secret_result, sanitized = self.run_secret_boundary(artifact, now=started)
        return self.run_routed(
            artifact,
            secret_result=secret_result,
            sanitized_diff=sanitized,
            planned_route_ids={
                "detect_secret": (),
                "detect_injection": (),
                "detect_dangerous_call": (),
            },
            now=started,
        )

    def run_secret_boundary(
        self,
        artifact: GitDiffArtifact,
        *,
        now: datetime | None = None,
    ) -> tuple[SecuritySkillResult, SanitizedDiffView]:
        """Run the always-on secret Skill before any cloud context can exist."""

        started = now or datetime.now(UTC)
        result = self._secret.run(artifact, mandatory=True, now=started)
        sanitized = self._build_sanitized_view(
            artifact,
            secret_status=result.status,
            redactions=result.redactions,
        )
        return result, sanitized

    def run_routed(
        self,
        artifact: GitDiffArtifact,
        *,
        secret_result: SecuritySkillResult,
        sanitized_diff: SanitizedDiffView,
        planned_route_ids: dict[str, tuple[str, ...]],
        now: datetime | None = None,
    ) -> SecurityScanResult:
        """Complete the suite while skipping optional Skills absent from the RiskMap."""

        started = now or datetime.now(UTC)
        if secret_result.review_id != artifact.review_id:
            raise ValueError("secret result review_id must match the Git artifact")
        if secret_result.manifest.name != "detect_secret":
            raise ValueError("secret_result must come from detect_secret")
        if sanitized_diff.review_id != artifact.review_id:
            raise ValueError("sanitized diff review_id must match the Git artifact")
        if sanitized_diff.source_diff_hash != artifact.diff_hash:
            raise ValueError("sanitized diff hash must match the Git artifact")
        supported = {
            "detect_secret",
            "detect_injection",
            "detect_dangerous_call",
        }
        if set(planned_route_ids) - supported:
            raise ValueError("planned deterministic security Skill is unsupported")
        if "detect_secret" not in planned_route_ids:
            raise ValueError("detect_secret must always be planned")

        injection = (
            self._injection.run(
                artifact,
                mandatory=True,
                route_ids=planned_route_ids["detect_injection"],
                now=started,
            )
            if "detect_injection" in planned_route_ids
            else self._skipped_result(
                artifact,
                self._injection,
                started,
                "No RiskMap route requires deterministic injection detection.",
            )
        )
        dangerous = (
            self._dangerous.run(
                artifact,
                mandatory=True,
                route_ids=planned_route_ids["detect_dangerous_call"],
                now=started,
            )
            if "detect_dangerous_call" in planned_route_ids
            else self._skipped_result(
                artifact,
                self._dangerous,
                started,
                "No RiskMap route requires deterministic dangerous-call detection.",
            )
        )
        secret_routes = planned_route_ids["detect_secret"]
        if secret_result.coverage.route_ids != secret_routes:
            rebound = secret_result.coverage.model_copy(
                update={"route_ids": secret_routes, "mandatory": True}
            )
            secret_result = secret_result.model_copy(
                update={
                    "coverage": CoverageRecord.model_validate_json(
                        rebound.model_dump_json()
                    )
                }
            )
            secret_result = SecuritySkillResult.model_validate_json(
                secret_result.model_dump_json()
            )
        return self._aggregate(
            artifact,
            (secret_result, injection, dangerous),
            sanitized_diff,
        )

    @staticmethod
    def _skipped_result(
        artifact: GitDiffArtifact,
        skill,
        now: datetime,
        reason: str,
    ) -> SecuritySkillResult:
        manifest = skill.manifest
        coverage = CoverageRecord(
            coverage_id=stable_id(
                "coverage",
                artifact.diff_hash,
                manifest.name,
                manifest.version,
            ),
            skill_name=manifest.name,
            skill_version=manifest.version,
            status=CoverageStatus.SKIPPED,
            mandatory=False,
            route_ids=(),
            files_checked=(),
            reason=reason,
            error_code=None,
            duration_ms=0,
        )
        return SecuritySkillResult(
            review_id=artifact.review_id,
            manifest=manifest,
            status=SkillStatus.SKIPPED,
            findings=(),
            evidence=(),
            coverage=coverage,
            verified_e3_evidence_ids=(),
            redactions=(),
            started_at=now,
            completed_at=now,
        )

    @staticmethod
    def _aggregate(
        artifact: GitDiffArtifact,
        results: tuple[SecuritySkillResult, ...],
        sanitized: SanitizedDiffView,
    ) -> SecurityScanResult:
        statuses = {result.status for result in results}
        if SkillStatus.FAILED in statuses:
            status = SkillStatus.FAILED
        elif statuses & {SkillStatus.PARTIAL, SkillStatus.SKIPPED}:
            status = SkillStatus.PARTIAL
        else:
            status = SkillStatus.SUCCESS

        findings = tuple(finding for result in results for finding in result.findings)
        evidence = tuple(proof for result in results for proof in result.evidence)
        verified_ids = tuple(
            evidence_id
            for result in results
            for evidence_id in result.verified_e3_evidence_ids
        )
        redactions = tuple(
            redaction for result in results for redaction in result.redactions
        )
        return SecurityScanResult(
            review_id=artifact.review_id,
            status=status,
            skill_results=results,
            findings=findings,
            evidence=evidence,
            coverage=tuple(result.coverage for result in results),
            verified_e3_evidence_ids=verified_ids,
            redactions=redactions,
            sanitized_diff=sanitized,
        )

    @staticmethod
    def _build_sanitized_view(
        artifact: GitDiffArtifact,
        *,
        secret_status: SkillStatus,
        redactions: tuple,
    ) -> SanitizedDiffView:
        redaction_ids = tuple(item.redaction_id for item in redactions)
        if secret_status is not SkillStatus.SUCCESS:
            return SanitizedDiffView(
                review_id=artifact.review_id,
                source_diff_hash=artifact.diff_hash,
                lines=(),
                redaction_ids=redaction_ids,
                cloud_safe=False,
                reason="Secret detection failed; source disclosure is denied.",
            )
        if artifact.exceeds_changed_line_limit:
            return SanitizedDiffView(
                review_id=artifact.review_id,
                source_diff_hash=artifact.diff_hash,
                lines=(),
                redaction_ids=redaction_ids,
                cloud_safe=False,
                reason="The diff exceeds the approved changed-line limit.",
            )

        masked_by_location = {
            (item.file_path, item.hunk_id, item.side, item.line_number): item.masked_content
            for item in redactions
        }
        lines = []
        for source_line in iter_source_lines(
            artifact,
            python_only=True,
            include_context=True,
            include_deletions=True,
        ):
            key = (
                source_line.file_path,
                source_line.hunk_id,
                source_line.side,
                source_line.line_number,
            )
            content = masked_by_location.get(key, source_line.content)
            lines.append(
                SanitizedDiffLine(
                    file_path=source_line.file_path,
                    hunk_id=source_line.hunk_id,
                    kind=source_line.kind,
                    side=source_line.side,
                    line_number=source_line.line_number,
                    content=content,
                    content_hash=content_hash(content),
                )
            )
        return SanitizedDiffView(
            review_id=artifact.review_id,
            source_diff_hash=artifact.diff_hash,
            lines=tuple(lines),
            redaction_ids=redaction_ids,
            cloud_safe=True,
            reason="Secret detection completed and every detected value was masked locally.",
        )
