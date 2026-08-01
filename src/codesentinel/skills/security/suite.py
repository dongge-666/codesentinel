"""Ordered P6 security suite and sanitized diff boundary."""

from __future__ import annotations

from datetime import UTC, datetime

from codesentinel.domain import SkillStatus
from codesentinel.gitdiff import GitDiffArtifact

from .base import content_hash
from .common import iter_source_lines
from .dangerous import DetectDangerousCallSkill
from .injection import DetectInjectionSkill
from .models import SanitizedDiffLine, SanitizedDiffView, SecurityScanResult
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
        started = now or datetime.now(UTC)
        results = (
            self._secret.run(artifact, mandatory=True, now=started),
            self._injection.run(artifact, mandatory=True, now=started),
            self._dangerous.run(artifact, mandatory=True, now=started),
        )
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
        sanitized = self._build_sanitized_view(
            artifact,
            secret_status=results[0].status,
            redactions=redactions,
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
