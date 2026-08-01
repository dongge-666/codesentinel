"""Deterministic secret detection and fail-closed source masking."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from codesentinel.domain import (
    EvidenceLevel,
    EvidenceSource,
    FindingStatus,
    RiskCategory,
    Severity,
)
from codesentinel.gitdiff import GitDiffArtifact

from .adapters import DefaultDetectSecretsAdapter, DetectSecretsAdapter
from .base import DetectionOutput, DeterministicSecuritySkill, content_hash, stable_id
from .common import SourceLine, build_detection, iter_source_lines
from .models import RedactionRecord, SkillManifest


@dataclass(frozen=True)
class _SecretMatch:
    source_line: SourceLine
    secret_type: str
    secret_value: str
    exact_rule: str | None


_EXACT_SECRET_RULES = (
    ("CS-SECRET-OPENAI", "OpenAI-style API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("CS-SECRET-AWS", "AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "CS-SECRET-GITHUB",
        "GitHub token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,255}"),
    ),
)


class DetectSecretSkill(DeterministicSecuritySkill):
    """Find secrets locally and mask every detected value before cloud use."""

    manifest = SkillManifest(
        name="detect_secret",
        purpose="Detect and mask credentials in the provided Git diff.",
        trigger="Always run before any diff content can become cloud eligible.",
        dependencies=("builtin-regex@1.0.0", "detect-secrets>=1.5,<2"),
        permissions=("provided_diff_only",),
        safety=(
            "Never serializes plaintext secrets; a detector failure makes the diff "
            "cloud-unsafe."
        ),
        reuse="Reusable for every text file in a parsed GitDiffArtifact.",
    )

    def __init__(self, adapter: DetectSecretsAdapter | None = None) -> None:
        self._adapter = adapter or DefaultDetectSecretsAdapter()

    def _detect(self, artifact: GitDiffArtifact, *, now: datetime) -> DetectionOutput:
        lines = iter_source_lines(
            artifact,
            python_only=False,
            include_context=True,
            include_deletions=True,
        )
        matches: dict[tuple[str, str, str, int, str], _SecretMatch] = {}
        for source_line in lines:
            for rule_id, secret_type, pattern in _EXACT_SECRET_RULES:
                for regex_match in pattern.finditer(source_line.content):
                    secret_value = regex_match.group(0)
                    key = self._match_key(source_line, secret_value)
                    matches[key] = _SecretMatch(
                        source_line=source_line,
                        secret_type=secret_type,
                        secret_value=secret_value,
                        exact_rule=rule_id,
                    )

        for observation in self._adapter.scan(lines):
            key = self._match_key(observation.source_line, observation.secret_value)
            if key in matches:
                continue
            matches[key] = _SecretMatch(
                source_line=observation.source_line,
                secret_type=observation.secret_type,
                secret_value=observation.secret_value,
                exact_rule=None,
            )

        by_line: dict[tuple[str, str, str, int], list[_SecretMatch]] = defaultdict(list)
        for match in matches.values():
            by_line[self._line_key(match.source_line)].append(match)

        redactions: list[RedactionRecord] = []
        masked_by_line: dict[tuple[str, str, str, int], str] = {}
        for line_key, line_matches in by_line.items():
            masked = line_matches[0].source_line.content
            sorted_matches = sorted(
                line_matches,
                key=lambda item: len(item.secret_value),
                reverse=True,
            )
            for match in sorted_matches:
                fingerprint = content_hash(match.secret_value)
                placeholder = f"<REDACTED:{self._safe_label(match.secret_type)}:{fingerprint[:12]}>"
                masked = masked.replace(match.secret_value, placeholder)
            masked_by_line[line_key] = masked
            for match in line_matches:
                fingerprint = content_hash(match.secret_value)
                redactions.append(
                    RedactionRecord(
                        redaction_id=stable_id(
                            "redaction",
                            artifact.diff_hash,
                            *line_key,
                            fingerprint,
                        ),
                        file_path=match.source_line.file_path,
                        hunk_id=match.source_line.hunk_id,
                        side=match.source_line.side,
                        line_number=match.source_line.line_number,
                        secret_type=match.secret_type,
                        secret_fingerprint=fingerprint,
                        masked_content=masked,
                    )
                )

        findings = []
        evidence = []
        for match in matches.values():
            if not match.source_line.is_added:
                continue
            if match.exact_rule is not None:
                rule_id = match.exact_rule
                level = EvidenceLevel.E3
                source = EvidenceSource.RULE
                severity = Severity.HIGH
                status = FindingStatus.CONFIRMED
                confidence = 1.0
            else:
                rule_id = f"DETECT-SECRETS-{self._safe_label(match.secret_type)}"
                level = EvidenceLevel.E2
                source = EvidenceSource.STATIC_TOOL
                severity = Severity.MEDIUM
                status = FindingStatus.SUSPECTED
                confidence = 0.85
            finding, proof = build_detection(
                artifact=artifact,
                source_line=match.source_line,
                detector_name=self.manifest.name,
                detector_version=self.manifest.version,
                rule_id=rule_id,
                category=RiskCategory.SECRET,
                severity=severity,
                title="Potential credential added",
                claim=f"{match.secret_type} was detected on an added line.",
                recommendation="Revoke the credential if real and load it from a secret store.",
                now=now,
                level=level,
                source=source,
                status=status,
                confidence=confidence,
                identity_salt=content_hash(match.secret_value),
            )
            findings.append(finding)
            evidence.append(proof)

        return DetectionOutput(
            findings=tuple(findings),
            evidence=tuple(evidence),
            redactions=tuple(redactions),
        )

    @staticmethod
    def _line_key(source_line: SourceLine) -> tuple[str, str, str, int]:
        return (
            source_line.file_path,
            source_line.hunk_id,
            source_line.side,
            source_line.line_number,
        )

    @classmethod
    def _match_key(
        cls,
        source_line: SourceLine,
        secret_value: str,
    ) -> tuple[str, str, str, int, str]:
        return (*cls._line_key(source_line), content_hash(secret_value))

    @staticmethod
    def _safe_label(value: str) -> str:
        return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_") or "SECRET"
