"""Deterministic source-line mapping and evidence factories for P6."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from codesentinel.domain import (
    CodeLocation,
    Evidence,
    EvidenceLevel,
    EvidenceSource,
    Finding,
    FindingStatus,
    RiskCategory,
    Severity,
)
from codesentinel.gitdiff import DiffLineKind, GitDiffArtifact

from .base import content_hash, stable_id


@dataclass(frozen=True)
class SourceLine:
    file_path: str
    hunk_id: str
    kind: DiffLineKind
    side: str
    line_number: int
    content: str

    @property
    def is_added(self) -> bool:
        return self.kind is DiffLineKind.ADDITION

    def location(self) -> CodeLocation:
        return CodeLocation(
            file_path=self.file_path,
            start_line=self.line_number,
            end_line=self.line_number,
            side=self.side,
            hunk_id=self.hunk_id,
            snippet_hash=content_hash(self.content),
        )


def iter_source_lines(
    artifact: GitDiffArtifact,
    *,
    python_only: bool,
    include_context: bool,
    include_deletions: bool,
) -> tuple[SourceLine, ...]:
    output: list[SourceLine] = []
    for parsed_file in artifact.files:
        change = parsed_file.change
        if change.is_binary or (python_only and change.language != "python"):
            continue
        for hunk in parsed_file.hunks:
            for line in hunk.lines:
                if line.kind is DiffLineKind.DELETION:
                    if not include_deletions or change.old_path is None or line.old_line is None:
                        continue
                    output.append(
                        SourceLine(
                            file_path=change.old_path,
                            hunk_id=hunk.hunk_id,
                            kind=line.kind,
                            side="old",
                            line_number=line.old_line,
                            content=line.content,
                        )
                    )
                    continue
                if line.kind is DiffLineKind.CONTEXT and not include_context:
                    continue
                if change.new_path is None or line.new_line is None:
                    continue
                output.append(
                    SourceLine(
                        file_path=change.new_path,
                        hunk_id=hunk.hunk_id,
                        kind=line.kind,
                        side="new",
                        line_number=line.new_line,
                        content=line.content,
                    )
                )
    return tuple(output)


def build_detection(
    *,
    artifact: GitDiffArtifact,
    source_line: SourceLine,
    detector_name: str,
    detector_version: str,
    rule_id: str,
    category: RiskCategory,
    severity: Severity,
    title: str,
    claim: str,
    recommendation: str,
    now: datetime,
    level: EvidenceLevel = EvidenceLevel.E3,
    source: EvidenceSource = EvidenceSource.RULE,
    status: FindingStatus = FindingStatus.CONFIRMED,
    confidence: float = 1.0,
    identity_salt: str = "",
) -> tuple[Finding, Evidence]:
    location = source_line.location()
    fingerprint = content_hash(
        detector_name,
        detector_version,
        rule_id,
        category.value,
        source_line.file_path,
        source_line.side,
        source_line.line_number,
        location.snippet_hash,
        identity_salt,
    )
    evidence_id = stable_id("evidence", artifact.diff_hash, fingerprint)
    finding_id = stable_id("finding", artifact.diff_hash, fingerprint)
    evidence = Evidence(
        evidence_id=evidence_id,
        level=level,
        source=source,
        detector_name=detector_name,
        detector_version=detector_version,
        summary=f"{rule_id}: {claim}",
        location=location,
        reproducible=level in {EvidenceLevel.E2, EvidenceLevel.E3},
        confidence=confidence,
        artifact_ref=None,
        content_hash=content_hash(fingerprint, rule_id, claim),
        created_at=now,
    )
    finding = Finding(
        finding_id=finding_id,
        category=category,
        title=title,
        claim=claim,
        severity=severity,
        status=status,
        locations=(location,),
        evidence_ids=(evidence_id,),
        confidence=confidence,
        recommendation=recommendation,
        agent_id="security-scanner",
        fingerprint=fingerprint,
    )
    return finding, evidence
