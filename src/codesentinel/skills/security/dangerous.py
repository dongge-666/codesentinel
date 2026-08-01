"""Deterministic dangerous-call detection with a constrained Bandit adapter."""

from __future__ import annotations

import ast
import textwrap
from datetime import datetime

from codesentinel.domain import (
    EvidenceLevel,
    EvidenceSource,
    FindingStatus,
    RiskCategory,
    Severity,
)
from codesentinel.gitdiff import GitDiffArtifact

from .adapters import BanditAdapter, DefaultBanditAdapter
from .base import DetectionOutput, DeterministicSecuritySkill
from .common import SourceLine, build_detection, iter_source_lines
from .models import SkillManifest

_SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}


class DetectDangerousCallSkill(DeterministicSecuritySkill):
    """Detect exact dangerous calls and preserve Bandit as independent support."""

    manifest = SkillManifest(
        name="detect_dangerous_call",
        purpose="Detect dangerous Python execution and shell APIs on added lines.",
        trigger="Run when Python source contains added lines.",
        dependencies=("python-ast@3.11", "bandit>=1.9.4,<2"),
        permissions=("provided_diff_only", "temporary_local_file"),
        safety="Never imports reviewed code; Bandit receives only isolated added statements.",
        reuse="Reusable for Python additions accepted by the local AST parser.",
    )

    def __init__(self, adapter: BanditAdapter | None = None) -> None:
        self._adapter = adapter or DefaultBanditAdapter()

    def _detect(self, artifact: GitDiffArtifact, *, now: datetime) -> DetectionOutput:
        lines = iter_source_lines(
            artifact,
            python_only=True,
            include_context=False,
            include_deletions=False,
        )
        findings = []
        evidence = []
        builtin_locations: set[tuple[str, str, int]] = set()
        for source_line in lines:
            tree = self._parse_line(source_line)
            if tree is None:
                continue
            rules: dict[str, tuple[str, str, str]] = {}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = self._qualified_name(node.func)
                if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                    rules["CS-DANGER-DYNAMIC-EXEC"] = (
                        "Dynamic code execution added",
                        "An eval or exec call can execute data as Python code.",
                        (
                            "Replace dynamic execution with an explicit parser or "
                            "allow-listed dispatch."
                        ),
                    )
                elif name == "os.system":
                    rules["CS-DANGER-OS-SYSTEM"] = (
                        "Shell process API added",
                        "os.system invokes a command through the operating-system shell.",
                        "Use subprocess with shell disabled and an argument list.",
                    )
                elif name in _SUBPROCESS_CALLS and self._shell_enabled(node):
                    rules["CS-DANGER-SUBPROCESS-SHELL"] = (
                        "Shell-enabled subprocess added",
                        "A subprocess call explicitly enables shell interpretation.",
                        "Disable shell execution and pass arguments as a list.",
                    )
            for rule_id, (title, claim, recommendation) in rules.items():
                finding, proof = build_detection(
                    artifact=artifact,
                    source_line=source_line,
                    detector_name=self.manifest.name,
                    detector_version=self.manifest.version,
                    rule_id=rule_id,
                    category=RiskCategory.DANGEROUS_CALL,
                    severity=Severity.HIGH,
                    title=title,
                    claim=claim,
                    recommendation=recommendation,
                    now=now,
                )
                findings.append(finding)
                evidence.append(proof)
                builtin_locations.add(
                    (source_line.file_path, source_line.hunk_id, source_line.line_number)
                )

        for observation in self._adapter.scan(lines):
            line_key = (
                observation.source_line.file_path,
                observation.source_line.hunk_id,
                observation.source_line.line_number,
            )
            if line_key in builtin_locations:
                continue
            finding, proof = build_detection(
                artifact=artifact,
                source_line=observation.source_line,
                detector_name=self.manifest.name,
                detector_version=self.manifest.version,
                rule_id=f"BANDIT-{observation.test_id}",
                category=RiskCategory.DANGEROUS_CALL,
                severity=self._bandit_severity(observation.severity),
                title="Bandit dangerous-call observation",
                claim=observation.safe_message,
                recommendation="Review the call and replace it with a constrained API.",
                now=now,
                level=EvidenceLevel.E2,
                source=EvidenceSource.STATIC_TOOL,
                status=FindingStatus.SUSPECTED,
                confidence=self._bandit_confidence(observation.confidence),
            )
            findings.append(finding)
            evidence.append(proof)
        return DetectionOutput(findings=tuple(findings), evidence=tuple(evidence))

    @staticmethod
    def _parse_line(source_line: SourceLine) -> ast.AST | None:
        candidate = textwrap.dedent(source_line.content).strip()
        if not candidate:
            return None
        try:
            return ast.parse(candidate)
        except SyntaxError:
            return None

    @staticmethod
    def _shell_enabled(node: ast.Call) -> bool:
        return any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    @classmethod
    def _qualified_name(cls, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = cls._qualified_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _bandit_severity(value: str) -> Severity:
        return Severity.MEDIUM if value.upper() in {"HIGH", "MEDIUM"} else Severity.LOW

    @staticmethod
    def _bandit_confidence(value: str) -> float:
        return {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.6}.get(value.upper(), 0.5)
