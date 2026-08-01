"""AST-backed deterministic injection detection for added Python lines."""

from __future__ import annotations

import ast
import re
import textwrap
from datetime import datetime

from codesentinel.domain import RiskCategory, Severity
from codesentinel.gitdiff import GitDiffArtifact

from .base import DetectionOutput, DeterministicSecuritySkill
from .common import SourceLine, build_detection, iter_source_lines
from .models import SkillManifest

_SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.I)
_SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}


class DetectInjectionSkill(DeterministicSecuritySkill):
    """Detect reproducible SQL and command-injection patterns on new lines."""

    manifest = SkillManifest(
        name="detect_injection",
        purpose="Detect deterministic SQL and shell injection patterns in added Python lines.",
        trigger="Run when Python source contains added lines.",
        dependencies=("python-ast@3.11", "builtin-rules@1.0.0"),
        permissions=("provided_diff_only",),
        safety="Parses isolated source lines locally and never executes reviewed code.",
        reuse="Reusable for Python additions that form a complete expression or statement.",
    )

    def _detect(self, artifact: GitDiffArtifact, *, now: datetime) -> DetectionOutput:
        findings = []
        evidence = []
        lines = iter_source_lines(
            artifact,
            python_only=True,
            include_context=False,
            include_deletions=False,
        )
        for source_line in lines:
            tree = self._parse_line(source_line)
            if tree is None:
                continue
            rules: dict[str, tuple[RiskCategory, str, str, str]] = {}
            for node in ast.walk(tree):
                if self._is_dynamic_sql(node):
                    rules["CS-INJECT-SQL-DYNAMIC"] = (
                        RiskCategory.SQL_INJECTION,
                        "Dynamic SQL construction added",
                        "SQL text is combined with a runtime value on an added line.",
                        "Use a parameterized query and pass data separately from SQL text.",
                    )
                if isinstance(node, ast.Call) and self._is_dynamic_shell_call(node):
                    rules["CS-INJECT-SHELL-DYNAMIC"] = (
                        RiskCategory.COMMAND_INJECTION,
                        "Dynamic shell command added",
                        "A shell-capable call receives runtime-composed command text.",
                        "Disable shell execution and pass validated arguments as a list.",
                    )
            for rule_id, (category, title, claim, recommendation) in rules.items():
                finding, proof = build_detection(
                    artifact=artifact,
                    source_line=source_line,
                    detector_name=self.manifest.name,
                    detector_version=self.manifest.version,
                    rule_id=rule_id,
                    category=category,
                    severity=Severity.HIGH,
                    title=title,
                    claim=claim,
                    recommendation=recommendation,
                    now=now,
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

    @classmethod
    def _is_dynamic_sql(cls, node: ast.AST) -> bool:
        if not isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
            return False
        return cls._contains_sql_text(node) and cls._is_dynamic(node)

    @classmethod
    def _is_dynamic_shell_call(cls, node: ast.Call) -> bool:
        name = cls._qualified_name(node.func)
        if not node.args:
            return False
        if name == "os.system":
            return cls._is_dynamic(node.args[0])
        if name not in _SUBPROCESS_CALLS:
            return False
        shell_enabled = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        return shell_enabled and cls._is_dynamic(node.args[0])

    @classmethod
    def _contains_sql_text(cls, node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and _SQL_KEYWORDS.search(child.value)
            for child in ast.walk(node)
        )

    @classmethod
    def _is_dynamic(cls, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(value, ast.FormattedValue) for value in node.values)
        if isinstance(node, ast.BinOp):
            return cls._is_dynamic(node.left) or cls._is_dynamic(node.right)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return bool(node.args or node.keywords)
            return True
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(cls._is_dynamic(item) for item in node.elts)
        return any(cls._is_dynamic(child) for child in ast.iter_child_nodes(node))

    @classmethod
    def _qualified_name(cls, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = cls._qualified_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""
