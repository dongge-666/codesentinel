"""AST-backed deterministic injection detection for added Python lines."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from datetime import datetime

from codesentinel.domain import RiskCategory, Severity
from codesentinel.gitdiff import GitDiffArtifact

from .base import DetectionOutput, DeterministicSecuritySkill
from .common import SourceLine, build_detection
from .models import SkillManifest
from .python_ast import (
    PythonAstUnit,
    analyze_python_diff,
    collect_import_aliases,
    python_files_in_scope,
    qualified_name,
)

_SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.I)
_SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
_SQL_SINK_METHODS = {"execute", "executemany", "executescript"}


@dataclass(frozen=True)
class _Assignment:
    value: ast.AST
    unit: PythonAstUnit
    line_number: int
    scope: tuple[str, ...]


class DetectInjectionSkill(DeterministicSecuritySkill):
    """Detect reproducible SQL and command-injection patterns on new lines."""

    manifest = SkillManifest(
        name="detect_injection",
        version="1.1.0",
        purpose="Detect deterministic SQL and shell injection patterns in added Python lines.",
        trigger="Run when Python source contains added lines.",
        dependencies=("python-ast@3.11", "builtin-rules@1.1.0"),
        permissions=("provided_diff_only",),
        safety="Reconstructs bounded diff hunks locally and never executes reviewed code.",
        reuse="Reusable for Python additions with sufficient hunk context for AST parsing.",
    )

    def _detect(self, artifact: GitDiffArtifact, *, now: datetime) -> DetectionOutput:
        analysis = analyze_python_diff(artifact)
        detections: dict[
            tuple[str, str, str, int],
            tuple[SourceLine, RiskCategory, str, str, str],
        ] = {}
        for file_path in analysis.files_checked:
            units = analysis.units_for_file(file_path)
            aliases = collect_import_aliases(units)
            scopes = self._collect_scopes(units)
            assignments = self._collect_assignments(units, scopes)
            for unit in units:
                for node in ast.walk(unit.tree):
                    if not isinstance(node, ast.Call):
                        continue
                    sql_line = self._dynamic_sql_line(
                        node,
                        unit=unit,
                        aliases=aliases,
                        assignments=assignments,
                        scope=scopes[id(node)],
                    )
                    if sql_line is not None:
                        detections[
                            (
                                "CS-INJECT-SQL-DYNAMIC",
                                sql_line.file_path,
                                sql_line.hunk_id,
                                sql_line.line_number,
                            )
                        ] = (
                            sql_line,
                            RiskCategory.SQL_INJECTION,
                            "Dynamic SQL execution added",
                            "A database execution sink receives runtime-composed SQL text.",
                            "Use a parameterized query and pass data separately from SQL text.",
                        )
                    shell_line = unit.source_line_for_node(node, added_only=True)
                    if shell_line is not None and self._is_dynamic_shell_call(
                        node,
                        aliases=aliases,
                    ):
                        detections[
                            (
                                "CS-INJECT-SHELL-DYNAMIC",
                                shell_line.file_path,
                                shell_line.hunk_id,
                                shell_line.line_number,
                            )
                        ] = (
                            shell_line,
                            RiskCategory.COMMAND_INJECTION,
                            "Dynamic shell command added",
                            "A shell-capable call receives runtime-composed command text.",
                            "Disable shell execution and pass validated arguments as a list.",
                        )

        findings = []
        evidence = []
        for key, (source_line, category, title, claim, recommendation) in detections.items():
            rule_id = key[0]
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

    def _files_in_scope(self, artifact: GitDiffArtifact) -> tuple[str, ...]:
        return python_files_in_scope(artifact)

    @classmethod
    def _dynamic_sql_line(
        cls,
        node: ast.Call,
        *,
        unit: PythonAstUnit,
        aliases: dict[str, str],
        assignments: dict[str, tuple[_Assignment, ...]],
        scope: tuple[str, ...],
    ) -> SourceLine | None:
        if not node.args or not cls._is_sql_sink(node, aliases=aliases):
            return None
        sink_line = unit.source_line_for_node(node, added_only=False)
        before_line = sink_line.line_number if sink_line is not None else 2**31 - 1
        value = node.args[0]
        if not cls._contains_sql_text(value, assignments, before_line, scope, set()):
            return None
        if not cls._is_dynamic(value, assignments, before_line, scope, set()):
            return None
        return unit.source_line_for_node(node, added_only=True) or cls._assignment_line(
            value,
            assignments,
            before_line,
            scope,
            set(),
        )

    @staticmethod
    def _is_sql_sink(node: ast.Call, *, aliases: dict[str, str]) -> bool:
        name = qualified_name(node.func, aliases)
        return bool(name) and name.rsplit(".", 1)[-1] in _SQL_SINK_METHODS

    @classmethod
    def _is_dynamic_shell_call(
        cls,
        node: ast.Call,
        *,
        aliases: dict[str, str],
    ) -> bool:
        name = qualified_name(node.func, aliases)
        if not node.args:
            return False
        if name == "os.system":
            return cls._is_dynamic(node.args[0], {}, 2**31 - 1, (), set())
        if name not in _SUBPROCESS_CALLS:
            return False
        shell_enabled = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        return shell_enabled and cls._is_dynamic(
            node.args[0],
            {},
            2**31 - 1,
            (),
            set(),
        )

    @classmethod
    def _contains_sql_text(
        cls,
        node: ast.AST,
        assignments: dict[str, tuple[_Assignment, ...]],
        before_line: int,
        scope: tuple[str, ...],
        seen: set[str],
    ) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _SQL_KEYWORDS.search(node.value) is not None
        if isinstance(node, ast.Name):
            assignment = cls._resolve_assignment(
                node.id,
                assignments,
                before_line,
                scope,
            )
            if assignment is None or node.id in seen:
                return False
            return cls._contains_sql_text(
                assignment.value,
                assignments,
                assignment.line_number,
                assignment.scope,
                {*seen, node.id},
            )
        return any(
            cls._contains_sql_text(child, assignments, before_line, scope, seen)
            for child in ast.iter_child_nodes(node)
        )

    @classmethod
    def _is_dynamic(
        cls,
        node: ast.AST,
        assignments: dict[str, tuple[_Assignment, ...]],
        before_line: int,
        scope: tuple[str, ...],
        seen: set[str],
    ) -> bool:
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            assignment = cls._resolve_assignment(
                node.id,
                assignments,
                before_line,
                scope,
            )
            if assignment is None or node.id in seen:
                return True
            return cls._is_dynamic(
                assignment.value,
                assignments,
                assignment.line_number,
                assignment.scope,
                {*seen, node.id},
            )
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(value, ast.FormattedValue) for value in node.values)
        if isinstance(node, ast.BinOp):
            return cls._is_dynamic(
                node.left, assignments, before_line, scope, seen
            ) or cls._is_dynamic(node.right, assignments, before_line, scope, seen)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return bool(node.args or node.keywords)
            return any(
                cls._is_dynamic(item, assignments, before_line, scope, seen)
                for item in (*node.args, *(item.value for item in node.keywords))
            )
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(
                cls._is_dynamic(item, assignments, before_line, scope, seen) for item in node.elts
            )
        return any(
            cls._is_dynamic(child, assignments, before_line, scope, seen)
            for child in ast.iter_child_nodes(node)
        )

    @staticmethod
    def _collect_assignments(
        units: tuple[PythonAstUnit, ...],
        scopes: dict[int, tuple[str, ...]],
    ) -> dict[str, tuple[_Assignment, ...]]:
        collected: dict[str, list[_Assignment]] = {}
        for unit in units:
            for node in ast.walk(unit.tree):
                targets: tuple[ast.AST, ...]
                value: ast.AST | None
                if isinstance(node, ast.Assign):
                    targets = tuple(node.targets)
                    value = node.value
                elif isinstance(node, ast.AnnAssign):
                    targets = (node.target,)
                    value = node.value
                elif isinstance(node, ast.NamedExpr):
                    targets = (node.target,)
                    value = node.value
                else:
                    continue
                if value is None:
                    continue
                source_line = unit.source_line_for_node(value, added_only=False)
                if source_line is None:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        collected.setdefault(target.id, []).append(
                            _Assignment(
                                value=value,
                                unit=unit,
                                line_number=source_line.line_number,
                                scope=scopes[id(node)],
                            )
                        )
        return {
            name: tuple(sorted(items, key=lambda item: item.line_number))
            for name, items in collected.items()
        }

    @staticmethod
    def _resolve_assignment(
        name: str,
        assignments: dict[str, tuple[_Assignment, ...]],
        before_line: int,
        scope: tuple[str, ...],
    ) -> _Assignment | None:
        for depth in range(len(scope), 0, -1):
            visible_scope = scope[:depth]
            candidates = tuple(
                item
                for item in assignments.get(name, ())
                if item.scope == visible_scope and item.line_number <= before_line
            )
            if candidates:
                return candidates[-1]
        return None

    @classmethod
    def _assignment_line(
        cls,
        node: ast.AST,
        assignments: dict[str, tuple[_Assignment, ...]],
        before_line: int,
        scope: tuple[str, ...],
        seen: set[str],
    ) -> SourceLine | None:
        if isinstance(node, ast.Name):
            assignment = cls._resolve_assignment(
                node.id,
                assignments,
                before_line,
                scope,
            )
            if assignment is None or node.id in seen:
                return None
            return assignment.unit.source_line_for_node(
                assignment.value,
                added_only=True,
            ) or cls._assignment_line(
                assignment.value,
                assignments,
                assignment.line_number,
                assignment.scope,
                {*seen, node.id},
            )
        for child in ast.iter_child_nodes(node):
            if line := cls._assignment_line(
                child,
                assignments,
                before_line,
                scope,
                seen,
            ):
                return line
        return None

    @staticmethod
    def _collect_scopes(
        units: tuple[PythonAstUnit, ...],
    ) -> dict[int, tuple[str, ...]]:
        scopes: dict[int, tuple[str, ...]] = {}
        scope_nodes = (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
            ast.ClassDef,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        )

        def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
            scopes[id(node)] = scope
            child_scope = scope
            if isinstance(node, scope_nodes):
                label = getattr(node, "name", type(node).__name__)
                child_scope = (*scope, f"{type(node).__name__}:{label}:{node.lineno}")
            for child in ast.iter_child_nodes(node):
                visit(child, child_scope)

        for unit in units:
            visit(unit.tree, (unit.hunk_id,))
        return scopes
