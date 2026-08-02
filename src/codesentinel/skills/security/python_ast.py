"""Fail-closed Python AST reconstruction for unified-diff hunks."""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass

from codesentinel.gitdiff import DiffLineKind, GitDiffArtifact

from .base import SkillExecutionError
from .common import SourceLine
from .models import SkillErrorCode


@dataclass(frozen=True)
class PythonAstUnit:
    """One parsed new-side hunk with a stable AST-to-diff line mapping."""

    file_path: str
    hunk_id: str
    tree: ast.Module
    source_lines: tuple[SourceLine, ...]
    wrapper_lines: int = 0

    def source_line_for_node(
        self,
        node: ast.AST,
        *,
        added_only: bool,
    ) -> SourceLine | None:
        start = getattr(node, "lineno", None)
        if not isinstance(start, int):
            return None
        end = getattr(node, "end_lineno", start)
        if not isinstance(end, int):
            end = start
        first_index = max(0, start - self.wrapper_lines - 1)
        last_index = min(len(self.source_lines) - 1, end - self.wrapper_lines - 1)
        if first_index > last_index:
            return None
        for index in range(first_index, last_index + 1):
            source_line = self.source_lines[index]
            if not added_only or source_line.is_added:
                return source_line
        return None


@dataclass(frozen=True)
class PythonAstAnalysis:
    units: tuple[PythonAstUnit, ...]
    files_checked: tuple[str, ...]

    def units_for_file(self, file_path: str) -> tuple[PythonAstUnit, ...]:
        return tuple(unit for unit in self.units if unit.file_path == file_path)


def python_files_in_scope(artifact: GitDiffArtifact) -> tuple[str, ...]:
    """Return only Python files whose added lines are actually inspected."""

    return tuple(
        path
        for parsed_file in artifact.files
        if not parsed_file.change.is_binary
        and parsed_file.change.language == "python"
        and parsed_file.change.additions > 0
        and (path := parsed_file.change.new_path or parsed_file.change.old_path) is not None
    )


def analyze_python_diff(artifact: GitDiffArtifact) -> PythonAstAnalysis:
    """Parse every Python hunk containing additions or fail coverage closed."""

    files_checked = python_files_in_scope(artifact)
    units: list[PythonAstUnit] = []
    for parsed_file in artifact.files:
        change = parsed_file.change
        file_path = change.new_path or change.old_path
        if file_path not in files_checked:
            continue
        for hunk in parsed_file.hunks:
            source_lines = tuple(
                SourceLine(
                    file_path=file_path,
                    hunk_id=hunk.hunk_id,
                    kind=line.kind,
                    side="new",
                    line_number=line.new_line,
                    content=line.content,
                )
                for line in hunk.lines
                if line.kind is not DiffLineKind.DELETION and line.new_line is not None
            )
            if not any(line.is_added for line in source_lines):
                continue
            tree, wrapper_lines = _parse_hunk(source_lines)
            units.append(
                PythonAstUnit(
                    file_path=file_path,
                    hunk_id=hunk.hunk_id,
                    tree=tree,
                    source_lines=source_lines,
                    wrapper_lines=wrapper_lines,
                )
            )
    return PythonAstAnalysis(units=tuple(units), files_checked=files_checked)


def collect_import_aliases(units: tuple[PythonAstUnit, ...]) -> dict[str, str]:
    """Collect explicit import aliases available in the supplied diff context."""

    aliases: dict[str, str] = {}
    for unit in units:
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    local_name = item.asname or item.name.split(".", 1)[0]
                    aliases[local_name] = item.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    if item.name == "*":
                        continue
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def qualified_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a simple Name/Attribute chain through explicit import aliases."""

    raw = _raw_qualified_name(node)
    if not raw:
        return ""
    head, separator, tail = raw.partition(".")
    resolved = aliases.get(head, head)
    return f"{resolved}.{tail}" if separator else resolved


def _raw_qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _raw_qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _parse_hunk(source_lines: tuple[SourceLine, ...]) -> tuple[ast.Module, int]:
    source = textwrap.dedent("\n".join(line.content for line in source_lines))
    try:
        return ast.parse(source), 0
    except SyntaxError:
        wrapped = "def __codesentinel_diff_fragment__():\n" + textwrap.indent(
            source or "pass",
            "    ",
        )
        try:
            return ast.parse(wrapped), 1
        except SyntaxError as exc:
            raise SkillExecutionError(
                SkillErrorCode.CONTEXT_INSUFFICIENT,
                "Python diff context could not be parsed without guessing.",
            ) from exc
