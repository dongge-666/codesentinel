"""Deterministic parser for Git's unified patch output."""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass

from pydantic import ValidationError

from codesentinel.domain import ChangeType, FileChange

from .errors import DiffParseError
from .models import DiffHunk, DiffLine, DiffLineKind, ParsedFileDiff

_HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$"
)


@dataclass(frozen=True)
class _FileSection:
    old_path: str | None
    new_path: str | None
    change_type: ChangeType
    is_binary: bool
    text: str
    lines: tuple[str, ...]


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _strip_git_prefix(value: str) -> str:
    if value == "/dev/null":
        return value
    if value.startswith(("a/", "b/")):
        return value[2:]
    return value


def _parse_diff_header(line: str) -> tuple[str, str]:
    payload = line.removeprefix("diff --git ")
    try:
        paths = shlex.split(payload, posix=True)
    except ValueError as exc:
        raise DiffParseError("malformed diff --git header") from exc
    if len(paths) != 2:
        # Git for Windows may leave spaces unquoted here. The ---/+++ headers
        # override this fallback for text patches; binary and mode-only paths
        # use the explicit a/ -> b/ boundary.
        separator = payload.find(" b/", 2)
        if not payload.startswith("a/") or separator < 0:
            raise DiffParseError("diff --git header must contain two paths")
        paths = [payload[:separator], payload[separator + 1 :]]
    return _strip_git_prefix(paths[0]), _strip_git_prefix(paths[1])


def _metadata_path(line: str, prefix: str) -> str:
    value = line.removeprefix(prefix).strip()
    if value.startswith('"'):
        try:
            decoded = shlex.split(value, posix=True)
        except ValueError as exc:
            raise DiffParseError(f"malformed {prefix.strip()} path") from exc
        if len(decoded) != 1:
            raise DiffParseError(f"malformed {prefix.strip()} path")
        value = decoded[0]
    return _strip_git_prefix(value)


def _split_sections(raw_diff: str) -> tuple[tuple[str, ...], ...]:
    lines = tuple(raw_diff.splitlines())
    starts = [index for index, line in enumerate(lines) if line.startswith("diff --git ")]
    if not starts:
        raise DiffParseError("Git patch did not contain a diff --git section")
    starts.append(len(lines))
    return tuple(tuple(lines[start:end]) for start, end in zip(starts, starts[1:]))


def _classify_section(lines: tuple[str, ...]) -> _FileSection:
    if not lines or not lines[0].startswith("diff --git "):
        raise DiffParseError("file section is missing its diff header")
    old_path, new_path = _parse_diff_header(lines[0])
    change_type = ChangeType.MODIFIED
    rename_from: str | None = None
    rename_to: str | None = None
    patch_old: str | None = None
    patch_new: str | None = None
    is_binary = False

    for line in lines[1:]:
        if line.startswith("new file mode "):
            change_type = ChangeType.ADDED
        elif line.startswith("deleted file mode "):
            change_type = ChangeType.DELETED
        elif line.startswith("rename from "):
            rename_from = _metadata_path(line, "rename from ")
            change_type = ChangeType.RENAMED
        elif line.startswith("rename to "):
            rename_to = _metadata_path(line, "rename to ")
            change_type = ChangeType.RENAMED
        elif line.startswith("--- "):
            patch_old = _metadata_path(line, "--- ")
        elif line.startswith("+++ "):
            patch_new = _metadata_path(line, "+++ ")
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            is_binary = True

    if patch_old is not None and patch_old != "/dev/null":
        old_path = patch_old
    if patch_new is not None and patch_new != "/dev/null":
        new_path = patch_new
    if change_type is ChangeType.ADDED:
        old_path = None
    elif change_type is ChangeType.DELETED:
        new_path = None
    elif change_type is ChangeType.RENAMED:
        if rename_from is None or rename_to is None:
            raise DiffParseError("rename sections require rename from and rename to")
        old_path, new_path = rename_from, rename_to

    return _FileSection(
        old_path=old_path,
        new_path=new_path,
        change_type=change_type,
        is_binary=is_binary,
        text="\n".join(lines) + "\n",
        lines=lines,
    )


def _parse_hunk(
    section_lines: tuple[str, ...],
    start: int,
    file_id: str,
    ordinal: int,
) -> tuple[DiffHunk, int]:
    header = section_lines[start]
    match = _HUNK_HEADER.match(header)
    if match is None:
        raise DiffParseError("malformed unified diff hunk header")
    old_start = int(match.group(1))
    old_count = int(match.group(2) or "1")
    new_start = int(match.group(3))
    new_count = int(match.group(4) or "1")
    old_line = old_start
    new_line = new_start
    parsed_lines: list[DiffLine] = []
    index = start + 1
    observed_old = 0
    observed_new = 0

    while index < len(section_lines):
        line = section_lines[index]
        if line.startswith("@@ ") or line.startswith("diff --git "):
            break
        if line == "\\ No newline at end of file":
            index += 1
            continue
        if observed_old == old_count and observed_new == new_count:
            break
        if line.startswith("+"):
            parsed_lines.append(
                DiffLine(
                    kind=DiffLineKind.ADDITION,
                    content=line[1:],
                    old_line=None,
                    new_line=new_line,
                )
            )
            new_line += 1
            observed_new += 1
        elif line.startswith("-"):
            parsed_lines.append(
                DiffLine(
                    kind=DiffLineKind.DELETION,
                    content=line[1:],
                    old_line=old_line,
                    new_line=None,
                )
            )
            old_line += 1
            observed_old += 1
        elif line.startswith(" "):
            parsed_lines.append(
                DiffLine(
                    kind=DiffLineKind.CONTEXT,
                    content=line[1:],
                    old_line=old_line,
                    new_line=new_line,
                )
            )
            old_line += 1
            new_line += 1
            observed_old += 1
            observed_new += 1
        else:
            raise DiffParseError("unexpected line inside unified diff hunk")
        index += 1

    if observed_old != old_count or observed_new != new_count:
        raise DiffParseError("unified diff hunk ended before its declared ranges")
    hunk_id = _stable_id("hunk", f"{file_id}\0{ordinal}\0{header}")
    return (
        DiffHunk(
            hunk_id=hunk_id,
            header=header,
            old_start=old_start,
            old_count=old_count,
            new_start=new_start,
            new_count=new_count,
            lines=tuple(parsed_lines),
        ),
        index,
    )


def _parse_file(raw_lines: tuple[str, ...]) -> ParsedFileDiff:
    section = _classify_section(raw_lines)
    identity = f"{section.old_path or ''}\0{section.new_path or ''}\0{section.change_type}"
    file_id = _stable_id("file", identity)
    hunks: list[DiffHunk] = []
    index = 1
    while index < len(section.lines):
        if section.lines[index].startswith("@@ "):
            hunk, index = _parse_hunk(
                section.lines,
                index,
                file_id,
                len(hunks) + 1,
            )
            hunks.append(hunk)
        else:
            index += 1

    additions = sum(
        line.kind is DiffLineKind.ADDITION for hunk in hunks for line in hunk.lines
    )
    deletions = sum(
        line.kind is DiffLineKind.DELETION for hunk in hunks for line in hunk.lines
    )
    active_path = section.new_path or section.old_path
    if active_path is None:
        raise DiffParseError("file section did not resolve to an active path")
    language = "python" if active_path.lower().endswith((".py", ".pyi")) else "unknown"
    exclusion_reason: str | None = None
    if section.is_binary:
        exclusion_reason = "binary"
    elif language == "unknown":
        exclusion_reason = "unsupported_language"

    try:
        change = FileChange(
            file_id=file_id,
            old_path=section.old_path,
            new_path=section.new_path,
            change_type=section.change_type,
            language=language,
            additions=additions,
            deletions=deletions,
            is_binary=section.is_binary,
            content_hash=hashlib.sha256(section.text.encode("utf-8")).hexdigest(),
            hunk_ids=tuple(hunk.hunk_id for hunk in hunks),
        )
        return ParsedFileDiff(
            change=change,
            hunks=tuple(hunks),
            analysis_eligible=exclusion_reason is None,
            exclusion_reason=exclusion_reason,
        )
    except ValidationError as exc:
        raise DiffParseError("Git path or file metadata violated the input contract") from exc


def parse_unified_diff(raw_diff: str) -> tuple[ParsedFileDiff, ...]:
    """Parse one complete Git patch without truncating source lines."""

    return tuple(_parse_file(section) for section in _split_sections(raw_diff))
