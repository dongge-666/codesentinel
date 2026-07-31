"""Public P5 API for safe local Git input and artifact persistence."""

from .artifacts import ArtifactStore, PersistedRun
from .errors import (
    ArtifactBoundaryError,
    DiffModeError,
    DiffParseError,
    DiffSizeLimitError,
    EmptyDiffError,
    GitCommandError,
    GitDiffError,
    RepositoryValidationError,
    RevisionValidationError,
)
from .models import (
    DiffHunk,
    DiffLine,
    DiffLineKind,
    DiffSource,
    GitDiffArtifact,
    ParsedFileDiff,
    TraceEvent,
)
from .reader import DEFAULT_MAX_DIFF_BYTES, GitDiffReader

__all__ = [
    "ArtifactBoundaryError",
    "ArtifactStore",
    "DEFAULT_MAX_DIFF_BYTES",
    "DiffHunk",
    "DiffLine",
    "DiffLineKind",
    "DiffModeError",
    "DiffParseError",
    "DiffSizeLimitError",
    "DiffSource",
    "EmptyDiffError",
    "GitCommandError",
    "GitDiffArtifact",
    "GitDiffError",
    "GitDiffReader",
    "ParsedFileDiff",
    "PersistedRun",
    "RepositoryValidationError",
    "RevisionValidationError",
    "TraceEvent",
]
