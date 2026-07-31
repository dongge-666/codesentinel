"""Typed failures for the read-only Git diff boundary."""


class GitDiffError(RuntimeError):
    """Base class for expected P5 input-boundary failures."""


class RepositoryValidationError(GitDiffError):
    """Raised when the requested path is not an acceptable Git worktree root."""


class RevisionValidationError(GitDiffError):
    """Raised when a revision is unsafe, missing, or not commit-like."""


class DiffModeError(GitDiffError):
    """Raised when the requested staged/unstaged mode is unsupported or empty."""


class EmptyDiffError(GitDiffError):
    """Raised when the selected revision or worktree range has no changes."""


class GitCommandError(GitDiffError):
    """Raised when a read-only Git subprocess cannot complete safely."""


class DiffParseError(GitDiffError):
    """Raised when Git output cannot be mapped into the frozen input contract."""


class DiffSizeLimitError(GitDiffError):
    """Raised when the absolute byte safety limit is exceeded."""


class ArtifactBoundaryError(GitDiffError):
    """Raised when an artifact path could escape or modify the target repository."""
