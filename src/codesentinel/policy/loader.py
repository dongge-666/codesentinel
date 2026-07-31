"""Version-locked loading for bundled CodeSentinel gate policies."""

from __future__ import annotations

import hashlib
import tomllib
from importlib import resources
from pathlib import Path

from pydantic import ValidationError

from .models import PolicyDocument

DEFAULT_POLICY_VERSION = "mvp-1.0.0"
EXPECTED_POLICY_DIGESTS = {
    DEFAULT_POLICY_VERSION: "3d222b317b56a2d793776f3826c5f682d8b37902599246e57c8954cd25909852",
}


class PolicyLoadError(RuntimeError):
    """Raised when policy data is absent, unsupported, malformed, or modified."""


def _read_bundled_policy(version: str) -> bytes:
    resource = resources.files("codesentinel.policies").joinpath(f"{version}.toml")
    try:
        return resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise PolicyLoadError("Bundled policy is unavailable.") from exc


def load_policy(
    version: str = DEFAULT_POLICY_VERSION,
    *,
    policy_path: Path | None = None,
) -> PolicyDocument:
    """Load and integrity-check a known policy without executable expressions."""

    if version not in EXPECTED_POLICY_DIGESTS:
        raise PolicyLoadError("Unsupported policy version.")
    if policy_path is None:
        raw = _read_bundled_policy(version)
    else:
        if policy_path.name != f"{version}.toml":
            raise PolicyLoadError("Policy filename does not match the requested version.")
        try:
            raw = policy_path.read_bytes()
        except OSError as exc:
            raise PolicyLoadError("Policy file is unavailable.") from exc

    actual_digest = hashlib.sha256(raw).hexdigest()
    if actual_digest != EXPECTED_POLICY_DIGESTS[version]:
        raise PolicyLoadError("Policy integrity verification failed.")

    try:
        payload = tomllib.loads(raw.decode("utf-8"))
        document = PolicyDocument.model_validate(payload)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise PolicyLoadError("Policy document is malformed.") from exc

    if document.schema_version != "1.0.0" or document.policy_version != version:
        raise PolicyLoadError("Policy document version metadata is inconsistent.")
    return document
