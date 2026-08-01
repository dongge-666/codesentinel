"""Verify one clean runtime archive against the Skill's fixed deployment binding."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

MAX_MANIFEST_BYTES = 64 * 1024
SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEPLOYMENT_FIELDS = {
    "schema_name",
    "schema_version",
    "skill_name",
    "skill_version",
    "source_revision",
    "source_dirty",
    "runtime_bundle_ref",
    "runtime_bundle_sha256",
}


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("manifest contains duplicate keys")
        value[key] = item
    return value


def read_json_object(content: bytes, *, label: str) -> dict[str, Any]:
    if not content or len(content) > MAX_MANIFEST_BYTES:
        raise ValueError(f"{label} size is outside the allowed boundary")
    value = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def safe_shared_ref(value: object) -> str:
    if not isinstance(value, str) or "__" in value:
        raise ValueError("runtime bundle ref is missing or contains a placeholder")
    windows_path = PureWindowsPath(value)
    path = PurePosixPath(value)
    if (
        "\\" in value
        or value.startswith("/")
        or "//" in value
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ":" in value
        or path.as_posix() != value
        or not value.startswith("shared/")
        or any(part in {"", ".", ".."} or part.startswith(".") for part in path.parts)
    ):
        raise ValueError("runtime bundle ref is unsafe")
    return value


def verify(manifest_path: Path, runtime_path: Path, expected_skill: str) -> None:
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or not runtime_path.is_file()
        or runtime_path.is_symlink()
    ):
        raise ValueError("deployment manifest and runtime must be regular files")
    deployment = read_json_object(manifest_path.read_bytes(), label="deployment manifest")
    if set(deployment) != DEPLOYMENT_FIELDS:
        raise ValueError("deployment manifest fields do not match the frozen contract")
    if (
        deployment["schema_name"] != "CodeSentinelWorkerSkillDeployment"
        or deployment["schema_version"] != "1.0.0"
        or deployment["skill_version"] != "1.0.0"
        or deployment["skill_name"] != expected_skill
        or deployment["source_dirty"] is not False
    ):
        raise ValueError("deployment manifest identity is invalid")
    source_revision = deployment["source_revision"]
    expected_sha256 = deployment["runtime_bundle_sha256"]
    if not isinstance(source_revision, str) or not SHA1_PATTERN.fullmatch(source_revision):
        raise ValueError("deployment source revision must be a clean Git SHA-1")
    if not isinstance(expected_sha256, str) or not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ValueError("deployment runtime SHA-256 is invalid")
    runtime_ref = safe_shared_ref(deployment["runtime_bundle_ref"])
    if PurePosixPath(runtime_ref).name != runtime_path.name:
        raise ValueError("runtime filename does not match deployment ref")
    actual_sha256 = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError("runtime archive SHA-256 does not match deployment manifest")

    with zipfile.ZipFile(runtime_path) as archive:
        internal = read_json_object(
            archive.read("codesentinel/agentteams/runtime-manifest.json"),
            label="runtime manifest",
        )
    if (
        internal.get("source_revision") != source_revision
        or internal.get("source_dirty") is not False
        or internal.get("contract_version") != "1.0.0"
    ):
        raise ValueError("runtime internal manifest does not match clean deployment")


def main() -> int:
    if len(sys.argv) != 4:
        print("runtime binding verification failed", file=sys.stderr)
        return 64
    try:
        verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    except Exception:
        print("runtime binding verification failed", file=sys.stderr)
        return 2
    print("runtime binding verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
