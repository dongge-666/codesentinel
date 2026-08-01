"""Build a deterministic, dependency-light AgentTeams runtime bundle."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .models import BUNDLE_VERSION, CONTRACT_VERSION
from .serialization import canonical_json_bytes, sha256_hex

ARCHIVE_NAME = f"codesentinel-agentteams-runtime-{BUNDLE_VERSION}.pyz"
MANIFEST_NAME = f"codesentinel-agentteams-runtime-{BUNDLE_VERSION}.manifest.json"
_RUNTIME_MODULES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "models.py",
    "serialization.py",
    "validation.py",
)
_ROOT_MAIN = b"from codesentinel.agentteams.cli import main\nraise SystemExit(main())\n"
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class BundleBuildResult:
    archive_path: Path
    manifest_path: Path
    archive_sha256: str
    archive_size: int
    source_revision: str
    source_dirty: bool


def _git(repository_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _source_entries(repository_root: Path) -> dict[str, bytes]:
    package_root = repository_root / "src" / "codesentinel" / "agentteams"
    entries = {
        "__main__.py": _ROOT_MAIN,
        "LICENSE": (repository_root / "LICENSE").read_bytes(),
        "codesentinel/__init__.py": (
            repository_root / "src" / "codesentinel" / "__init__.py"
        ).read_bytes(),
    }
    for name in _RUNTIME_MODULES:
        source = package_root / name
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"runtime source is missing or unsafe: {name}")
        entries[f"codesentinel/agentteams/{name}"] = source.read_bytes()
    return entries


def _zip_entry(name: str, content: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o644 & 0xFFFF) << 16
    info.create_system = 3
    return info, content


def build_runtime_bundle(
    repository_root: str | Path,
    output_directory: str | Path,
) -> BundleBuildResult:
    root = Path(repository_root).resolve(strict=True)
    output = Path(output_directory).resolve(strict=False)
    if not (root / "pyproject.toml").is_file():
        raise ValueError("repository root does not contain pyproject.toml")
    source_revision = _git(root, "rev-parse", "HEAD")
    source_entries = _source_entries(root)
    source_dirty = bool(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "--",
            "LICENSE",
            "src/codesentinel/__init__.py",
            "src/codesentinel/agentteams",
        )
    )
    source_hashes = {
        name: sha256_hex(content) for name, content in sorted(source_entries.items())
    }
    internal_manifest = {
        "schema_name": "CodeSentinelAgentTeamsRuntimeManifest",
        "schema_version": "1.0.0",
        "bundle_version": BUNDLE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "source_revision": source_revision,
        "source_dirty": source_dirty,
        "required_python": ">=3.11,<3.12",
        "required_pydantic": ">=2.13,<3",
        "source_files": source_hashes,
    }
    source_entries["codesentinel/agentteams/runtime-manifest.json"] = (
        canonical_json_bytes(internal_manifest)
    )
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / ARCHIVE_NAME
    manifest_path = output / MANIFEST_NAME
    with tempfile.NamedTemporaryFile(
        dir=output,
        prefix=f".{ARCHIVE_NAME}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(
            temporary_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, content in sorted(source_entries.items()):
                info, payload = _zip_entry(name, content)
                archive.writestr(info, payload)
        archive_bytes = temporary_path.read_bytes()
        archive_sha256 = sha256_hex(archive_bytes)
        os.replace(temporary_path, archive_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    external_manifest = {
        **internal_manifest,
        "archive_name": ARCHIVE_NAME,
        "archive_sha256": archive_sha256,
        "archive_size": archive_path.stat().st_size,
    }
    temporary_manifest = manifest_path.with_name(f".{manifest_path.name}.tmp")
    try:
        temporary_manifest.write_bytes(canonical_json_bytes(external_manifest))
        os.replace(temporary_manifest, manifest_path)
    finally:
        if temporary_manifest.exists():
            temporary_manifest.unlink()
    return BundleBuildResult(
        archive_path=archive_path,
        manifest_path=manifest_path,
        archive_sha256=archive_sha256,
        archive_size=archive_path.stat().st_size,
        source_revision=source_revision,
        source_dirty=source_dirty,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codesentinel-agentteams-bundle")
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    result = build_runtime_bundle(args.repository_root, args.output_directory)
    print(
        canonical_json_bytes(
            {
                "archive": result.archive_path.name,
                "archive_sha256": result.archive_sha256,
                "archive_size": result.archive_size,
                "manifest": result.manifest_path.name,
                "source_revision": result.source_revision,
                "source_dirty": result.source_dirty,
            }
        ).decode("utf-8"),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
