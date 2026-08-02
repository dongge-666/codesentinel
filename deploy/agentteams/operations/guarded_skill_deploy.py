"""Offline-only entry point for the R2-1 deployment guard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from codesentinel.agentteams.deploy_guard import (  # noqa: E402
    APPROVED_SKILL,
    APPROVED_WORKER,
    EXPECTED_OFFICIAL_SCRIPT_SHA256,
    EXPECTED_PACKAGE_FILES,
    build_package_manifest_from_directory,
)
from codesentinel.agentteams.serialization import canonical_json_bytes  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guarded-skill-deploy",
        description=(
            "R2-1 offline guard inspection. This entry point has no live "
            "Docker, MinIO, Matrix, Heartbeat, or deployment action."
        ),
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("self-check")
    inspect_parser = subparsers.add_parser("inspect-package")
    inspect_parser.add_argument("--package-root", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.operation == "self-check":
        payload = {
            "approved_mapping": {
                "skill": APPROVED_SKILL,
                "worker": APPROVED_WORKER,
            },
            "expected_files": sorted(EXPECTED_PACKAGE_FILES),
            "live_execution_available": False,
            "model_calls": 0,
            "official_script_sha256": EXPECTED_OFFICIAL_SCRIPT_SHA256,
            "ok": True,
            "operation": "self-check",
        }
    else:
        manifest = build_package_manifest_from_directory(args.package_root)
        payload = {
            "live_execution_available": False,
            "manifest": manifest.model_dump(mode="json"),
            "model_calls": 0,
            "ok": True,
            "operation": "inspect-package",
        }
    print(canonical_json_bytes(payload).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
