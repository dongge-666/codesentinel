"""Zero-model compatibility CLI embedded in the P10 runtime bundle."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import pydantic

from .models import BUNDLE_VERSION, CONTRACT_VERSION
from .serialization import canonical_json_bytes
from .validation import (
    build_assignment_control,
    load_and_validate_delivery,
    load_and_validate_request,
    validate_delivery_against_request,
)


def _runtime_manifest() -> dict[str, Any]:
    try:
        content = (
            resources.files("codesentinel.agentteams")
            .joinpath("runtime-manifest.json")
            .read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        return {
            "bundle_version": BUNDLE_VERSION,
            "contract_version": CONTRACT_VERSION,
            "packaging": "source",
        }
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("runtime manifest must be an object")
    return value


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value))


def _self_check(_: argparse.Namespace) -> dict[str, Any]:
    pydantic_parts = tuple(int(part) for part in pydantic.__version__.split(".")[:2])
    compatible = sys.version_info[:2] == (3, 11) and (2, 13) <= pydantic_parts < (3, 0)
    if not compatible:
        raise RuntimeError("runtime dependency compatibility check failed")
    manifest = _runtime_manifest()
    return {
        "ok": True,
        "operation": "self-check",
        "bundle_version": manifest.get("bundle_version"),
        "contract_version": manifest.get("contract_version"),
        "source_revision": manifest.get("source_revision"),
        "source_dirty": manifest.get("source_dirty"),
        "python": platform.python_version(),
        "pydantic": pydantic.__version__,
        "model_calls": 0,
    }


def _validate_request(args: argparse.Namespace) -> dict[str, Any]:
    request = load_and_validate_request(
        args.request,
        args.artifact,
        now=_parse_utc(args.now),
    )
    return {
        "ok": True,
        "operation": "validate-request",
        "review_id": request.review_id,
        "trace_id": request.trace_id,
        "input_artifact_ref": request.input_artifact_ref,
        "input_sha256": request.input_sha256,
        "model_calls": 0,
    }


def _validate_delivery(args: argparse.Namespace) -> dict[str, Any]:
    request = load_and_validate_request(
        args.request,
        args.artifact,
        now=_parse_utc(args.now),
    )
    delivery = load_and_validate_delivery(args.delivery)
    validate_delivery_against_request(
        delivery,
        request,
        expected_role=args.role,
        expected_task_id=args.task_id,
    )
    return {
        "ok": True,
        "operation": "validate-delivery",
        "review_id": delivery.review_id,
        "trace_id": delivery.trace_id,
        "task_id": delivery.task_id,
        "role": delivery.role,
        "output_sha256": delivery.output_sha256,
        "model_calls": 0,
    }


def _build_control(args: argparse.Namespace) -> dict[str, Any]:
    request = load_and_validate_request(
        args.request,
        args.artifact,
        now=_parse_utc(args.now),
    )
    control = build_assignment_control(
        request,
        task_id=args.task_id,
        role=args.role,
    )
    return {
        "ok": True,
        "operation": "build-control",
        "matrix_text": control.to_matrix_text(),
        "matrix_bytes": len(control.to_matrix_text().encode("utf-8")),
        "artifact_transport": "minio",
        "model_calls": 0,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codesentinel-agentteams-runtime")
    commands = parser.add_subparsers(dest="command", required=True)

    self_check = commands.add_parser("self-check")
    self_check.set_defaults(handler=_self_check)

    for name, handler in (
        ("validate-request", _validate_request),
        ("validate-delivery", _validate_delivery),
        ("build-control", _build_control),
    ):
        command = commands.add_parser(name)
        command.add_argument("--request", type=Path, required=True)
        command.add_argument("--artifact", type=Path, required=True)
        command.add_argument("--now", required=True)
        if name != "validate-request":
            command.add_argument("--task-id", required=True)
            command.add_argument(
                "--role",
                choices=("diff_analyzer", "security_scanner", "quality_reviewer"),
                required=True,
            )
        if name == "validate-delivery":
            command.add_argument("--delivery", type=Path, required=True)
        command.set_defaults(handler=handler)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except Exception as exc:
        _emit(
            {
                "ok": False,
                "operation": getattr(args, "command", "unknown"),
                "error_code": "COMPATIBILITY_VALIDATION_FAILED",
                "error_type": type(exc).__name__,
                "model_calls": 0,
            }
        )
        return 2
    _emit(result)
    return 0
