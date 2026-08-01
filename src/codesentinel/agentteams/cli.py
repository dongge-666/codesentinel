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

from .assignment import (
    load_and_validate_assignment,
    load_and_validate_role_context,
    validate_delivery_against_assignment,
)
from .delivery import build_worker_delivery, load_role_payload, write_delivery_atomic
from .models import BUNDLE_VERSION, CONTRACT_VERSION
from .serialization import canonical_json_bytes, sha256_hex
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
        expected_attempt=args.attempt,
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


def _validate_assigned_delivery(args: argparse.Namespace) -> dict[str, Any]:
    request = load_and_validate_request(
        args.request,
        args.artifact,
        now=_parse_utc(args.now),
    )
    assignment = load_and_validate_assignment(
        args.assignment,
        request,
        now=_parse_utc(args.now),
    )
    context = load_and_validate_role_context(args.context, assignment)
    delivery = load_and_validate_delivery(args.delivery)
    validate_delivery_against_assignment(delivery, request, assignment, context)
    return {
        "ok": True,
        "operation": "validate-assigned-delivery",
        "review_id": delivery.review_id,
        "trace_id": delivery.trace_id,
        "task_id": delivery.task_id,
        "role": delivery.role,
        "attempt": delivery.attempt,
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


def _build_delivery(args: argparse.Namespace) -> dict[str, Any]:
    request = load_and_validate_request(
        args.request,
        args.artifact,
        now=_parse_utc(args.now),
    )
    assignment = load_and_validate_assignment(
        args.assignment,
        request,
        now=_parse_utc(args.now),
    )
    context = load_and_validate_role_context(args.context, assignment)
    payload = load_role_payload(args.payload, role=assignment.role)
    delivery = build_worker_delivery(
        request,
        assignment=assignment,
        context=context,
        payload=payload,
        started_at=_parse_utc(args.started_at),
        finished_at=_parse_utc(args.finished_at),
        status=args.status,
        model_calls=args.model_calls,
    )
    destination = write_delivery_atomic(
        delivery,
        args.delivery,
        assignment=assignment,
        artifact_root=args.artifact_root,
    )
    return {
        "ok": True,
        "operation": "build-delivery",
        "review_id": delivery.review_id,
        "trace_id": delivery.trace_id,
        "task_id": delivery.task_id,
        "role": delivery.role,
        "attempt": delivery.attempt,
        "delivery": destination.name,
        "delivery_sha256": sha256_hex(destination.read_bytes()),
        "output_sha256": delivery.output_sha256,
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
            command.add_argument("--attempt", type=int, choices=(1, 2), required=True)
        command.set_defaults(handler=handler)

    assigned_delivery = commands.add_parser("validate-assigned-delivery")
    assigned_delivery.add_argument("--request", type=Path, required=True)
    assigned_delivery.add_argument("--artifact", type=Path, required=True)
    assigned_delivery.add_argument("--assignment", type=Path, required=True)
    assigned_delivery.add_argument("--context", type=Path, required=True)
    assigned_delivery.add_argument("--delivery", type=Path, required=True)
    assigned_delivery.add_argument("--now", required=True)
    assigned_delivery.set_defaults(handler=_validate_assigned_delivery)

    build_delivery = commands.add_parser("build-delivery")
    build_delivery.add_argument("--request", type=Path, required=True)
    build_delivery.add_argument("--artifact", type=Path, required=True)
    build_delivery.add_argument("--payload", type=Path, required=True)
    build_delivery.add_argument("--assignment", type=Path, required=True)
    build_delivery.add_argument("--context", type=Path, required=True)
    build_delivery.add_argument("--delivery", type=Path, required=True)
    build_delivery.add_argument("--artifact-root", type=Path, required=True)
    build_delivery.add_argument("--now", required=True)
    build_delivery.add_argument("--started-at", required=True)
    build_delivery.add_argument("--finished-at", required=True)
    build_delivery.add_argument(
        "--status",
        choices=("SUCCESS", "SUCCESS_WITH_NOTES", "REVISION_NEEDED"),
        default="SUCCESS",
    )
    build_delivery.add_argument("--model-calls", type=int, choices=(1,), default=1)
    build_delivery.set_defaults(handler=_build_delivery)
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
