"""Isolated Matrix control-plane probe for the P10-2 compatibility gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

_CONTROL_KEYS = {
    "schema_name",
    "schema_version",
    "event_type",
    "review_id",
    "trace_id",
    "task_id",
    "parent_task_id",
    "role",
    "attempt",
    "input_artifact",
    "deadline_at",
}
_FORBIDDEN_CONTROL_KEYS = {
    "files",
    "patch",
    "content",
    "source",
    "repository_path",
    "api_key",
    "access_token",
    "secret",
}


class MatrixProbeError(RuntimeError):
    """The isolated Matrix round trip or cleanup failed."""


def _json_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise MatrixProbeError("probe input must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MatrixProbeError("probe input is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise MatrixProbeError("probe input root must be an object")
    return value


def validate_control_output(path: str | Path) -> str:
    """Extract an allow-listed Matrix body from the runtime CLI output."""

    wrapper = _json_object(Path(path))
    if (
        wrapper.get("ok") is not True
        or wrapper.get("operation") != "build-control"
        or wrapper.get("artifact_transport") != "minio"
        or wrapper.get("model_calls") != 0
    ):
        raise MatrixProbeError("control wrapper does not meet the P10-2 boundary")
    text = wrapper.get("matrix_text")
    if not isinstance(text, str) or len(text.encode("utf-8")) > 4096:
        raise MatrixProbeError("Matrix control text is invalid or oversized")
    try:
        control = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MatrixProbeError("Matrix control text is not JSON") from exc
    if not isinstance(control, dict) or set(control) != _CONTROL_KEYS:
        raise MatrixProbeError("Matrix control keys do not match the allow-list")

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) & _FORBIDDEN_CONTROL_KEYS:
                raise MatrixProbeError("Matrix control contains a data-plane key")
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(control)
    return text


def _matrix_request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urlopen(request, timeout=15) as response:  # noqa: S310
            value = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise MatrixProbeError(f"Matrix request returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise MatrixProbeError("Matrix request transport failed") from exc
    if not isinstance(value, dict):
        raise MatrixProbeError("Matrix response root must be an object")
    return value


def run_probe(config_path: str | Path, control_path: str | Path) -> dict[str, Any]:
    """Round-trip one custom event in an agent-free private room and clean up."""

    config = _json_object(Path(config_path))
    try:
        matrix = config["channels"]["matrix"]
        configured_homeserver = matrix.get("homeserver", "")
        homeserver = (
            os.environ.get("HICLAW_MATRIX_URL") or configured_homeserver
        ).rstrip("/")
        token = matrix.get("access_token") or matrix.get("accessToken")
    except (KeyError, TypeError, AttributeError) as exc:
        raise MatrixProbeError("Matrix channel configuration is incomplete") from exc
    if not isinstance(homeserver, str) or not homeserver.startswith(("http://", "https://")):
        raise MatrixProbeError("Matrix homeserver URL is invalid")
    if not isinstance(token, str) or not token:
        raise MatrixProbeError("Matrix access token is unavailable")

    control_text = validate_control_output(control_path)
    room_id: str | None = None
    event_id: str | None = None
    cleanup_complete = False
    cleanup_stage = "not-started"
    cleanup_detail = "none"
    room_forgotten = False
    try:
        created = _matrix_request(
            "POST",
            f"{homeserver}/_matrix/client/v3/createRoom",
            token,
            {
                "visibility": "private",
                "preset": "private_chat",
                "is_direct": False,
                "invite": [],
                "name": f"CodeSentinel P10-2 {uuid.uuid4().hex[:12]}",
            },
        )
        room_id = created.get("room_id")
        if not isinstance(room_id, str) or not room_id:
            raise MatrixProbeError("Matrix did not return a room ID")
        transaction_id = f"codesentinel-p10-2-{uuid.uuid4().hex}"
        event_type = "com.codesentinel.compat.control.v1"
        room = quote(room_id, safe="")
        sent_content = {
            "body": control_text,
            "content_type": "application/vnd.codesentinel.control+json",
        }
        sent = _matrix_request(
            "PUT",
            (
                f"{homeserver}/_matrix/client/v3/rooms/{room}/send/"
                f"{event_type}/{transaction_id}"
            ),
            token,
            sent_content,
        )
        event_id = sent.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise MatrixProbeError("Matrix did not return an event ID")
        fetched = _matrix_request(
            "GET",
            (
                f"{homeserver}/_matrix/client/v3/rooms/{room}/event/"
                f"{quote(event_id, safe='')}"
            ),
            token,
            None,
        )
        if fetched.get("type") != event_type or fetched.get("content") != sent_content:
            raise MatrixProbeError("Matrix round-trip content did not match")
    finally:
        if room_id is not None:
            room = quote(room_id, safe="")
            try:
                cleanup_stage = "leave"
                _matrix_request(
                    "POST",
                    f"{homeserver}/_matrix/client/v3/rooms/{room}/leave",
                    token,
                    {},
                )
                cleanup_stage = "sync-after-leave"
                sync = _matrix_request(
                    "GET",
                    f"{homeserver}/_matrix/client/v3/sync?timeout=0",
                    token,
                    None,
                )
                joined = sync.get("rooms", {}).get("join", {})
                if not isinstance(joined, dict) or room_id in joined:
                    raise MatrixProbeError("room remained joined after leave")
                cleanup_complete = True
                cleanup_stage = "forget"
                try:
                    _matrix_request(
                        "POST",
                        f"{homeserver}/_matrix/client/v3/rooms/{room}/forget",
                        token,
                        {},
                    )
                    room_forgotten = True
                    cleanup_detail = "forgotten"
                except MatrixProbeError as exc:
                    cleanup_detail = str(exc)
                cleanup_stage = "complete"
            except MatrixProbeError as exc:
                cleanup_complete = False
                cleanup_detail = str(exc)
    if event_id is None or not cleanup_complete:
        room_reference = room_id or "not-created"
        raise MatrixProbeError(
            f"Matrix cleanup failed at {cleanup_stage} ({cleanup_detail}); "
            f"room={room_reference}"
        )
    return {
        "ok": True,
        "operation": "matrix-control-round-trip",
        "event_type": "com.codesentinel.compat.control.v1",
        "event_id": event_id,
        "body_sha256": hashlib.sha256(control_text.encode("utf-8")).hexdigest(),
        "matrix_bytes": len(control_text.encode("utf-8")),
        "round_trip_equal": True,
        "cleanup_complete": True,
        "room_forgotten": room_forgotten,
        "forget_detail": cleanup_detail,
        "invited_agents": 0,
        "model_calls": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codesentinel-p10-2-matrix-probe")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--control-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.config, args.control_output)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "operation": "matrix-control-round-trip",
                    "error_code": "MATRIX_PROBE_FAILED",
                    "error_type": type(exc).__name__,
                    "error_stage": str(exc)[:120],
                    "model_calls": 0,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
