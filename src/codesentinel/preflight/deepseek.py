"""Safe DeepSeek API preflight for CodeSentinel P2.

The preflight validates plain chat, JSON output, and tool calling without
persisting prompts, model content, or credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-pro"
PREFLIGHT_SCHEMA_VERSION = "1.0.0"
TOOL_NAME = "record_preflight_result"


class MissingApiKeyError(RuntimeError):
    """Raised when no DeepSeek API key is available."""


class PreflightSettings(BaseModel):
    """Validated settings loaded from a local environment."""

    model_config = ConfigDict(extra="forbid")

    api_key: str = Field(min_length=1, repr=False)
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout_seconds: float = Field(default=45.0, gt=0, le=120)


class JsonProbePayload(BaseModel):
    """Expected response for the JSON-output probe."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    code: Literal[2026]
    component: Literal["codesentinel"]


class ToolProbeArguments(BaseModel):
    """Expected arguments for the tool-call probe."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    component: Literal["codesentinel"]


class ProbeResult(BaseModel):
    """Redacted metadata for one live probe."""

    model_config = ConfigDict(extra="forbid")

    name: Literal["chat", "json_output", "tool_call"]
    status: Literal["passed", "failed", "skipped"]
    latency_ms: int = Field(ge=0)
    response_model: str | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    error_type: str | None = None
    error_message: str | None = None


class PreflightReport(BaseModel):
    """Secret-free report persisted under ignored runtime artifacts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = PREFLIGHT_SCHEMA_VERSION
    status: Literal["passed", "failed"]
    base_url: str
    requested_model: str
    started_at: datetime
    completed_at: datetime
    probes: list[ProbeResult]


def load_settings(env_file: Path | None = None) -> PreflightSettings:
    """Load a key without printing it or searching parent directories."""

    selected_env = env_file if env_file is not None else Path.cwd() / ".env"
    if selected_env.is_file():
        load_dotenv(dotenv_path=selected_env, override=False)

    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise MissingApiKeyError(
            "DEEPSEEK_API_KEY is not configured. Add it locally to the ignored "
            ".env file or a temporary environment variable; never send it in chat."
        )

    return PreflightSettings(
        api_key=api_key,
        base_url=os.getenv("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL).strip(),
        model=os.getenv("DEEPSEEK_MODEL", DEFAULT_MODEL).strip(),
    )


def sanitize_error(message: str, api_key: str) -> str:
    """Remove credential-shaped values from an exception message."""

    sanitized = message.replace(api_key, "[REDACTED]") if api_key else message
    sanitized = re.sub(
        r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+",
        r"\1[REDACTED]",
        sanitized,
    )
    sanitized = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED]", sanitized)
    sanitized = re.sub(
        r"(?i)(https?://)[^/\s@]+@",
        r"\1[REDACTED]@",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)([?&](?:api[_-]?key|access_token|token|key)=)[^&#\s]+",
        r"\1[REDACTED]",
        sanitized,
    )
    return sanitized[:1000]


def public_base_url(base_url: str) -> str:
    """Return only a non-sensitive URL origin for persisted diagnostics."""

    try:
        parsed = urlsplit(base_url)
        if not parsed.scheme or not parsed.hostname:
            return "[INVALID_URL]"
        hostname = (
            f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        )
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme.lower()}://{hostname}{port}"
    except ValueError:
        return "[INVALID_URL]"


def _usage(response: Any) -> tuple[int | None, int | None, int | None]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return None, None, None
    return (
        getattr(usage, "prompt_tokens", None),
        getattr(usage, "completion_tokens", None),
        getattr(usage, "total_tokens", None),
    )


def _passed_result(name: str, response: Any, started: float) -> ProbeResult:
    prompt_tokens, completion_tokens, total_tokens = _usage(response)
    return ProbeResult(
        name=name,
        status="passed",
        latency_ms=round((time.perf_counter() - started) * 1000),
        response_model=getattr(response, "model", None),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
    )


def _chat_probe(client: Any, model: str) -> ProbeResult:
    started = time.perf_counter()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "Return only the exact requested text. Do not add explanation.",
            },
            {"role": "user", "content": "Return exactly: CODESENTINEL_OK"},
        ],
        temperature=0,
        max_tokens=32,
        stream=False,
        extra_body={"thinking": {"type": "disabled"}},
    )
    content = response.choices[0].message.content
    if not isinstance(content, str) or content.strip() != "CODESENTINEL_OK":
        raise ValueError("Chat probe returned unexpected content.")
    return _passed_result("chat", response, started)


def _json_probe(client: Any, model: str) -> ProbeResult:
    started = time.perf_counter()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    "Return valid json only. Required example: "
                    '{"status":"ok","code":2026,"component":"codesentinel"}.'
                ),
            },
            {
                "role": "user",
                "content": (
                    "Return the example json object with exactly those three fields "
                    "and values."
                ),
            },
        ],
        response_format={"type": "json_object"},
        temperature=0,
        max_tokens=96,
        stream=False,
        extra_body={"thinking": {"type": "disabled"}},
    )
    content = response.choices[0].message.content
    if not isinstance(content, str) or not content.strip():
        raise ValueError("JSON probe returned empty content.")
    JsonProbePayload.model_validate_json(content)
    return _passed_result("json_output", response, started)


def _tool_probe(client: Any, model: str) -> ProbeResult:
    started = time.perf_counter()
    tools = [
        {
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": "Record a successful CodeSentinel API preflight.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["ok"]},
                        "component": {"type": "string", "enum": ["codesentinel"]},
                    },
                    "required": ["status", "component"],
                    "additionalProperties": False,
                },
            },
        }
    ]
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": (
                    "Call record_preflight_result with status ok and component "
                    "codesentinel. Do not answer with normal text."
                ),
            }
        ],
        tools=tools,
        temperature=0,
        max_tokens=128,
        stream=False,
        extra_body={"thinking": {"type": "disabled"}},
    )
    tool_calls = response.choices[0].message.tool_calls or []
    if len(tool_calls) != 1:
        raise ValueError("Tool probe did not return exactly one tool call.")
    function = tool_calls[0].function
    if function.name != TOOL_NAME:
        raise ValueError("Tool probe returned an unexpected tool name.")
    ToolProbeArguments.model_validate_json(function.arguments)
    return _passed_result("tool_call", response, started)


Probe = Callable[[Any, str], ProbeResult]


def run_preflight(
    settings: PreflightSettings,
    client_factory: Callable[..., Any] = OpenAI,
) -> PreflightReport:
    """Execute three live probes and return only redacted metadata."""

    started_at = datetime.now(UTC)
    client_started = time.perf_counter()
    try:
        client = client_factory(
            api_key=settings.api_key,
            base_url=settings.base_url,
            timeout=settings.timeout_seconds,
            max_retries=0,
        )
    except Exception as exc:
        error_message = sanitize_error(str(exc), settings.api_key)
        probes = [
            ProbeResult(
                name="chat",
                status="failed",
                latency_ms=round((time.perf_counter() - client_started) * 1000),
                error_type=type(exc).__name__,
                error_message=error_message,
            ),
            ProbeResult(
                name="json_output",
                status="skipped",
                latency_ms=0,
                error_type="ClientInitializationError",
                error_message="Skipped because the API client could not be initialized.",
            ),
            ProbeResult(
                name="tool_call",
                status="skipped",
                latency_ms=0,
                error_type="ClientInitializationError",
                error_message="Skipped because the API client could not be initialized.",
            ),
        ]
        return PreflightReport(
            status="failed",
            base_url=public_base_url(settings.base_url),
            requested_model=settings.model,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            probes=probes,
        )

    probes: list[ProbeResult] = []
    checks: tuple[tuple[str, Probe], ...] = (
        ("chat", _chat_probe),
        ("json_output", _json_probe),
        ("tool_call", _tool_probe),
    )

    for name, check in checks:
        started = time.perf_counter()
        try:
            probes.append(check(client, settings.model))
        except Exception as exc:  # The SDK exposes several provider-specific errors.
            probes.append(
                ProbeResult(
                    name=name,
                    status="failed",
                    latency_ms=round((time.perf_counter() - started) * 1000),
                    error_type=type(exc).__name__,
                    error_message=sanitize_error(str(exc), settings.api_key),
                )
            )

    return PreflightReport(
        status="passed" if all(probe.status == "passed" for probe in probes) else "failed",
        base_url=public_base_url(settings.base_url),
        requested_model=settings.model,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        probes=probes,
    )


def write_report(report: PreflightReport, report_dir: Path) -> Path:
    """Persist a redacted JSON report under an ignored artifact directory."""

    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = report.completed_at.strftime("%Y%m%dT%H%M%SZ")
    target = report_dir / f"deepseek-preflight-{timestamp}.json"
    target.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CodeSentinel DeepSeek P2 preflight.")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path.cwd() / ".env",
        help="Ignored local env file. Defaults to ./.env.",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path.cwd() / "artifacts" / "preflight",
        help="Directory for the redacted preflight report.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        settings = load_settings(args.env_file)
    except MissingApiKeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    report = run_preflight(settings)
    report_path = write_report(report, args.report_dir)

    print(f"DeepSeek preflight: {report.status.upper()}")
    for probe in report.probes:
        tokens = probe.total_tokens if probe.total_tokens is not None else "n/a"
        print(
            f"- {probe.name}: {probe.status}; "
            f"latency_ms={probe.latency_ms}; total_tokens={tokens}"
        )
        if probe.error_message:
            print(f"  error={probe.error_type}: {probe.error_message}")
    print(f"Redacted report: {report_path}")
    return 0 if report.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
