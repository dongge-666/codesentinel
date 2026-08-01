"""Allow-listed local adapters for detect-secrets and Bandit."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Protocol

from detect_secrets.core import scan as detect_secrets_scan
from detect_secrets.settings import default_settings

from .base import SkillExecutionError
from .common import SourceLine
from .models import SkillErrorCode


@dataclass(frozen=True)
class SecretObservation:
    source_line: SourceLine
    secret_type: str
    secret_value: str
    upstream_hash: str


class DetectSecretsAdapter(Protocol):
    version: str

    def scan(self, lines: tuple[SourceLine, ...]) -> tuple[SecretObservation, ...]: ...


class DefaultDetectSecretsAdapter:
    """Run detect-secrets in memory and immediately discard upstream plaintext."""

    version = metadata.version("detect-secrets")

    def scan(self, lines: tuple[SourceLine, ...]) -> tuple[SecretObservation, ...]:
        observations: list[SecretObservation] = []
        try:
            with default_settings():
                for source_line in lines:
                    for secret in detect_secrets_scan.scan_line(source_line.content):
                        secret_value = secret.secret_value
                        if not secret_value:
                            continue
                        observations.append(
                            SecretObservation(
                                source_line=source_line,
                                secret_type=secret.type,
                                secret_value=secret_value,
                                upstream_hash=secret.secret_hash,
                            )
                        )
                        secret.secret_value = None
        except Exception as exc:
            raise SkillExecutionError(
                SkillErrorCode.TOOL_ERROR,
                "detect-secrets adapter failed",
            ) from exc
        return tuple(observations)


@dataclass(frozen=True)
class BanditObservation:
    source_line: SourceLine
    test_id: str
    severity: str
    confidence: str
    safe_message: str


class BanditAdapter(Protocol):
    version: str

    def scan(self, lines: tuple[SourceLine, ...]) -> tuple[BanditObservation, ...]: ...


_BANDIT_MESSAGES = {
    "B102": "Use of exec detected by Bandit.",
    "B307": "Use of eval detected by Bandit.",
    "B602": "Subprocess call with shell=True detected by Bandit.",
    "B604": "Function call with shell=True detected by Bandit.",
    "B605": "Shell process start detected by Bandit.",
    "B606": "Process start without a shell detected by Bandit.",
}


class DefaultBanditAdapter:
    """Run Bandit's stable JSON CLI against a short-lived synthetic module."""

    version = metadata.version("bandit")

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        self._timeout_seconds = timeout_seconds

    def scan(self, lines: tuple[SourceLine, ...]) -> tuple[BanditObservation, ...]:
        synthetic_lines: list[str] = []
        line_map: dict[int, SourceLine] = {}
        for source_line in lines:
            candidate = textwrap.dedent(source_line.content).strip()
            if not candidate:
                continue
            try:
                parsed = ast.parse(candidate)
            except SyntaxError:
                continue
            if len(parsed.body) != 1 or "\n" in candidate:
                continue
            synthetic_lines.append(candidate)
            line_map[len(synthetic_lines)] = source_line
        if not synthetic_lines:
            return ()

        environment = os.environ.copy()
        environment.update({"PYTHONUTF8": "1", "NO_COLOR": "1"})
        try:
            with tempfile.TemporaryDirectory(prefix="codesentinel-bandit-") as directory:
                target = Path(directory) / "diff_lines.py"
                target.write_text("\n".join(synthetic_lines) + "\n", encoding="utf-8")
                try:
                    target.chmod(0o600)
                except OSError:
                    pass
                completed = subprocess.run(
                    [sys.executable, "-m", "bandit", "-q", "-f", "json", str(target)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=self._timeout_seconds,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
        except subprocess.TimeoutExpired as exc:
            raise SkillExecutionError(SkillErrorCode.TIMEOUT, "Bandit timed out") from exc
        except OSError as exc:
            raise SkillExecutionError(
                SkillErrorCode.TOOL_ERROR,
                "Bandit adapter could not start",
            ) from exc
        if completed.returncode not in {0, 1}:
            raise SkillExecutionError(
                SkillErrorCode.TOOL_ERROR,
                "Bandit returned an invalid process status",
            )
        try:
            payload = json.loads(completed.stdout.decode("utf-8"))
            raw_results = payload["results"]
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SkillExecutionError(
                SkillErrorCode.TOOL_ERROR,
                "Bandit returned invalid JSON",
            ) from exc

        observations: list[BanditObservation] = []
        for item in raw_results:
            test_id = str(item.get("test_id", ""))
            source_line = line_map.get(int(item.get("line_number", 0)))
            if test_id not in _BANDIT_MESSAGES or source_line is None:
                continue
            observations.append(
                BanditObservation(
                    source_line=source_line,
                    test_id=test_id,
                    severity=str(item.get("issue_severity", "UNDEFINED")),
                    confidence=str(item.get("issue_confidence", "UNDEFINED")),
                    safe_message=_BANDIT_MESSAGES[test_id],
                )
            )
        return tuple(observations)
