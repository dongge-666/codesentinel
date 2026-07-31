import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codesentinel.preflight.deepseek import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    MissingApiKeyError,
    PreflightSettings,
    load_settings,
    public_base_url,
    run_preflight,
    sanitize_error,
    write_report,
)


def _response(*, content: str | None = None, tool_calls: list[object] | None = None) -> object:
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message)],
        usage=usage,
        model=DEFAULT_MODEL,
    )


class FakeCompletions:
    def create(self, **kwargs: object) -> object:
        if "response_format" in kwargs:
            return _response(
                content='{"status":"ok","code":2026,"component":"codesentinel"}'
            )
        if "tools" in kwargs:
            function = SimpleNamespace(
                name="record_preflight_result",
                arguments='{"status":"ok","component":"codesentinel"}',
            )
            return _response(tool_calls=[SimpleNamespace(function=function)])
        return _response(content="CODESENTINEL_OK")


class FakeClient:
    def __init__(self, **_: object) -> None:
        self.chat = SimpleNamespace(completions=FakeCompletions())


def _client_with(completions: object) -> object:
    return SimpleNamespace(chat=SimpleNamespace(completions=completions))


def test_load_settings_rejects_missing_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError):
        load_settings(tmp_path / "missing.env")


def test_load_settings_uses_expected_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-key")
    monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)

    settings = load_settings(tmp_path / "missing.env")

    assert settings.base_url == DEFAULT_BASE_URL
    assert settings.model == DEFAULT_MODEL


def test_sanitize_error_redacts_exact_and_shaped_keys() -> None:
    key = "".join(("sk-", "unit-test-secret-value"))
    alternate = "".join(("sk-", "another-secret"))
    message = f"Authorization: Bearer {key}; alternate {alternate}"

    sanitized = sanitize_error(message, key)

    assert key not in sanitized
    assert alternate not in sanitized
    assert sanitized.count("[REDACTED]") >= 2


def test_sanitize_error_redacts_url_credentials_and_sensitive_query() -> None:
    message = (
        "request failed for https://user:password@example.test/v1"
        "?api_key=secret-value&mode=test"
    )

    sanitized = sanitize_error(message, "different-key")

    assert "user:password" not in sanitized
    assert "secret-value" not in sanitized


def test_public_base_url_keeps_only_origin() -> None:
    base_url = "https://user:password@example.test:8443/v1?api_key=secret#fragment"

    assert public_base_url(base_url) == "https://example.test:8443"


def test_run_preflight_passes_all_three_probes() -> None:
    settings = PreflightSettings(api_key="unit-test-key")

    report = run_preflight(settings, client_factory=FakeClient)

    assert report.status == "passed"
    assert [probe.name for probe in report.probes] == [
        "chat",
        "json_output",
        "tool_call",
    ]
    assert all(probe.status == "passed" for probe in report.probes)
    assert all(probe.total_tokens == 15 for probe in report.probes)


def test_run_preflight_rejects_wrong_chat_content() -> None:
    class WrongChatCompletions(FakeCompletions):
        def create(self, **kwargs: object) -> object:
            if "response_format" not in kwargs and "tools" not in kwargs:
                return _response(content="WRONG")
            return super().create(**kwargs)

    report = run_preflight(
        PreflightSettings(api_key="unit-test-key"),
        client_factory=lambda **_: _client_with(WrongChatCompletions()),
    )

    assert report.status == "failed"
    assert report.probes[0].status == "failed"
    assert report.probes[1].status == "passed"
    assert report.probes[2].status == "passed"


@pytest.mark.parametrize(
    "content",
    [
        "",
        "not-json",
        '{"status":"ok","code":2026,"component":"codesentinel","extra":true}',
    ],
)
def test_run_preflight_rejects_invalid_json_output(content: str) -> None:
    class InvalidJsonCompletions(FakeCompletions):
        def create(self, **kwargs: object) -> object:
            if "response_format" in kwargs:
                return _response(content=content)
            return super().create(**kwargs)

    report = run_preflight(
        PreflightSettings(api_key="unit-test-key"),
        client_factory=lambda **_: _client_with(InvalidJsonCompletions()),
    )

    assert report.status == "failed"
    assert report.probes[1].status == "failed"


@pytest.mark.parametrize(
    ("tool_calls", "expected_error"),
    [
        ([], "exactly one tool call"),
        (
            [
                SimpleNamespace(
                    function=SimpleNamespace(
                        name="record_preflight_result",
                        arguments='{"status":"ok","component":"codesentinel"}',
                    )
                ),
                SimpleNamespace(
                    function=SimpleNamespace(
                        name="record_preflight_result",
                        arguments='{"status":"ok","component":"codesentinel"}',
                    )
                ),
            ],
            "exactly one tool call",
        ),
        (
            [
                SimpleNamespace(
                    function=SimpleNamespace(
                        name="wrong_tool",
                        arguments='{"status":"ok","component":"codesentinel"}',
                    )
                )
            ],
            "unexpected tool name",
        ),
        (
            [
                SimpleNamespace(
                    function=SimpleNamespace(
                        name="record_preflight_result",
                        arguments='{"status":"wrong","component":"codesentinel"}',
                    )
                )
            ],
            "validation error",
        ),
    ],
)
def test_run_preflight_rejects_invalid_tool_calls(
    tool_calls: list[object],
    expected_error: str,
) -> None:
    class InvalidToolCompletions(FakeCompletions):
        def create(self, **kwargs: object) -> object:
            if "tools" in kwargs:
                return _response(tool_calls=tool_calls)
            return super().create(**kwargs)

    report = run_preflight(
        PreflightSettings(api_key="unit-test-key"),
        client_factory=lambda **_: _client_with(InvalidToolCompletions()),
    )

    assert report.status == "failed"
    assert report.probes[2].status == "failed"
    assert expected_error in (report.probes[2].error_message or "").lower()


def test_run_preflight_sanitizes_sdk_error_in_report(tmp_path: Path) -> None:
    key = "".join(("sk-", "unit-test-secret-value"))

    class FailingCompletions:
        def create(self, **_: object) -> object:
            raise RuntimeError(f"Authorization: Bearer {key}")

    report = run_preflight(
        PreflightSettings(api_key=key),
        client_factory=lambda **_: _client_with(FailingCompletions()),
    )
    report_path = write_report(report, tmp_path)
    content = report_path.read_text(encoding="utf-8")

    assert report.status == "failed"
    assert key not in content
    assert "Bearer [REDACTED]" in content


def test_run_preflight_sanitizes_client_initialization_error(tmp_path: Path) -> None:
    key = "".join(("sk-", "unit-test-secret-value"))

    def failing_factory(**_: object) -> object:
        raise RuntimeError(f"client rejected {key}")

    report = run_preflight(
        PreflightSettings(
            api_key=key,
            base_url="https://user:password@example.test/v1?token=url-secret",
        ),
        client_factory=failing_factory,
    )
    report_path = write_report(report, tmp_path)
    content = report_path.read_text(encoding="utf-8")

    assert report.status == "failed"
    assert [probe.status for probe in report.probes] == ["failed", "skipped", "skipped"]
    assert key not in content
    assert "password" not in content
    assert "url-secret" not in content


def test_write_report_contains_no_api_key(tmp_path: Path) -> None:
    key = "".join(("sk-", "unit-test-secret-value"))
    report = run_preflight(PreflightSettings(api_key=key), client_factory=FakeClient)

    report_path = write_report(report, tmp_path)
    content = report_path.read_text(encoding="utf-8")

    assert key not in content
    parsed = json.loads(content)
    assert parsed["status"] == "passed"
    assert len(parsed["probes"]) == 3
