from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codesentinel.agents import DeepSeekProvider, DeepSeekProviderSettings
from codesentinel.preflight.p7_agents import run_live_probe, write_live_report


class SchemaAwareCompletions:
    def __init__(self) -> None:
        self.call_count = 0

    def create(self, **kwargs: object):
        self.call_count += 1
        messages = kwargs["messages"]
        user_content = messages[1]["content"]
        context = json.loads(user_content.split("SANITIZED_AGENT_CONTEXT=", 1)[1])
        line_ref = context["lines"][0]["line_ref"]
        if '"title":"DiffSemanticPayload"' in user_content:
            payload = {
                "summary": "The function now stores and returns an incremented value.",
                "change_intents": ["increment the input"],
                "affected_symbols": ["calculate"],
            }
        elif '"title":"SecurityReviewPayload"' in user_content:
            payload = {"findings": [], "summary": "No semantic security risk found."}
        else:
            payload = {
                "findings": [
                    {
                        "category": "test_gap",
                        "severity": "medium",
                        "title": "Focused regression test is absent",
                        "claim": "The changed result path has no test in the supplied diff.",
                        "recommendation": "Add a regression test for the increment.",
                        "confidence": 0.8,
                        "line_refs": [line_ref],
                    }
                ],
                "summary": "One quality review item found.",
            }
        message = SimpleNamespace(content=json.dumps(payload), reasoning_content="discard me")
        usage = SimpleNamespace(
            prompt_tokens=100,
            prompt_cache_hit_tokens=0,
            prompt_cache_miss_tokens=100,
            completion_tokens=30,
            total_tokens=130,
        )
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason="stop")],
            usage=usage,
            model="deepseek-v4-pro",
        )


def test_p7_live_probe_uses_three_calls_and_persists_metadata_only(tmp_path: Path) -> None:
    key = "sk-" + ("L" * 24)
    completions = SchemaAwareCompletions()

    def provider_factory(settings: DeepSeekProviderSettings) -> DeepSeekProvider:
        client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        return DeepSeekProvider(settings, client_factory=lambda **_: client)

    report = run_live_probe(
        DeepSeekProviderSettings(api_key=key),
        provider_factory=provider_factory,
    )
    report_path = write_live_report(report, tmp_path)
    serialized = report_path.read_text(encoding="utf-8")

    assert report.status == "passed"
    assert report.calls_used == 3
    assert completions.call_count == 3
    assert [item.agent_id for item in report.agents] == [
        "diff-analyzer",
        "security-scanner",
        "quality-reviewer",
    ]
    assert all(item.call_count == 1 for item in report.agents)
    assert key not in serialized
    assert "discard me" not in serialized
    assert "result = value + 1" not in serialized
