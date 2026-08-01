"""Bounded DeepSeek JSON Provider with secret-free call telemetry."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Generic, TypeVar

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from codesentinel.preflight.deepseek import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    MissingApiKeyError,
    sanitize_error,
)

from .models import (
    AgentId,
    CallPurpose,
    ModelCallRecord,
    ModelCallStatus,
    ProviderErrorCode,
)
from .prompts import PromptDefinition

OutputT = TypeVar("OutputT", bound=BaseModel)


class DeepSeekProviderSettings(BaseModel):
    """Local-only Provider settings; the credential is never serializable telemetry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_key: SecretStr
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout_seconds: float = Field(default=45.0, gt=0, le=120)
    temperature: float = Field(default=0.1, ge=0, le=0.3)
    max_network_retries: int = Field(default=1, ge=0, le=1)
    max_schema_repairs: int = Field(default=1, ge=0, le=1)
    max_retry_delay_seconds: float = Field(default=2.0, ge=0, le=5)
    pricing_version: str = "deepseek-v4-pro-2026-08-01"
    cache_hit_usd_per_million: float = Field(default=0.003625, ge=0)
    cache_miss_usd_per_million: float = Field(default=0.435, ge=0)
    output_usd_per_million: float = Field(default=0.87, ge=0)


def load_deepseek_provider_settings(
    env_file: Path | None = None,
) -> DeepSeekProviderSettings:
    """Load P7 settings from one explicit ignored file and environment variables."""

    selected = env_file if env_file is not None else Path.cwd() / ".env"
    if selected.is_file():
        load_dotenv(dotenv_path=selected, override=False)
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise MissingApiKeyError(
            "DEEPSEEK_API_KEY is not configured in the local environment."
        )
    model = os.getenv("DEEPSEEK_MODEL", DEFAULT_MODEL).strip()
    if model != DEFAULT_MODEL:
        raise ValueError(f"P7 requires the frozen model {DEFAULT_MODEL!r}")
    return DeepSeekProviderSettings(
        api_key=SecretStr(api_key),
        base_url=os.getenv("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL).strip(),
        model=model,
    )


class ModelCallBudget:
    """Thread-safe hard cap shared by all Agents in one review."""

    def __init__(self, max_calls: int = 4) -> None:
        if not 1 <= max_calls <= 4:
            raise ValueError("P7 model call budget must be between 1 and 4")
        self.max_calls = max_calls
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.max_calls - self._used

    def consume(self) -> int | None:
        with self._lock:
            if self._used >= self.max_calls:
                return None
            self._used += 1
            return self._used


@dataclass(frozen=True)
class ProviderExecution(Generic[OutputT]):
    output: OutputT | None
    calls: tuple[ModelCallRecord, ...]
    failure_code: ProviderErrorCode | None
    failure_message: str | None

    @property
    def succeeded(self) -> bool:
        return self.output is not None and self.failure_code is None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_user_id(review_id: str, agent_id: AgentId) -> str:
    return f"codesentinel-{agent_id}-{_sha256(review_id)[:20]}"


def _attribute(value: Any, name: str) -> Any:
    direct = getattr(value, name, None)
    if direct is not None:
        return direct
    extra = getattr(value, "model_extra", None)
    return extra.get(name) if isinstance(extra, dict) else None


class DeepSeekProvider:
    """Call DeepSeek with one network retry and one schema regeneration at most."""

    def __init__(
        self,
        settings: DeepSeekProviderSettings,
        *,
        client_factory: Callable[..., Any] = OpenAI,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self._client_factory = client_factory
        self._sleeper = sleeper
        self._client: Any | None = None

    def generate(
        self,
        *,
        review_id: str,
        prompt: PromptDefinition,
        context: BaseModel,
        output_model: type[OutputT],
        budget: ModelCallBudget,
    ) -> ProviderExecution[OutputT]:
        if prompt.agent_id not in {
            "diff-analyzer",
            "security-scanner",
            "quality-reviewer",
        }:
            raise ValueError("unsupported P7 Agent identity")
        context_json = json.dumps(
            context.model_dump(
                mode="json",
                exclude={"review_id", "input_artifact_ids"},
            ),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        schema_json = json.dumps(
            output_model.model_json_schema(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        messages = self._messages(prompt, context_json, schema_json, repair=False)
        calls: list[ModelCallRecord] = []
        network_retries = 0
        schema_repairs = 0
        purpose = CallPurpose.INITIAL

        while True:
            budget_sequence = budget.consume()
            if budget_sequence is None:
                return ProviderExecution(
                    output=None,
                    calls=tuple(calls),
                    failure_code=ProviderErrorCode.BUDGET_EXCEEDED,
                    failure_message="The review exhausted its four-call model budget.",
                )
            attempt = len(calls) + 1
            started_at = datetime.now(UTC)
            timer = time.perf_counter_ns()
            request_hash = self._request_hash(messages, prompt)
            response: Any | None = None
            content: str | None = None
            try:
                client = self._get_client()
                response = client.chat.completions.create(
                    model=self.settings.model,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=self.settings.temperature,
                    max_tokens=min(prompt.max_tokens, 2048),
                    stream=False,
                    extra_body={
                        "thinking": {"type": prompt.thinking},
                        "reasoning_effort": prompt.reasoning_effort,
                        "user_id": _safe_user_id(review_id, prompt.agent_id),
                    },
                )
                choice = response.choices[0]
                finish_reason = getattr(choice, "finish_reason", None)
                content = choice.message.content
                if finish_reason == "length":
                    raise _ResponseFailure(
                        ProviderErrorCode.TRUNCATED_RESPONSE,
                        "The model response reached its output limit.",
                    )
                if not isinstance(content, str) or not content.strip():
                    raise _ResponseFailure(
                        ProviderErrorCode.EMPTY_RESPONSE,
                        "The model returned empty structured content.",
                    )
                try:
                    json.loads(content)
                except json.JSONDecodeError as exc:
                    raise _ResponseFailure(
                        ProviderErrorCode.INVALID_JSON,
                        "The model returned invalid JSON.",
                    ) from exc
                try:
                    output = output_model.model_validate_json(content)
                except ValidationError as exc:
                    raise _ResponseFailure(
                        ProviderErrorCode.SCHEMA_ERROR,
                        "The model JSON did not match the target schema.",
                    ) from exc
                calls.append(
                    self._record(
                        review_id=review_id,
                        prompt=prompt,
                        attempt=attempt,
                        review_call_index=budget_sequence,
                        purpose=purpose,
                        status=ModelCallStatus.SUCCESS,
                        failure_code=None,
                        request_hash=request_hash,
                        response=response,
                        content=content,
                        started_at=started_at,
                        timer=timer,
                    )
                )
                return ProviderExecution(
                    output=output,
                    calls=tuple(calls),
                    failure_code=None,
                    failure_message=None,
                )
            except _ResponseFailure as exc:
                calls.append(
                    self._record(
                        review_id=review_id,
                        prompt=prompt,
                        attempt=attempt,
                        review_call_index=budget_sequence,
                        purpose=purpose,
                        status=ModelCallStatus.FAILED,
                        failure_code=exc.code,
                        request_hash=request_hash,
                        response=response,
                        content=content,
                        started_at=started_at,
                        timer=timer,
                    )
                )
                if schema_repairs >= self.settings.max_schema_repairs:
                    return ProviderExecution(
                        output=None,
                        calls=tuple(calls),
                        failure_code=exc.code,
                        failure_message=exc.safe_message,
                    )
                schema_repairs += 1
                purpose = CallPurpose.SCHEMA_REPAIR
                messages = self._messages(prompt, context_json, schema_json, repair=True)
            except Exception as exc:
                code, retryable = self._classify_exception(exc)
                calls.append(
                    self._record(
                        review_id=review_id,
                        prompt=prompt,
                        attempt=attempt,
                        review_call_index=budget_sequence,
                        purpose=purpose,
                        status=ModelCallStatus.FAILED,
                        failure_code=code,
                        request_hash=request_hash,
                        response=None,
                        content=None,
                        started_at=started_at,
                        timer=timer,
                    )
                )
                safe_message = sanitize_error(
                    str(exc),
                    self.settings.api_key.get_secret_value(),
                )
                if not safe_message:
                    safe_message = "DeepSeek request failed."
                if not retryable or network_retries >= self.settings.max_network_retries:
                    return ProviderExecution(
                        output=None,
                        calls=tuple(calls),
                        failure_code=code,
                        failure_message=safe_message,
                    )
                network_retries += 1
                purpose = CallPurpose.NETWORK_RETRY
                self._sleeper(self._retry_delay(exc, network_retries))

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self._client_factory(
                api_key=self.settings.api_key.get_secret_value(),
                base_url=self.settings.base_url,
                timeout=self.settings.timeout_seconds,
                max_retries=0,
            )
        return self._client

    @staticmethod
    def _messages(
        prompt: PromptDefinition,
        context_json: str,
        schema_json: str,
        *,
        repair: bool,
    ) -> list[dict[str, str]]:
        user_content = (
            "Return JSON only. Validate every line_ref against the input.\n"
            f"TARGET_JSON_SCHEMA={schema_json}\n"
            f"SANITIZED_AGENT_CONTEXT={context_json}"
        )
        messages = [
            {"role": "system", "content": prompt.system_prompt},
            {"role": "user", "content": user_content},
        ]
        if repair:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "The previous response was empty, truncated, invalid JSON, or "
                        "schema-invalid. Regenerate once from the same sanitized input. "
                        "Return exactly one JSON object and no commentary."
                    ),
                }
            )
        return messages

    def _request_hash(
        self,
        messages: list[dict[str, str]],
        prompt: PromptDefinition,
    ) -> str:
        payload = json.dumps(
            {
                "messages": messages,
                "model": self.settings.model,
                "prompt_version": prompt.version,
                "temperature": self.settings.temperature,
                "max_tokens": min(prompt.max_tokens, 2048),
                "thinking": prompt.thinking,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return _sha256(payload)

    def _record(
        self,
        *,
        review_id: str,
        prompt: PromptDefinition,
        attempt: int,
        review_call_index: int,
        purpose: CallPurpose,
        status: ModelCallStatus,
        failure_code: ProviderErrorCode | None,
        request_hash: str,
        response: Any | None,
        content: str | None,
        started_at: datetime,
        timer: int,
    ) -> ModelCallRecord:
        completed_at = datetime.now(UTC)
        latency_ms = max(0, (time.perf_counter_ns() - timer) // 1_000_000)
        usage = getattr(response, "usage", None) if response is not None else None
        prompt_tokens = _attribute(usage, "prompt_tokens") if usage is not None else None
        completion_tokens = (
            _attribute(usage, "completion_tokens") if usage is not None else None
        )
        total_tokens = _attribute(usage, "total_tokens") if usage is not None else None
        cache_hit = (
            _attribute(usage, "prompt_cache_hit_tokens") if usage is not None else None
        )
        cache_miss = (
            _attribute(usage, "prompt_cache_miss_tokens") if usage is not None else None
        )
        if prompt_tokens is not None and cache_hit is None and cache_miss is None:
            cache_hit = 0
            cache_miss = prompt_tokens
        estimated_cost = self._estimate_cost(
            prompt_tokens=prompt_tokens,
            cache_hit_tokens=cache_hit,
            cache_miss_tokens=cache_miss,
            completion_tokens=completion_tokens,
        )
        response_model = getattr(response, "model", None) if response is not None else None
        call_identity = "\0".join(
            (
                review_id,
                prompt.agent_id,
                prompt.version,
                str(attempt),
                str(review_call_index),
                request_hash,
            )
        )
        return ModelCallRecord(
            call_id=f"call-{_sha256(call_identity)[:20]}",
            review_id=review_id,
            agent_id=prompt.agent_id,
            prompt_version=prompt.version,
            target_schema=prompt.target_schema,
            requested_model=self.settings.model,
            response_model=response_model,
            status=status,
            purpose=purpose,
            attempt=attempt,
            review_call_index=review_call_index,
            failure_code=failure_code,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            prompt_cache_hit_tokens=cache_hit,
            prompt_cache_miss_tokens=cache_miss,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost_usd=estimated_cost,
            pricing_version=self.settings.pricing_version,
            request_hash=request_hash,
            response_hash=_sha256(content) if content is not None else None,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _estimate_cost(
        self,
        *,
        prompt_tokens: int | None,
        cache_hit_tokens: int | None,
        cache_miss_tokens: int | None,
        completion_tokens: int | None,
    ) -> float | None:
        if prompt_tokens is None or completion_tokens is None:
            return None
        hit = cache_hit_tokens or 0
        miss = cache_miss_tokens
        if miss is None:
            miss = max(0, prompt_tokens - hit)
        cost = (
            hit * self.settings.cache_hit_usd_per_million
            + miss * self.settings.cache_miss_usd_per_million
            + completion_tokens * self.settings.output_usd_per_million
        ) / 1_000_000
        return round(cost, 12)

    def _classify_exception(
        self,
        exc: Exception,
    ) -> tuple[ProviderErrorCode, bool]:
        status_code = getattr(exc, "status_code", None)
        response = getattr(exc, "response", None)
        if status_code is None and response is not None:
            status_code = getattr(response, "status_code", None)
        class_name = type(exc).__name__.lower()
        if isinstance(exc, TimeoutError) or "timeout" in class_name:
            return ProviderErrorCode.TIMEOUT, True
        if status_code == 401:
            return ProviderErrorCode.AUTHENTICATION_ERROR, False
        if status_code == 402:
            return ProviderErrorCode.INSUFFICIENT_BALANCE, False
        if status_code == 429:
            return ProviderErrorCode.RATE_LIMIT, True
        if status_code is not None and int(status_code) >= 500:
            return ProviderErrorCode.PROVIDER_ERROR, True
        if "connection" in class_name or isinstance(exc, OSError):
            return ProviderErrorCode.TRANSPORT_ERROR, True
        return ProviderErrorCode.PROVIDER_ERROR, False

    def _retry_delay(self, exc: Exception, retry_number: int) -> float:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        raw_retry_after = headers.get("Retry-After") if headers is not None else None
        try:
            requested = float(raw_retry_after)
        except (TypeError, ValueError):
            requested = 0.25 * (2 ** (retry_number - 1))
        return min(max(0.0, requested), self.settings.max_retry_delay_seconds)


class _ResponseFailure(RuntimeError):
    def __init__(self, code: ProviderErrorCode, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message
