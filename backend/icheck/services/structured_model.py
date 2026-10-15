from __future__ import annotations

from ..ai_runtime_policy import qwen_runtime_parameters
from ..bounded_http import read_bounded_response
from ..ai_failure_diagnostics import timeout_diagnostic, model_validation_diagnostic, schema_field_names

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, TypeVar
from urllib.error import HTTPError, URLError
from ..ai_failure_diagnostics import batch_model, batch_diagnostic, provider_diagnostic, diagnostic_text
from urllib.request import ProxyHandler, Request, build_opener

from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AIModelConfig, AIModelRoute, AIProviderConfig
from .ai_settings import (
    _NoRedirect,
    AIProviderUnavailable,
    _models_request_headers,
    validated_provider_url,
)
from .audit import record_audit_event
from .ai_authoring_quota import (
    reserve_authoring_tokens,
    settle_authoring_tokens,
)


MAX_STRUCTURED_REQUEST_BYTES = 1_000_000
MAX_STRUCTURED_RESPONSE_BYTES = 1_000_000
# A single response plus a previously admitted route budget must fit the
# platform's signed 32-bit persisted token counters.
MAX_REPORTED_TOKENS = 1_000_000_000
StructuredDocument = TypeVar("StructuredDocument", bound=BaseModel)


class StructuredModelUnavailable(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        token_usage: int = 0,
        external_charge_unknown: bool = False,
        diagnostic: dict | None = None,
    ):
        if isinstance(token_usage, bool) or not isinstance(token_usage, int) or token_usage < 0:
            raise ValueError("Known model token usage must be a non-negative integer")
        super().__init__(message)
        self.token_usage = token_usage
        self.external_charge_unknown = external_charge_unknown
        self.diagnostic = diagnostic


@dataclass(frozen=True)
class StructuredGenerationResult:
    document: BaseModel
    route_id: str
    model_id: str
    tokens_used: int
    external_charge_unknown: bool = False


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class OpenAICompatibleStructuredGenerator:
    def __init__(self, db: Session, *, opener: Any | None = None):
        self.db = db
        self.opener = opener or build_opener(ProxyHandler({}), _NoRedirect())

    def generate(
        self,
        *,
        route_purpose: str,
        response_model: type[StructuredDocument],
        schema_name: str,
        system_prompt: str,
        prompt_document: dict[str, Any],
        entity_type: str,
        entity_id: str,
        actor_id: str,
    ) -> StructuredGenerationResult:
        route = self.db.query(AIModelRoute).filter_by(
            purpose=route_purpose
        ).one_or_none()
        if route is None or not route.enabled:
            raise StructuredModelUnavailable(
                f"AI model route {route_purpose!r} is unavailable"
            )
        reservation_id = reserve_authoring_tokens(
            self.db, actor=actor_id, entity_type=entity_type,
            entity_id=entity_id, token_budget=route.token_budget,
        )
        try:
            result = self._generate_candidates(
                route=route, response_model=response_model,
                schema_name=schema_name, system_prompt=system_prompt,
                prompt_document=prompt_document, entity_type=entity_type,
                entity_id=entity_id, actor_id=actor_id,
            )
        except Exception as exc:
            known_tokens = exc.token_usage if isinstance(exc, StructuredModelUnavailable) else 0
            charge_unknown = (
                exc.external_charge_unknown
                if isinstance(exc, StructuredModelUnavailable) else True
            )
            try:
                settle_authoring_tokens(
                    self.db, reservation_id, known_tokens=known_tokens,
                    external_charge_unknown=charge_unknown,
                )
            except Exception as settlement_error:
                self.db.rollback()
                raise StructuredModelUnavailable(
                    "AI authoring quota settlement failed after model attempt",
                    token_usage=known_tokens,
                    external_charge_unknown=charge_unknown,
                ) from settlement_error
            raise
        try:
            settle_authoring_tokens(
                self.db, reservation_id, known_tokens=result.tokens_used,
                external_charge_unknown=result.external_charge_unknown,
            )
        except Exception as exc:
            self.db.rollback()
            raise StructuredModelUnavailable(
                "AI authoring quota settlement failed after model completion",
                token_usage=result.tokens_used,
                external_charge_unknown=result.external_charge_unknown,
            ) from exc
        return result

    def _generate_candidates(
        self,
        *,
        route: AIModelRoute,
        response_model: type[StructuredDocument],
        schema_name: str,
        system_prompt: str,
        prompt_document: dict[str, Any],
        entity_type: str,
        entity_id: str,
        actor_id: str,
    ) -> StructuredGenerationResult:
        candidates = list(
            dict.fromkeys(
                [route.primary_model_id, *(route.fallback_model_ids or [])]
            )
        )
        started = time.monotonic()
        failed_tokens = 0
        external_charge_unknown = False
        last_error: Exception | None = None
        for candidate_index, model_id in enumerate(candidates):
            if failed_tokens >= route.token_budget:
                break  # Do not start another chargeable candidate after exhaustion.
            model: AIModelConfig | None = None
            provider: AIProviderConfig | None = None
            try:
                model, provider = self._candidate(model_id)
                document, tokens = self._invoke(
                    model=model,
                    provider=provider,
                    route=route,
                    response_model=response_model,
                    schema_name=schema_name,
                    system_prompt=system_prompt,
                    prompt_document=prompt_document,
                    elapsed_seconds=time.monotonic() - started,
                    remaining_token_budget=route.token_budget - failed_tokens,
                )
            except (AIProviderUnavailable, StructuredModelUnavailable) as exc:
                last_error = exc
                known_tokens = (
                    exc.token_usage if isinstance(exc, StructuredModelUnavailable) else 0
                )
                failed_tokens += known_tokens
                external_charge_unknown |= (
                    exc.external_charge_unknown
                    if isinstance(exc, StructuredModelUnavailable) else False
                )
                self._audit(
                    event_type="capability.model.failed",
                    outcome="failure",
                    actor_id=actor_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    route=route,
                    model_id=model_id,
                    provider_id=provider.id if provider else None,
                    candidate_index=candidate_index,
                    prompt_document=prompt_document,
                    details={
                        "error": str(exc)[:1000],
                        **({"diagnostic": exc.diagnostic} if isinstance(exc, StructuredModelUnavailable) and exc.diagnostic else {}),
                        "token_usage": known_tokens,
                        "cumulative_token_usage": failed_tokens,
                        "external_charge_unknown": external_charge_unknown,
                    },
                )
                continue
            total_tokens = failed_tokens + tokens
            if total_tokens > route.token_budget:
                self._audit(
                    event_type="capability.model.budget_exceeded",
                    outcome="failure",
                    actor_id=actor_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    route=route,
                    model_id=model.id,
                    provider_id=provider.id,
                    candidate_index=candidate_index,
                    prompt_document=prompt_document,
                    details={
                        "token_usage": tokens,
                        "cumulative_token_usage": total_tokens,
                        "budget": route.token_budget,
                        "external_charge_unknown": external_charge_unknown,
                    },
                )
                raise StructuredModelUnavailable(
                    "Structured generation exceeded the route token budget",
                    token_usage=total_tokens,
                    external_charge_unknown=external_charge_unknown,
                )
            self._audit(
                event_type="capability.model.completed",
                outcome="success",
                actor_id=actor_id,
                entity_type=entity_type,
                entity_id=entity_id,
                route=route,
                model_id=model.id,
                provider_id=provider.id,
                candidate_index=candidate_index,
                prompt_document=prompt_document,
                details={
                    "token_usage": total_tokens,
                    "candidate_token_usage": tokens,
                    "external_charge_unknown": external_charge_unknown,
                },
            )
            return StructuredGenerationResult(
                document=document,
                route_id=route.id,
                model_id=model.id,
                tokens_used=total_tokens,
                external_charge_unknown=external_charge_unknown,
            )
        if failed_tokens >= route.token_budget:
            raise StructuredModelUnavailable(
                "Structured generation exhausted the route token budget",
                token_usage=failed_tokens,
                external_charge_unknown=external_charge_unknown,
            ) from last_error
        suffix = f": {last_error}" if last_error else ""
        raise StructuredModelUnavailable(
            f"All configured structured-model candidates failed{suffix}",
            token_usage=failed_tokens,
            external_charge_unknown=external_charge_unknown,
            diagnostic=last_error.diagnostic if isinstance(last_error, StructuredModelUnavailable) else None,
        ) from last_error

    def _candidate(
        self, model_id: str
    ) -> tuple[AIModelConfig, AIProviderConfig]:
        model = self.db.get(AIModelConfig, model_id)
        if model is None or not model.enabled:
            raise StructuredModelUnavailable("AI model candidate is unavailable")
        provider = self.db.get(AIProviderConfig, model.provider_id)
        if provider is None or not provider.enabled:
            raise StructuredModelUnavailable("AI provider candidate is unavailable")
        if provider.provider_type not in {"openai_compatible", "anthropic"}:
            raise StructuredModelUnavailable("AI provider type is unsupported")
        if not {"chat", "json_schema"} <= set(model.capabilities):
            raise StructuredModelUnavailable(
                "AI model candidate requires chat and json_schema capabilities"
            )
        return model, provider

    def _invoke(
        self,
        *,
        model: AIModelConfig,
        provider: AIProviderConfig,
        route: AIModelRoute,
        response_model: type[StructuredDocument],
        schema_name: str,
        system_prompt: str,
        prompt_document: dict[str, Any],
        elapsed_seconds: float,
        remaining_token_budget: int,
    ) -> tuple[StructuredDocument, int]:
        if provider.base_url.rstrip("/") == "https://openrouter.ai/api/v1" and batch_model(model.model_name):
            raise StructuredModelUnavailable(diagnostic_text(batch_diagnostic()))
        try:
            base_url = validated_provider_url(self.db, provider)
        except (ValueError, AIProviderUnavailable) as exc:
            raise StructuredModelUnavailable(str(exc)) from exc
        parameters = dict(model.default_parameters)
        if "max_tokens" in parameters and "max_completion_tokens" in parameters:
            raise StructuredModelUnavailable(
                "AI model config cannot set both output-token parameters"
            )
        token_limit = min(
            model.max_output_tokens or remaining_token_budget,
            remaining_token_budget,
        )
        if token_limit < 1:
            raise StructuredModelUnavailable("AI model output-token limit is invalid")
        parameter_name = (
            "max_completion_tokens" if "max_completion_tokens" in parameters
            else "max_tokens"
        )
        configured_limit = parameters.get(parameter_name)
        if configured_limit is not None:
            if (
                isinstance(configured_limit, bool)
                or not isinstance(configured_limit, int)
                or configured_limit < 1
            ):
                raise StructuredModelUnavailable("AI model output-token parameter is invalid")
            token_limit = min(token_limit, configured_limit)
        parameters[parameter_name] = token_limit
        parameters = qwen_runtime_parameters(base_url, model.model_name, parameters, remaining_token_budget)
        payload = {
            **parameters,
            "model": model.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(
                        prompt_document,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": True,
                    "schema": response_model.model_json_schema(),
                },
            },
            "stream": False,
        }
        from ..ai_provider_transport import prepare_completion, normalize_completion
        try:
            completion_url, payload = prepare_completion(provider.provider_type, base_url, payload)
        except ValueError as exc:
            raise StructuredModelUnavailable(str(exc)) from exc
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_STRUCTURED_REQUEST_BYTES:
            raise StructuredModelUnavailable(
                "Structured-model request exceeded 1000000 bytes"
            )
        remaining = route.timeout_seconds - elapsed_seconds
        if remaining <= 0:
            raise StructuredModelUnavailable(
                "Structured generation exhausted its wall-clock budget"
            )
        request_started = False
        try:
            with _models_request_headers(self.db, provider) as headers:
                headers.update(
                    {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "User-Agent": "iCheck-capability-studio/0.1",
                    }
                )
                request = Request(
                    completion_url,
                    data=encoded,
                    headers=headers,
                    method="POST",
                )
                request_started = True
                body = read_bounded_response(self.opener, request,
                    timeout=min(provider.request_timeout_seconds, remaining), max_bytes=MAX_STRUCTURED_RESPONSE_BYTES)
        except AIProviderUnavailable as exc:
            raise StructuredModelUnavailable(
                str(exc), external_charge_unknown=request_started,
            ) from exc
        except HTTPError as exc:
            code = exc.code
            try: error_body = exc.read(16385)
            except OSError: error_body = b""
            finally: exc.close()
            value = provider_diagnostic(code, error_body, model_name=model.model_name)
            raise StructuredModelUnavailable(diagnostic_text(value), diagnostic=value,
                external_charge_unknown=True) from None
        except (OSError, URLError) as exc:
            if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
                value = timeout_diagnostic(timeout_seconds=min(provider.request_timeout_seconds, remaining))
                raise StructuredModelUnavailable(diagnostic_text(value), diagnostic=value,
                    external_charge_unknown=True) from None
            raise StructuredModelUnavailable(
                "AI provider request failed", external_charge_unknown=True,
            ) from exc
        if len(body) > MAX_STRUCTURED_RESPONSE_BYTES:
            raise StructuredModelUnavailable(
                "AI provider response exceeded 1000000 bytes",
                external_charge_unknown=True,
            )
        try:
            response_document = normalize_completion(provider.provider_type, json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StructuredModelUnavailable(
                "AI provider returned an invalid structured completion",
                external_charge_unknown=True,
            ) from exc
        if not isinstance(response_document, dict):
            raise StructuredModelUnavailable(
                "AI provider returned invalid structured completion metadata",
                external_charge_unknown=True,
            )
        usage = response_document.get("usage")
        total_tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
        if (
            isinstance(total_tokens, bool)
            or not isinstance(total_tokens, int)
            or total_tokens < 0
            or total_tokens > MAX_REPORTED_TOKENS
        ):
            raise StructuredModelUnavailable(
                "AI provider returned invalid structured completion metadata",
                external_charge_unknown=True,
            )
        try:
            content = response_document["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise StructuredModelUnavailable(
                "AI provider returned an invalid structured completion",
                token_usage=total_tokens,
            ) from exc
        if not isinstance(content, str):
            raise StructuredModelUnavailable(
                "AI provider returned invalid structured completion metadata",
                token_usage=total_tokens,
            )
        try:
            return response_model.model_validate_json(content), total_tokens
        except ValueError as exc:
            value = model_validation_diagnostic(exc,
                finish_reason=response_document["choices"][0].get("finish_reason"),
                stage="capability_authoring", known_fields=schema_field_names(response_model.model_json_schema()))
            raise StructuredModelUnavailable(
                "AI provider output did not match the required schema. " + value["cause"],
                token_usage=total_tokens,
                diagnostic=value,
            ) from None

    def _audit(
        self,
        *,
        event_type: str,
        outcome: str,
        actor_id: str,
        entity_type: str,
        entity_id: str,
        route: AIModelRoute,
        model_id: str,
        provider_id: str | None,
        candidate_index: int,
        prompt_document: dict[str, Any],
        details: dict[str, Any],
    ) -> None:
        record_audit_event(
            self.db,
            event_type=event_type,
            actor_type="agent",
            actor_id=actor_id,
            entity_type=entity_type,
            entity_id=entity_id,
            outcome=outcome,
            details={
                "route_id": route.id,
                "model_id": model_id,
                "provider_id": provider_id,
                "candidate_index": candidate_index,
                "fallback_used": candidate_index > 0,
                "prompt_sha256": _hash(prompt_document),
                **details,
            },
        )
        self.db.commit()
