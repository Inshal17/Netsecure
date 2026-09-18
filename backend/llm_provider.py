"""Controlled mapping-suggestion provider with an offline-safe fallback."""

from __future__ import annotations

import json
import logging
import os
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

try:
    import certifi
except ModuleNotFoundError:  # pragma: no cover - optional runtime fallback
    certifi = None

PROMPT_VERSION = "mapping-suggestion-v1"
logger = logging.getLogger("netsecureai.llm")


@dataclass(frozen=True)
class ProviderResult:
    field_name: str
    observed_value: Any
    meaning: str
    confidence: float
    reason: str
    provider: str
    model: str
    used_remote_model: bool


def _offline_result(
    *,
    field_name: str,
    observed_value: Any,
    vendor: str,
) -> ProviderResult:
    return ProviderResult(
        field_name=field_name,
        observed_value=observed_value,
        meaning=f"Explainable heuristic suggests this command controls {field_name}.",
        confidence=72,
        reason=(
            f"Offline heuristic matched a known security keyword for {vendor}; "
            "reviewer approval is required before persistence."
        ),
        provider="offline-heuristic",
        model="keyword-rules",
        used_remote_model=False,
    )


def _valid_remote_result(
    payload: Any,
    *,
    valid_fields: set[str],
) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("field_name") in valid_fields
        and isinstance(payload.get("meaning"), str)
        and bool(payload["meaning"].strip())
        and isinstance(payload.get("reason"), str)
        and bool(payload["reason"].strip())
        and isinstance(payload.get("confidence"), (int, float))
        and 0 <= float(payload["confidence"]) <= 100
        and "observed_value" in payload
    )


def _request_json(request: Request) -> Any:
    ssl_context = (
        ssl.create_default_context(cafile=certifi.where())
        if certifi is not None
        else ssl.create_default_context()
    )
    with urlopen(request, timeout=10, context=ssl_context) as response:
        return json.loads(response.read().decode("utf-8"))


def _openai_result(
    *,
    command: str,
    vendor: str,
    framework: str,
    knowledge: dict[str, Any],
    valid_fields: set[str],
) -> ProviderResult | None:
    endpoint = os.getenv(
        "NETSECURE_LLM_ENDPOINT",
        "https://api.openai.com/v1/chat/completions",
    )
    api_key = os.getenv("NETSECURE_LLM_API_KEY")
    model = os.getenv("NETSECURE_LLM_MODEL", "gpt-4o-mini")
    if not api_key:
        return None

    request_body = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a network compliance mapping assistant. Return JSON only with "
                    "field_name, observed_value, meaning, confidence, and reason. "
                    "Use only allowed fields. Do not claim compliance or provide executable remediation."
                ),
            },
            {
                "role": "user",
                "content": json.dumps({
                    "prompt_version": PROMPT_VERSION,
                    "command": command,
                    "vendor": vendor,
                    "framework": framework,
                    "allowed_fields": sorted(valid_fields),
                    "retrieved_knowledge": knowledge.get("retrievedDocuments", []),
                }),
            },
        ],
    }
    request = Request(
        endpoint,
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        payload = _request_json(request)
        if isinstance(payload, dict) and payload.get("choices"):
            content = payload["choices"][0].get("message", {}).get("content")
            payload = json.loads(content) if isinstance(content, str) else content
        elif isinstance(payload, dict) and isinstance(payload.get("output"), dict):
            payload = payload["output"]
        if not _valid_remote_result(payload, valid_fields=valid_fields):
            return None
        return ProviderResult(
            field_name=payload["field_name"],
            observed_value=payload["observed_value"],
            meaning=payload["meaning"].strip(),
            confidence=float(payload["confidence"]),
            reason=payload["reason"].strip(),
            provider="remote-llm",
            model=model,
            used_remote_model=True,
        )
    except HTTPError as exc:
        logger.warning("Remote LLM request fell back to offline provider: HTTP %s", exc.code)
        return None
    except URLError as exc:
        logger.warning("Remote LLM request fell back to offline provider: network %s", type(exc.reason).__name__)
        return None
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Remote LLM request fell back to offline provider: %s", type(exc).__name__)
        return None


def _gemini_result(
    *,
    command: str,
    vendor: str,
    framework: str,
    knowledge: dict[str, Any],
    valid_fields: set[str],
) -> ProviderResult | None:
    api_key = os.getenv("NETSECURE_LLM_API_KEY")
    model = os.getenv("NETSECURE_LLM_MODEL", "gemini-flash-latest")
    endpoint = os.getenv(
        "NETSECURE_LLM_ENDPOINT",
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    ).format(model=quote(model, safe=""))
    if not api_key:
        return None

    parts = urlsplit(endpoint)
    query = dict([item for item in [pair.split("=", 1) for pair in parts.query.split("&") if "=" in pair]])
    query["key"] = api_key
    endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    prompt = json.dumps({
        "prompt_version": PROMPT_VERSION,
        "command": command,
        "vendor": vendor,
        "framework": framework,
        "allowed_fields": sorted(valid_fields),
        "retrieved_knowledge": knowledge.get("retrievedDocuments", []),
    })
    request = Request(
        endpoint,
        data=json.dumps({
            "systemInstruction": {
                "parts": [{"text": "You are a network compliance mapping assistant. Return JSON only with field_name, observed_value, meaning, confidence, and reason. Use only allowed fields. Do not claim compliance or provide executable remediation."}],
            },
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        response = _request_json(request)
        content = response["candidates"][0]["content"]["parts"][0]["text"]
        payload = json.loads(content)
        if not _valid_remote_result(payload, valid_fields=valid_fields):
            return None
        return ProviderResult(
            field_name=payload["field_name"],
            observed_value=payload["observed_value"],
            meaning=payload["meaning"].strip(),
            confidence=float(payload["confidence"]),
            reason=payload["reason"].strip(),
            provider="gemini",
            model=model,
            used_remote_model=True,
        )
    except HTTPError as exc:
        logger.warning("Gemini request fell back to offline provider: HTTP %s", exc.code)
        return None
    except URLError as exc:
        logger.warning("Gemini request fell back to offline provider: network %s", type(exc.reason).__name__)
        return None
    except (KeyError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Gemini request fell back to offline provider: %s", type(exc).__name__)
        return None


def suggest_mapping(
    *,
    command: str,
    vendor: str,
    framework: str,
    knowledge: dict[str, Any],
    field_name: str,
    observed_value: Any,
    valid_fields: set[str],
) -> ProviderResult:
    provider = os.getenv("NETSECURE_LLM_PROVIDER", "offline").lower()
    if provider in {"openai-compatible", "remote"}:
        result = _openai_result(
            command=command,
            vendor=vendor,
            framework=framework,
            knowledge=knowledge,
            valid_fields=valid_fields,
        )
        if result is not None:
            return result
    elif provider == "gemini":
        result = _gemini_result(
            command=command,
            vendor=vendor,
            framework=framework,
            knowledge=knowledge,
            valid_fields=valid_fields,
        )
        if result is not None:
            return result

    return _offline_result(
        field_name=field_name,
        observed_value=observed_value,
        vendor=vendor,
    )
