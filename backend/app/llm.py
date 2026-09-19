"""Small, optional Ollama chat client for Copilot responses.

The security pipeline remains deterministic. This client is only used to make
natural-language Copilot answers more useful when Ollama is running locally.
It deliberately uses the existing httpx dependency so local/demo installs do
not need another SDK.
"""
from __future__ import annotations

import asyncio
import logging
from threading import Lock
from time import monotonic
from typing import Any

import httpx

from app.settings import settings
from app.performance import timed

logger = logging.getLogger("pnc.llm")

_answer_cache: dict[tuple[str, str, str, int, int], tuple[float, str]] = {}
_cache_lock = Lock()


def _cache_key(question: str, context: dict[str, Any]) -> tuple[str, str, str, int, int]:
    return (
        f"{settings.ai_provider}:{settings.ollama_base_url}:{settings.ollama_model}:{question.strip()}",
        str(context["total"]),
        str(context["unresolved_critical"]),
        int(context["unresolved_high"]),
        settings.ai_max_tokens,
    )


def _cached_answer(key: tuple[str, str, str, int, int]) -> str | None:
    now = monotonic()
    with _cache_lock:
        cached = _answer_cache.get(key)
        if cached and now - cached[0] < settings.ai_cache_ttl_seconds:
            return cached[1]
        if cached:
            _answer_cache.pop(key, None)
    return None


def _store_answer(key: tuple[str, str, str, int, int], answer: str) -> None:
    with _cache_lock:
        # Remove the oldest entries before adding a new one. This keeps a busy
        # tenant or repeated prompts from growing the process indefinitely.
        max_entries = max(1, settings.ai_cache_max_entries)
        while len(_answer_cache) >= max_entries:
            _answer_cache.pop(next(iter(_answer_cache)))
        _answer_cache[key] = (monotonic(), answer)


def generate_answer(question: str, context: dict[str, Any]) -> str | None:
    """Return an Ollama answer, or None when the deterministic fallback is used."""
    provider = settings.ai_provider.lower().strip()
    logger.info("Analyzing Copilot request\nPrompt Type: Copilot Question\nTokens: max=%s", settings.ai_max_tokens)
    if provider != "ollama":
        return None

    key = _cache_key(question, context)
    cached = _cached_answer(key)
    if cached is not None:
        return cached

    endpoint = settings.ollama_base_url.rstrip("/")
    model = settings.ollama_model.strip()
    if not endpoint or not model:
        return None

    prompt_context = (
        f"Tenant findings: {context['total']} total; "
        f"{context['unresolved_critical']} unresolved critical; "
        f"{context['unresolved_high']} unresolved high. "
        "Evidence sources: vulnerability inventory, workflow state, audit event store."
    )
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a concise application security copilot. Use only the supplied evidence. If the evidence does not answer the question, say so."},
            {"role": "user", "content": f"Evidence: {prompt_context}\nQuestion: {question}"},
        ],
        "temperature": 0.1,
        "options": {"num_predict": settings.ai_max_tokens},
        "stream": False,
    }
    try:
        with timed("ai.llm_call", detail=f"provider={provider} model={model}"):
            response = httpx.post(f"{endpoint}/api/chat", json=body, timeout=settings.ai_timeout_seconds)
        response.raise_for_status()
        content = response.json().get("message", {}).get("content")
        answer = content.strip() if isinstance(content, str) and content.strip() else None
        logger.info("LLM response received: provider=%s response_tokens=%s", provider, len(answer.split()) if answer else 0)
        if answer:
            _store_answer(key, answer)
        return answer
    except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
        logger.warning("Ollama Copilot request failed; using deterministic response: %s", exc)
        return None


async def generate_answer_async(question: str, context: dict[str, Any]) -> str | None:
    """Use the existing provider adapter without blocking FastAPI's event loop."""
    return await asyncio.to_thread(generate_answer, question, context)