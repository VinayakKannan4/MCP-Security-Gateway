"""BaseAgent — abstract base class for all LLM-backed agents.

Handles:
- Provider-aware client init (Anthropic or OpenAI-compat: Groq, Ollama, etc.)
- Retry loop with configurable max retries
- Timeout enforcement via asyncio.wait_for
- DEBUG-level logging of prompts and responses (never INFO)
- Static XML tag extractor used by all subclasses
"""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

from anthropic import APIError as AnthropicAPIError
from anthropic import AsyncAnthropic
from anthropic.types import TextBlock
from openai import APIError as OpenAIAPIError
from openai import AsyncOpenAI
from pydantic import BaseModel

from gateway.config import Settings

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    def __init__(self, settings: Settings) -> None:
        self._provider = settings.llm_provider
        self._model = settings.llm_model
        self._timeout = settings.llm_timeout_seconds
        self._max_retries = settings.llm_max_retries

        if settings.llm_provider == "anthropic":
            self._anthropic_client: AsyncAnthropic | None = AsyncAnthropic(
                api_key=settings.anthropic_api_key
            )
            self._openai_client: AsyncOpenAI | None = None
        else:
            self._anthropic_client = None
            self._openai_client = AsyncOpenAI(
                base_url=settings.llm_base_url,
                api_key=settings.llm_api_key,
            )

    async def _call(self, system: str, prompt: str) -> str:
        """Make an LLM call with timeout + retry.

        Returns the raw text of the first content block.
        Raises the last exception after exhausting retries.
        LLM inputs/outputs are logged at DEBUG (never INFO — they are verbose).
        """
        logger.debug("LLM call | model=%s system=%.100r prompt=%.200r", self._model, system, prompt)
        last_exc: BaseException = RuntimeError("no attempts made")

        for attempt in range(self._max_retries + 1):
            try:
                text = await asyncio.wait_for(
                    self._invoke(system, prompt),
                    timeout=self._timeout,
                )
                logger.debug("LLM response | attempt=%d text=%.200r", attempt, text)
                return text
            except (AnthropicAPIError, OpenAIAPIError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    logger.debug("LLM attempt %d/%d failed: %s", attempt + 1, self._max_retries, exc)

        raise last_exc

    async def _invoke(self, system: str, prompt: str) -> str:
        """Single provider-specific API call, no retry logic."""
        if self._anthropic_client is not None:
            response = await self._anthropic_client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            block = response.content[0]
            return block.text if isinstance(block, TextBlock) else ""
        else:
            assert self._openai_client is not None
            response = await self._openai_client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content or ""

    @staticmethod
    def _extract_tag(raw: str, tag: str) -> str | None:
        """Return content inside <tag>...</tag>, stripped. None if not found."""
        pattern = rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>"
        m = re.search(pattern, raw, re.DOTALL)
        return m.group(1).strip() if m else None

    @abstractmethod
    def parse_response(self, raw: str) -> BaseModel: ...

    # Expose clients for test patching without accessing private attrs directly
    def _get_client(self) -> Any:
        return self._anthropic_client if self._anthropic_client is not None else self._openai_client
