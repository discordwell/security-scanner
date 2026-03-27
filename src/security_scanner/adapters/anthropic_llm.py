"""Anthropic Claude API adapter for LLM-powered analysis."""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

try:
    import anthropic as _anthropic

    HAS_ANTHROPIC = True
except ImportError:
    _anthropic = None  # type: ignore[assignment]
    HAS_ANTHROPIC = False


class AnthropicLLMAdapter:
    """Calls the Anthropic Messages API for code analysis."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout: int = 120,
    ) -> None:
        if not HAS_ANTHROPIC:
            raise ImportError("anthropic SDK is not installed. Install with: pip install anthropic")
        self._client = _anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout)
        self._model = model
        self._max_tokens = max_tokens
        self._timeout = timeout

    async def analyze_file(
        self,
        prompt: str,
        remaining_budget: int = 100_000,
    ) -> tuple[str, int, int]:
        """Send a prompt to Claude and return (response_text, input_tokens, output_tokens).

        Returns ("", 0, 0) if budget exceeded or call fails.
        """
        # Rough budget check: ~4 chars per token
        estimated_input = len(prompt) // 4
        if estimated_input > remaining_budget:
            logger.info("Skipping LLM call: estimated %d tokens exceeds budget %d", estimated_input, remaining_budget)
            return "", 0, 0

        last_error = None
        for attempt in range(3):
            try:
                response = await self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text if response.content else ""
                in_tokens = response.usage.input_tokens
                out_tokens = response.usage.output_tokens
                return text, in_tokens, out_tokens

            except Exception as exc:
                last_error = exc
                exc_name = type(exc).__name__
                if "rate" in exc_name.lower() or "429" in str(exc):
                    wait = 2 ** attempt
                    logger.warning("Rate limited, retrying in %ds (attempt %d/3)", wait, attempt + 1)
                    await asyncio.sleep(wait)
                    continue
                elif "timeout" in exc_name.lower() or "timed out" in str(exc).lower():
                    logger.warning("LLM call timed out")
                    return "", 0, 0
                else:
                    logger.warning("LLM API error: %s: %s", exc_name, exc)
                    return "", 0, 0

        logger.warning("LLM call failed after 3 attempts: %s", last_error)
        return "", 0, 0
