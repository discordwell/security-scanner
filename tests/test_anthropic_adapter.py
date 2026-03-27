"""Tests for the Anthropic LLM adapter (mocked, no real API calls)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# -- Tests that work without anthropic SDK --

def test_adapter_import_error_without_sdk():
    with patch("security_scanner.adapters.anthropic_llm.HAS_ANTHROPIC", False):
        with patch("security_scanner.adapters.anthropic_llm._anthropic", None):
            from security_scanner.adapters.anthropic_llm import AnthropicLLMAdapter
            with pytest.raises(ImportError, match="anthropic SDK"):
                AnthropicLLMAdapter(api_key="test")


# -- Tests with mocked SDK --

@pytest.fixture()
def mock_adapter():
    """Create adapter with mocked anthropic client."""
    with patch("security_scanner.adapters.anthropic_llm.HAS_ANTHROPIC", True):
        with patch("security_scanner.adapters.anthropic_llm._anthropic") as mock_sdk:
            mock_client = AsyncMock()
            mock_sdk.AsyncAnthropic.return_value = mock_client

            from security_scanner.adapters.anthropic_llm import AnthropicLLMAdapter
            adapter = AnthropicLLMAdapter(api_key="test-key", model="test-model")
            adapter._client = mock_client
            yield adapter, mock_client


@pytest.mark.asyncio
async def test_successful_api_call(mock_adapter):
    adapter, mock_client = mock_adapter

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="Analysis result\n```json\n{}\n```")]
    mock_response.usage = MagicMock(input_tokens=500, output_tokens=200)
    mock_client.messages.create = AsyncMock(return_value=mock_response)

    text, in_tok, out_tok = await adapter.analyze_file(prompt="Analyze this code")
    assert "Analysis result" in text
    assert in_tok == 500
    assert out_tok == 200


@pytest.mark.asyncio
async def test_budget_exceeded_skips_call(mock_adapter):
    adapter, mock_client = mock_adapter
    # Very low budget
    text, in_tok, out_tok = await adapter.analyze_file(
        prompt="x" * 10000,  # ~2500 estimated tokens
        remaining_budget=100,
    )
    assert text == ""
    assert in_tok == 0
    mock_client.messages.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_timeout_returns_empty(mock_adapter):
    adapter, mock_client = mock_adapter
    mock_client.messages.create = AsyncMock(side_effect=TimeoutError("timed out"))

    text, in_tok, out_tok = await adapter.analyze_file(prompt="test")
    assert text == ""


@pytest.mark.asyncio
async def test_generic_error_returns_empty(mock_adapter):
    adapter, mock_client = mock_adapter
    mock_client.messages.create = AsyncMock(side_effect=Exception("API error"))

    text, in_tok, out_tok = await adapter.analyze_file(prompt="test")
    assert text == ""


@pytest.mark.asyncio
async def test_rate_limit_retries(mock_adapter):
    adapter, mock_client = mock_adapter

    # First call: rate limited. Second call: success.
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="OK")]
    mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)

    call_count = 0

    async def side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("rate_limit_error: 429")
        return mock_response

    mock_client.messages.create = AsyncMock(side_effect=side_effect)

    with patch("security_scanner.adapters.anthropic_llm.asyncio.sleep", new_callable=AsyncMock):
        text, in_tok, out_tok = await adapter.analyze_file(prompt="test")

    assert text == "OK"
    assert call_count == 2


@pytest.mark.asyncio
async def test_empty_response_handled(mock_adapter):
    adapter, mock_client = mock_adapter

    mock_response = MagicMock()
    mock_response.content = []
    mock_response.usage = MagicMock(input_tokens=100, output_tokens=0)
    mock_client.messages.create = AsyncMock(return_value=mock_response)

    text, in_tok, out_tok = await adapter.analyze_file(prompt="test")
    assert text == ""
    assert in_tok == 100
