"""Tests for the IntentAgent."""

from __future__ import annotations

import pytest

from mimo_forensics.agents.intent import IntentAgent
from mimo_forensics.models import (
    FundFlowGraph,
    FundFlowEdge,
    IntentType,
    RiskLevel,
)
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Mock MiMo client
# ---------------------------------------------------------------------------

class MockMiMoClient:
    """Returns a fixed response for testing."""

    def __init__(self, response: dict | None = None) -> None:
        self._response = response or {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"primary_intent": "layering", "confidence": 0.87, '
                            '"risk_level": "high", '
                            '"reasoning_chain": ["Step 1: Found multi-hop pattern", '
                            '"Step 2: Value splitting detected"], '
                            '"indicators": ["rapid hops", "value splitting"]}'
                        )
                    }
                }
            ],
            "usage": {"total_tokens": 2340},
        }
        self.calls: list = []

    async def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return self._response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_graph() -> FundFlowGraph:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return FundFlowGraph(
        root_address="0x" + "a" * 40,
        edges=[
            FundFlowEdge(
                from_address="0x" + "a" * 40,
                to_address="0x" + "b" * 40,
                total_value=10.0,
                tx_count=5,
                first_seen=base,
                last_seen=base,
            ),
        ],
        total_addresses=2,
        total_transactions=5,
        total_value_traced=10.0,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_assess_returns_valid_intent():
    client = MockMiMoClient()
    agent = IntentAgent(client)
    graph = _make_graph()

    result = await agent.assess("0x" + "a" * 40, graph)

    assert result.primary_intent == IntentType.LAYERING
    assert result.confidence == 0.87
    assert result.risk_level == RiskLevel.HIGH
    assert len(result.reasoning_chain) == 2
    assert result.tokens_used == 2340


@pytest.mark.asyncio
async def test_assess_sends_correct_prompt():
    client = MockMiMoClient()
    agent = IntentAgent(client)
    graph = _make_graph()

    await agent.assess("0x" + "a" * 40, graph)

    assert len(client.calls) == 1
    messages = client.calls[0][0]
    assert messages[0]["role"] == "system"
    assert "MiMo" in messages[0]["content"] or "blockchain" in messages[0]["content"]
    assert messages[1]["role"] == "user"
    assert "0x" + "a" * 40 in messages[1]["content"]


@pytest.mark.asyncio
async def test_assess_handles_invalid_json():
    client = MockMiMoClient(
        response={
            "choices": [{"message": {"content": "This is not JSON at all."}}],
            "usage": {"total_tokens": 100},
        }
    )
    agent = IntentAgent(client)
    graph = _make_graph()

    result = await agent.assess("0x" + "a" * 40, graph)

    # Should fall back to defaults without crashing
    assert result.primary_intent == IntentType.UNKNOWN
    assert result.tokens_used == 100


@pytest.mark.asyncio
async def test_assess_cluster():
    client = MockMiMoClient()
    agent = IntentAgent(client)
    graph = _make_graph()

    result = await agent.assess_cluster(
        cluster_id="CL-001",
        addresses=["0x" + "a" * 40, "0x" + "b" * 40],
        graph=graph,
    )

    assert result.address == "0x" + "a" * 40
    # Should include cluster info in the prompt
    messages = client.calls[0][0]
    assert "CL-001" in messages[1]["content"]
