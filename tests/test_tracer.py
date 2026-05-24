"""Tests for the TracerAgent."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from mimo_forensics.agents.tracer import TracerAgent
from mimo_forensics.models import Transaction, TransactionType


# ---------------------------------------------------------------------------
# Mock data provider
# ---------------------------------------------------------------------------

class MockDataProvider:
    """Deterministic mock chain data for testing."""

    def __init__(self, txs_per_address: int = 5) -> None:
        self._txs_per_address = txs_per_address
        self._call_count = 0

    async def get_transactions(
        self, address: str, *, page: int = 1, page_size: int = 100
    ) -> list[Transaction]:
        self._call_count += 1
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        txs = []
        for i in range(self._txs_per_address):
            txs.append(
                Transaction(
                    tx_hash=f"0x{address[2:6]}{i:04x}",
                    from_address=address,
                    to_address=f"0x{'b' * 40}",
                    value=1.0 + i * 0.1,
                    token_symbol="ETH",
                    timestamp=base + timedelta(hours=i),
                    tx_type=TransactionType.TRANSFER,
                    block_number=19000000 + i,
                )
            )
        return txs

    async def get_balance(self, address: str) -> float:
        return 10.0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_trace_returns_graph():
    provider = MockDataProvider()
    agent = TracerAgent(provider, max_depth=2, page_size=100)

    graph = await agent.trace("0x" + "a" * 40)

    assert graph.root_address == "0x" + "a" * 40
    assert graph.total_addresses >= 1
    assert len(graph.edges) >= 1
    assert graph.total_value_traced > 0


@pytest.mark.asyncio
async def test_trace_respects_max_depth():
    provider = MockDataProvider()
    agent = TracerAgent(provider, max_depth=1, page_size=100)

    graph = await agent.trace("0x" + "a" * 40)

    # With depth=1, should not explore beyond immediate neighbors
    assert graph.max_depth == 1


@pytest.mark.asyncio
async def test_trace_min_value_filter():
    provider = MockDataProvider()
    agent = TracerAgent(provider, max_depth=2, min_value=100.0)

    graph = await agent.trace("0x" + "a" * 40)

    # All edges should be filtered out since mock values are < 100
    assert len(graph.edges) == 0


@pytest.mark.asyncio
async def test_top_recipients():
    provider = MockDataProvider()
    agent = TracerAgent(provider, max_depth=2)

    graph = await agent.trace("0x" + "a" * 40)
    top = agent.top_recipients(graph, n=3)

    assert len(top) <= 3
    # Should be sorted by value descending
    for i in range(len(top) - 1):
        assert top[i].total_value >= top[i + 1].total_value
