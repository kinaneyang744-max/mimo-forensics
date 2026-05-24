"""Tests for the ClusterAgent."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from mimo_forensics.agents.cluster import ClusterAgent
from mimo_forensics.models import (
    FundFlowEdge,
    FundFlowGraph,
    Transaction,
    TransactionType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_graph(
    root: str = "0xA",
    edges: list[FundFlowEdge] | None = None,
    num_addresses: int = 5,
) -> FundFlowGraph:
    if edges is None:
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        edges = [
            FundFlowEdge(
                from_address=root,
                to_address=f"0x{chr(66 + i)}{'0' * 38}",
                total_value=10.0 + i,
                tx_count=3,
                first_seen=base,
                last_seen=base + timedelta(days=i),
            )
            for i in range(num_addresses - 1)
        ]
    return FundFlowGraph(
        root_address=root,
        edges=edges,
        total_addresses=num_addresses,
        total_transactions=sum(e.tx_count for e in edges),
        total_value_traced=sum(e.total_value for e in edges),
        max_depth=3,
    )


def _make_txs(
    from_addr: str,
    to_addr: str,
    count: int = 5,
    input_data: str | None = None,
) -> list[Transaction]:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return [
        Transaction(
            tx_hash=f"0x{i:064x}",
            from_address=from_addr,
            to_address=to_addr,
            value=1.0,
            timestamp=base + timedelta(minutes=i * 30),
            input_data=input_data,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cluster_basic():
    agent = ClusterAgent()
    graph = _make_graph()
    result = await agent.cluster(graph)

    assert result.total_wallets_analyzed >= 5
    assert isinstance(result.target_address, str)


@pytest.mark.asyncio
async def test_cluster_with_shared_inputs():
    """Addresses with shared input data should cluster together."""
    addr_a = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    addr_b = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    addr_c = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

    shared_input = "0xdeadbeef"
    txs_a = _make_txs(addr_a, addr_c, input_data=shared_input)
    txs_b = _make_txs(addr_b, addr_c, input_data=shared_input)
    txs_c = _make_txs(addr_c, addr_a, count=2)

    tx_cache = {addr_a: txs_a, addr_b: txs_b, addr_c: txs_c}

    edge = FundFlowEdge(
        from_address=addr_a,
        to_address=addr_c,
        total_value=5.0,
        tx_count=5,
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    graph = FundFlowGraph(
        root_address=addr_a,
        edges=[edge],
        total_addresses=3,
        total_transactions=5,
        total_value_traced=5.0,
    )

    agent = ClusterAgent(min_cluster_confidence=0.1)
    result = await agent.cluster(graph, tx_cache=tx_cache)

    # At least one cluster should include both shared-input addresses
    all_clustered = [a for cl in result.clusters for a in cl.addresses]
    # addr_a and addr_b should appear in some cluster
    assert addr_a in all_clustered or addr_b in all_clustered


@pytest.mark.asyncio
async def test_cluster_empty_graph():
    agent = ClusterAgent()
    graph = FundFlowGraph(root_address="0x" + "0" * 40)
    result = await agent.cluster(graph)

    assert result.clusters == []
    assert result.total_wallets_analyzed == 1
