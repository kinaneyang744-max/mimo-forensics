"""Fund-flow tracing agent.

Performs recursive multi-hop transaction graph traversal from a seed
address, collecting edges, aggregating values, and computing flow
metrics at each depth level.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Protocol

from mimo_forensics.models import (
    FundFlowEdge,
    FundFlowGraph,
    Transaction,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data source protocol (swap with real RPC/indexer later)
# ---------------------------------------------------------------------------

class ChainDataProvider(Protocol):
    """Abstraction for on-chain data retrieval."""

    async def get_transactions(
        self, address: str, *, page: int = 1, page_size: int = 100
    ) -> list[Transaction]:
        """Return recent transactions for *address*."""
        ...

    async def get_balance(self, address: str) -> float:
        """Return native-token balance."""
        ...


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class TracerAgent:
    """Traces fund flows starting from a seed address.

    Uses breadth-first search up to *max_depth* hops.  Each edge is
    aggregated by (from, to, token) into a single ``FundFlowEdge`` with
    summed values and counts.
    """

    def __init__(
        self,
        data_provider: ChainDataProvider,
        *,
        max_depth: int = 5,
        min_value: float = 0.0,
        page_size: int = 100,
    ) -> None:
        self._provider = data_provider
        self._max_depth = max_depth
        self._min_value = min_value
        self._page_size = page_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def trace(self, seed_address: str) -> FundFlowGraph:
        """Trace all fund flows originating from *seed_address*.

        Returns a ``FundFlowGraph`` with aggregated edges and metadata.
        """
        logger.info("Tracing fund flows for %s (max_depth=%d)", seed_address, self._max_depth)

        edge_map: dict[tuple[str, str, str], dict] = defaultdict(
            lambda: {"value": 0.0, "count": 0, "first": None, "last": None}
        )
        visited: set[str] = set()
        frontier: list[tuple[str, int]] = [(seed_address, 0)]
        total_addresses = 0

        while frontier:
            current, depth = frontier.pop(0)
            if depth > self._max_depth or current in visited:
                continue
            visited.add(current)
            total_addresses += 1

            txs = await self._provider.get_transactions(
                current, page_size=self._page_size
            )

            for tx in txs:
                key = (tx.from_address, tx.to_address, tx.token_symbol)
                bucket = edge_map[key]
                bucket["value"] += tx.value
                bucket["count"] += 1
                ts = tx.timestamp

                if bucket["first"] is None or ts < bucket["first"]:
                    bucket["first"] = ts
                if bucket["last"] is None or ts > bucket["last"]:
                    bucket["last"] = ts

                if depth + 1 <= self._max_depth:
                    frontier.append((tx.to_address, depth + 1))

        edges = [
            FundFlowEdge(
                from_address=k[0],
                to_address=k[1],
                total_value=v["value"],
                tx_count=v["count"],
                first_seen=v["first"] or datetime.now(timezone.utc),
                last_seen=v["last"] or datetime.now(timezone.utc),
                token_symbol=k[2],
            )
            for k, v in edge_map.items()
            if v["value"] >= self._min_value
        ]

        total_value = sum(e.total_value for e in edges)
        total_txs = sum(e.tx_count for e in edges)

        graph = FundFlowGraph(
            root_address=seed_address,
            edges=edges,
            total_addresses=total_addresses,
            total_transactions=total_txs,
            total_value_traced=total_value,
            max_depth=self._max_depth,
        )

        logger.info(
            "Trace complete: %d addresses, %d edges, %.4f value traced",
            total_addresses,
            len(edges),
            total_value,
        )
        return graph

    # ------------------------------------------------------------------
    # Convenience: top recipients
    # ------------------------------------------------------------------

    def top_recipients(self, graph: FundFlowGraph, n: int = 10) -> list[FundFlowEdge]:
        """Return the *n* highest-value edges by total value."""
        return sorted(graph.edges, key=lambda e: e.total_value, reverse=True)[:n]
