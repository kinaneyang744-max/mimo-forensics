"""Wallet clustering agent.

Groups addresses that are likely controlled by the same entity using
shared-input analysis, temporal correlation, and balance heuristics.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Optional, Protocol

from mimo_forensics.models import (
    ClusteringResult,
    FundFlowGraph,
    Transaction,
    WalletCluster,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared-input analysis helpers
# ---------------------------------------------------------------------------

def _shared_input_score(
    addr_a_txs: list[Transaction],
    addr_b_txs: list[Transaction],
) -> float:
    """Heuristic: fraction of transactions sharing the same ``input_data``.

    A simplified proxy for the "common-input-ownership" heuristic used in
    Bitcoin UTXO analysis; adapted for account-model chains by comparing
    calldata patterns.
    """
    inputs_a = {tx.input_data for tx in addr_a_txs if tx.input_data}
    inputs_b = {tx.input_data for tx in addr_b_txs if tx.input_data}
    if not inputs_a or not inputs_b:
        return 0.0
    overlap = inputs_a & inputs_b
    return len(overlap) / max(len(inputs_a | inputs_b), 1)


def _temporal_overlap_score(
    addr_a_txs: list[Transaction],
    addr_b_txs: list[Transaction],
    window: timedelta = timedelta(minutes=30),
) -> float:
    """Fraction of addr_a transactions that fall within *window* of an addr_b tx."""
    if not addr_a_txs or not addr_b_txs:
        return 0.0
    b_times = [tx.timestamp for tx in sorted(addr_b_txs, key=lambda t: t.timestamp)]
    overlap_count = 0
    for tx_a in sorted(addr_a_txs, key=lambda t: t.timestamp):
        for t_b in b_times:
            if abs((tx_a.timestamp - t_b).total_seconds()) <= window.total_seconds():
                overlap_count += 1
                break
    return overlap_count / len(addr_a_txs)


def _balance_correlation(
    balance_a: float,
    balance_b: float,
    epsilon: float = 1e-9,
) -> float:
    """Simple correlation heuristic for balances.

    Returns 1.0 when balances are identical, decreasing with ratio distance.
    """
    if balance_a == 0 and balance_b == 0:
        return 1.0
    ratio = min(balance_a, balance_b) / max(balance_a, balance_b) if max(balance_a, balance_b) > 0 else 0.0
    return ratio


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ClusterAgent:
    """Clusters wallets using structural and behavioral heuristics.

    Takes a ``FundFlowGraph`` from the tracer and returns groups of
    addresses likely controlled by the same entity.
    """

    def __init__(
        self,
        *,
        shared_input_threshold: float = 0.15,
        temporal_threshold: float = 0.3,
        balance_threshold: float = 0.6,
        min_cluster_confidence: float = 0.4,
    ) -> None:
        self._si_thresh = shared_input_threshold
        self._temp_thresh = temporal_threshold
        self._bal_thresh = balance_threshold
        self._min_confidence = min_cluster_confidence

    async def cluster(
        self,
        graph: FundFlowGraph,
        tx_cache: Optional[dict[str, list[Transaction]]] = None,
        balance_cache: Optional[dict[str, float]] = None,
    ) -> ClusteringResult:
        """Produce wallet clusters from a fund-flow graph.

        Parameters
        ----------
        graph:
            Output of :class:`TracerAgent.trace`.
        tx_cache:
            Mapping ``address → [Transaction]``.  If ``None``, edges are
            used as the sole signal.
        balance_cache:
            Mapping ``address → balance``.  Optional.
        """
        addresses = _extract_addresses(graph)
        tx_cache = tx_cache or {}
        balance_cache = balance_cache or {}

        logger.info("Clustering %d addresses from fund-flow graph", len(addresses))

        # Union-Find for merging clusters
        parent: dict[str, str] = {a: a for a in addresses}
        confidence_map: dict[tuple[str, str], float] = {}

        def _find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def _union(x: str, y: str) -> None:
            rx, ry = _find(x), _find(y)
            if rx != ry:
                parent[ry] = rx

        # Pairwise scoring (ok for <500 addresses)
        addr_list = list(addresses)
        for i in range(len(addr_list)):
            for j in range(i + 1, len(addr_list)):
                a, b = addr_list[i], addr_list[j]
                txs_a = tx_cache.get(a, [])
                txs_b = tx_cache.get(b, [])

                si = _shared_input_score(txs_a, txs_b)
                temp = _temporal_overlap_score(txs_a, txs_b)
                bal = _balance_correlation(
                    balance_cache.get(a, 0), balance_cache.get(b, 0)
                )

                combined = 0.4 * si + 0.35 * temp + 0.25 * bal
                if (
                    combined >= self._min_confidence
                    and si >= self._si_thresh
                    and (temp >= self._temp_thresh or bal >= self._bal_thresh)
                ):
                    _union(a, b)
                    confidence_map[(a, b)] = combined

        # Build clusters
        groups: dict[str, list[str]] = defaultdict(list)
        for a in addr_list:
            groups[_find(a)].append(a)

        clusters: list[WalletCluster] = []
        for root, members in groups.items():
            if len(members) < 2:
                continue
            # Compute average pairwise confidence within cluster
            pair_confs = [
                confidence_map.get((a, b), confidence_map.get((b, a), 0.0))
                for a in members
                for b in members
                if a < b
            ]
            avg_conf = sum(pair_confs) / max(len(pair_confs), 1) if pair_confs else 0.0

            clusters.append(
                WalletCluster(
                    cluster_id=f"CL-{uuid.uuid4().hex[:8]}",
                    addresses=members,
                    confidence=round(avg_conf, 4),
                    shared_inputs=int(
                        sum(
                            _shared_input_score(
                                tx_cache.get(a, []), tx_cache.get(b, [])
                            )
                            for a in members
                            for b in members
                            if a < b
                        )
                        * len(members)
                    ),
                    temporal_overlap=round(
                        sum(
                            _temporal_overlap_score(
                                tx_cache.get(a, []), tx_cache.get(b, [])
                            )
                            for a in members
                            for b in members
                            if a < b
                        )
                        / max(len(members) * (len(members) - 1) / 2, 1),
                        4,
                    ),
                )
            )

        result = ClusteringResult(
            target_address=graph.root_address,
            clusters=clusters,
            total_wallets_analyzed=len(addresses),
        )

        logger.info(
            "Clustering complete: %d clusters from %d addresses",
            len(clusters),
            len(addresses),
        )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_addresses(graph: FundFlowGraph) -> set[str]:
    addrs = {graph.root_address}
    for edge in graph.edges:
        addrs.add(edge.from_address)
        addrs.add(edge.to_address)
    return addrs
