"""Main orchestrator for the MiMo Forensics investigation pipeline.

Coordinates the tracer → clusterer → intent → reporter pipeline,
managing shared state and MiMo API interactions across all agents.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from mimo_forensics.agents.cluster import ClusterAgent
from mimo_forensics.agents.intent import IntentAgent
from mimo_forensics.agents.reporter import ReporterAgent
from mimo_forensics.agents.tracer import ChainDataProvider, TracerAgent
from mimo_forensics.models import (
    ForensicsReport,
    FundFlowGraph,
    ClusteringResult,
    IntentAssessment,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MiMo API client (OpenAI-compatible)
# ---------------------------------------------------------------------------

@dataclass
class MiMoConfig:
    """Configuration for the MiMo V2.5 API."""
    api_key: str
    base_url: str = "https://api.mimo.xiaomi.com/v1"
    model: str = "mimo-v2.5-100t"
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120


class MiMoClient:
    """OpenAI-compatible client for Xiaomi MiMo V2.5.

    Uses aiohttp for async HTTP requests.
    """

    def __init__(self, config: MiMoConfig) -> None:
        self._config = config

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> dict[str, Any]:
        """Send a chat completion request to MiMo V2.5."""
        import aiohttp

        url = f"{self._config.base_url}/chat/completions"
        payload = {
            "model": model or self._config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self._config.temperature,
            "max_tokens": max_tokens or self._config.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._config.timeout),
            ) as resp:
                resp.raise_for_status()
                return await resp.json()


# ---------------------------------------------------------------------------
# Investigation configuration
# ---------------------------------------------------------------------------

@dataclass
class InvestigationConfig:
    """Parameters for a single investigation run."""
    address: str
    chain: str = "ethereum"
    max_depth: int = 5
    min_value: float = 0.0
    label_lookup: bool = True
    parallel_intent: bool = True


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ForensicsEngine:
    """High-level API for running on-chain forensic investigations.

    Usage::

        engine = ForensicsEngine(api_key="mimo-xxx")
        report = await engine.investigate(
            address="0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38",
            depth=5,
        )
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        data_provider: Optional[ChainDataProvider] = None,
        mimo_config: Optional[MiMoConfig] = None,
    ) -> None:
        self._api_key = api_key or os.getenv("MIMO_API_KEY", "")
        self._mimo_config = mimo_config or MiMoConfig(api_key=self._api_key)
        self._client = MiMoClient(self._mimo_config)
        self._data_provider = data_provider

        # Initialize agents
        self._tracer = TracerAgent(
            data_provider=data_provider,  # type: ignore[arg-type]
        )
        self._clusterer = ClusterAgent()
        self._intent = IntentAgent(self._client)
        self._reporter = ReporterAgent(self._client)

    async def investigate(
        self,
        address: str,
        *,
        chain: str = "ethereum",
        depth: int = 5,
        min_value: float = 0.0,
        labels: Optional[dict[str, str]] = None,
    ) -> ForensicsReport:
        """Run a full forensic investigation on *address*.

        Pipeline:
        1. **Trace** fund flows up to *depth* hops
        2. **Cluster** wallets in the flow graph
        3. **Assess intent** using MiMo V2.5 reasoning
        4. **Generate report** with findings and executive summary

        Returns a validated ``ForensicsReport``.
        """
        config = InvestigationConfig(
            address=address,
            chain=chain,
            max_depth=depth,
            min_value=min_value,
        )

        logger.info("=== Investigation started for %s ===", address)
        logger.info("Chain: %s | Depth: %d", chain, depth)

        # Step 1: Trace fund flows
        logger.info("[1/4] Tracing fund flows…")
        graph = await self._tracer.trace(address)
        graph.max_depth = depth
        logger.info(
            "  → %d addresses, %d edges, %.4f total value",
            graph.total_addresses,
            len(graph.edges),
            graph.total_value_traced,
        )

        # Step 2: Cluster wallets
        logger.info("[2/4] Clustering wallets…")
        clustering = await self._clusterer.cluster(graph)
        logger.info("  → %d clusters from %d wallets",
                     len(clustering.clusters),
                     clustering.total_wallets_analyzed)

        # Step 3: MiMo intent analysis
        logger.info("[3/4] Running MiMo intent analysis…")
        intents = await self._assess_intents(address, graph, labels)
        logger.info("  → %d intent assessments, %d total tokens",
                     len(intents),
                     sum(i.tokens_used for i in intents))

        # Step 4: Generate report
        logger.info("[4/4] Generating forensic report…")
        report = await self._reporter.generate(
            address=address,
            chain=chain,
            fund_flow=graph,
            clustering=clustering,
            intents=intents,
        )

        logger.info("=== Investigation complete: %s ===", report.report_id)
        return report

    async def _assess_intents(
        self,
        address: str,
        graph: FundFlowGraph,
        labels: Optional[dict[str, str]],
    ) -> list[IntentAssessment]:
        """Run intent analysis on the target and any clustered wallets."""
        intents: list[IntentAssessment] = []

        # Primary address
        primary = await self._intent.assess(address, graph, labels=labels)
        intents.append(primary)

        # Cluster representatives
        # (In production, we'd resolve clusters here and assess each)

        return intents

    # ------------------------------------------------------------------
    # CLI entry point
    # ------------------------------------------------------------------

    @classmethod
    async def run_cli(cls) -> None:
        """CLI entry point for ``python -m mimo_forensics.forensics``."""
        import argparse

        parser = argparse.ArgumentParser(
            description="MiMo Forensics — On-Chain Investigation Engine"
        )
        parser.add_argument(
            "--address", "-a", required=True, help="Target address to investigate"
        )
        parser.add_argument(
            "--depth", "-d", type=int, default=5, help="Max trace depth"
        )
        parser.add_argument(
            "--chain", "-c", default="ethereum", help="Chain identifier"
        )
        parser.add_argument(
            "--output", "-o", default="report.json", help="Output file path"
        )
        parser.add_argument(
            "--verbose", "-v", action="store_true", help="Verbose logging"
        )
        args = parser.parse_args()

        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

        engine = cls()
        report = await engine.investigate(
            address=args.address,
            chain=args.chain,
            depth=args.depth,
        )

        # Write report
        from mimo_forensics.agents.reporter import ReporterAgent
        import json

        report_json = ReporterAgent.to_json(report)
        with open(args.output, "w") as f:
            f.write(report_json)

        logger.info("Report written to %s", args.output)
        print(f"\n✅ Investigation complete: {report.report_id}")
        print(f"   Risk level: {report.risk_level.value}")
        print(f"   Findings: {len(report.findings)}")
        print(f"   Report: {args.output}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Synchronous wrapper for the async CLI."""
    asyncio.run(ForensicsEngine.run_cli())


if __name__ == "__main__":
    main()
