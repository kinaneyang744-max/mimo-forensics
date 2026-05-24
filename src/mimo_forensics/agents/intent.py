"""Intent detection agent powered by Xiaomi MiMo V2.5.

Uses MiMo's long-chain reasoning to infer the behavioral intent behind
observed transaction patterns — distinguishing legitimate transfers from
mixing, layering, peeling chains, and other obfuscation techniques.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional, Protocol

from mimo_forensics.models import (
    FundFlowGraph,
    IntentAssessment,
    IntentType,
    RiskLevel,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MiMo client protocol
# ---------------------------------------------------------------------------

class MiMoClient(Protocol):
    """Minimal interface for the MiMo V2.5 API."""

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        model: str = "mimo-v2.5-100t",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Return OpenAI-compatible chat completion response."""
        ...


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert blockchain forensic analyst with deep knowledge of:
- On-chain transaction patterns (peeling chains, mixers, tumblers)
- Tornado Cash and privacy protocol mechanics
- Cross-chain bridge abuse patterns
- Layering and structuring techniques used in money laundering
- Wallet behavioral fingerprinting

You reason step-by-step through long chains of evidence. For each analysis,
output a JSON object with these exact fields:
{
  "primary_intent": "<one of: legitimate, mixing, layering, peeling_chain, tornado_cash, bridge_hop, sandblaster, unknown>",
  "confidence": <0.0 to 1.0>,
  "risk_level": "<one of: low, medium, high, critical>",
  "reasoning_chain": ["step 1 reasoning", "step 2 reasoning", ...],
  "indicators": ["indicator 1", "indicator 2", ...]
}

Be precise and evidence-based. Never speculate without citing the data.
"""

INVESTIGATION_PROMPT_TEMPLATE = """\
## On-Chain Investigation Task

**Target address:** {address}
**Fund flow summary:**
- Total addresses traced: {total_addresses}
- Total transactions: {total_transactions}
- Total value traced: {total_value}
- Max depth: {max_depth}

**Top fund flows (from → to, value, count):**
{flow_summary}

**Wallet cluster info:**
{cluster_info}

**Known labels / risk tags for involved addresses:**
{labels}

---

Analyze the above data using deep chain-of-thought reasoning. Determine
the primary intent behind this wallet's activity. Return your assessment
as a JSON object matching the schema in your system instructions.
"""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class IntentAgent:
    """Infers transaction intent using MiMo V2.5 long-chain reasoning.

    This agent feeds structured on-chain data to MiMo and parses its
    chain-of-thought output into validated ``IntentAssessment`` objects.
    """

    def __init__(
        self,
        mimo_client: MiMoClient,
        *,
        model: str = "mimo-v2.5-100t",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self._client = mimo_client
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens

    async def assess(
        self,
        address: str,
        graph: FundFlowGraph,
        *,
        labels: Optional[dict[str, str]] = None,
        cluster_summary: Optional[str] = None,
    ) -> IntentAssessment:
        """Run MiMo reasoning on *address* and its fund-flow graph.

        Returns a validated ``IntentAssessment`` with the full reasoning
        chain and token usage stats.
        """
        prompt = self._build_prompt(address, graph, labels, cluster_summary)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        logger.info("Invoking MiMo V2.5 for intent analysis of %s", address)

        response = await self._client.chat_completion(
            messages,
            model=self._model,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        # Parse response
        choice = response.get("choices", [{}])[0]
        content = choice.get("message", {}).get("content", "{}")
        usage = response.get("usage", {})
        tokens_used = usage.get("total_tokens", 0)

        assessment = self._parse_response(address, content)
        assessment.tokens_used = tokens_used

        logger.info(
            "MiMo assessment for %s: intent=%s confidence=%.2f tokens=%d",
            address,
            assessment.primary_intent.value,
            assessment.confidence,
            tokens_used,
        )
        return assessment

    async def assess_cluster(
        self,
        cluster_id: str,
        addresses: list[str],
        graph: FundFlowGraph,
        *,
        labels: Optional[dict[str, str]] = None,
    ) -> IntentAssessment:
        """Assess the collective intent of a wallet cluster."""
        cluster_summary = (
            f"Cluster {cluster_id} contains {len(addresses)} addresses: "
            f"{', '.join(addresses[:10])}"
            + (f" ... and {len(addresses) - 10} more" if len(addresses) > 10 else "")
        )

        # Use first address as representative for the prompt
        primary = addresses[0]
        return await self.assess(
            primary, graph, labels=labels, cluster_summary=cluster_summary
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        address: str,
        graph: FundFlowGraph,
        labels: Optional[dict[str, str]],
        cluster_summary: Optional[str],
    ) -> str:
        # Summarize top flows
        sorted_edges = sorted(graph.edges, key=lambda e: e.total_value, reverse=True)[:15]
        flow_lines = [
            f"  {e.from_address[:10]}… → {e.to_address[:10]}… "
            f"| {e.total_value:.4f} {e.token_symbol} | {e.tx_count} txs"
            for e in sorted_edges
        ]
        flow_summary = "\n".join(flow_lines) if flow_lines else "  (no edges)"

        # Label info
        if labels:
            label_lines = [f"  {a}: {l}" for a, l in list(labels.items())[:20]]
            labels_str = "\n".join(label_lines)
        else:
            labels_str = "  (none)"

        return INVESTIGATION_PROMPT_TEMPLATE.format(
            address=address,
            total_addresses=graph.total_addresses,
            total_transactions=graph.total_transactions,
            total_value=f"{graph.total_value_traced:.4f}",
            max_depth=graph.max_depth,
            flow_summary=flow_summary,
            cluster_info=cluster_summary or "  (not available)",
            labels=labels_str,
        )

    def _parse_response(self, address: str, content: str) -> IntentAssessment:
        """Parse MiMo's JSON response into a validated IntentAssessment."""
        # Try to extract JSON from the response
        parsed: dict = {}
        try:
            # Handle markdown code blocks
            text = content.strip()
            if "```" in text:
                # Extract JSON from code block
                start = text.find("{")
                end = text.rfind("}") + 1
                if start >= 0 and end > start:
                    text = text[start:end]
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse MiMo response as JSON; using defaults")
            parsed = {
                "primary_intent": "unknown",
                "confidence": 0.0,
                "risk_level": "low",
                "reasoning_chain": [content[:500]],
                "indicators": [],
            }

        return IntentAssessment(
            address=address,
            primary_intent=IntentType(parsed.get("primary_intent", "unknown")),
            confidence=min(max(parsed.get("confidence", 0.0), 0.0), 1.0),
            reasoning_chain=parsed.get("reasoning_chain", []),
            risk_level=RiskLevel(parsed.get("risk_level", "low")),
            indicators=parsed.get("indicators", []),
        )
