"""Forensic report generator agent.

Assembles structured findings from the tracer, clusterer, and intent
agents into a court-grade forensic report with evidence chains and
executive summary.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Protocol

from mimo_forensics.models import (
    ClusteringResult,
    Finding,
    ForensicsReport,
    FundFlowGraph,
    IntentAssessment,
    RiskLevel,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MiMo client (for summary generation)
# ---------------------------------------------------------------------------

class MiMoClient(Protocol):
    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        model: str = "mimo-v2.5-100t",
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> dict: ...


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ReporterAgent:
    """Generates forensic investigation reports.

    Combines outputs from all analysis stages into a structured
    ``ForensicsReport`` with:
    - Executive summary (generated via MiMo)
    - Structured findings with evidence chains
    - Risk assessment
    - Methodology disclosure
    """

    def __init__(self, mimo_client: Optional[MiMoClient] = None) -> None:
        self._client = mimo_client

    async def generate(
        self,
        address: str,
        chain: str,
        fund_flow: Optional[FundFlowGraph] = None,
        clustering: Optional[ClusteringResult] = None,
        intents: Optional[list[IntentAssessment]] = None,
        *,
        custom_findings: Optional[list[Finding]] = None,
    ) -> ForensicsReport:
        """Assemble a complete forensic report.

        Generates an executive summary via MiMo (if client available),
        constructs findings from intent assessments, and computes an
        overall risk level.
        """
        intents = intents or []
        findings = list(custom_findings or [])

        # --- Generate findings from intents ---
        for i, intent in enumerate(intents):
            if intent.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                findings.append(
                    Finding(
                        finding_id=f"INT-{uuid.uuid4().hex[:8]}",
                        category="intent",
                        description=(
                            f"Address {intent.address[:10]}… shows "
                            f"{intent.primary_intent.value} behavior "
                            f"(confidence: {intent.confidence:.0%})"
                        ),
                        evidence=intent.reasoning_chain[:5],
                        confidence=intent.confidence,
                        risk_level=intent.risk_level,
                    )
                )

        # --- Generate findings from clustering ---
        if clustering and clustering.clusters:
            for cl in clustering.clusters:
                if cl.confidence >= 0.6 and len(cl.addresses) >= 3:
                    findings.append(
                        Finding(
                            finding_id=f"CLU-{uuid.uuid4().hex[:8]}",
                            category="clustering",
                            description=(
                                f"Cluster {cl.cluster_id} contains "
                                f"{len(cl.addresses)} wallets "
                                f"(confidence: {cl.confidence:.0%})"
                            ),
                            evidence=cl.addresses[:5],
                            confidence=cl.confidence,
                            risk_level=(
                                RiskLevel.MEDIUM
                                if cl.confidence < 0.8
                                else RiskLevel.HIGH
                            ),
                        )
                    )

        # --- Generate findings from fund flow ---
        if fund_flow:
            hotspots = self._detect_flow_anomalies(fund_flow)
            for anomaly in hotspots:
                findings.append(anomaly)

        # --- Compute overall risk ---
        overall_risk = self._aggregate_risk(findings)

        # --- Generate executive summary ---
        summary = await self._generate_summary(
            address, fund_flow, clustering, intents, findings
        )

        # --- Token usage ---
        total_tokens = sum(i.tokens_used for i in intents)

        report = ForensicsReport(
            report_id=f"RPT-{uuid.uuid4().hex[:12]}",
            target_address=address,
            chain=chain,
            investigation_date=datetime.now(timezone.utc),
            fund_flow=fund_flow,
            clustering=clustering,
            intents=intents,
            findings=findings,
            executive_summary=summary,
            risk_level=overall_risk,
            total_tokens_consumed=total_tokens,
        )

        logger.info(
            "Report %s generated: %d findings, overall risk=%s, %d tokens",
            report.report_id,
            len(findings),
            overall_risk.value,
            total_tokens,
        )
        return report

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    async def _generate_summary(
        self,
        address: str,
        fund_flow: Optional[FundFlowGraph],
        clustering: Optional[ClusteringResult],
        intents: list[IntentAssessment],
        findings: list[Finding],
    ) -> str:
        """Generate a human-readable executive summary."""
        if self._client is None:
            return self._fallback_summary(address, fund_flow, clustering, intents, findings)

        prompt = (
            f"Write a concise executive summary (150-300 words) for a blockchain "
            f"forensic investigation of address {address}.\n\n"
            f"Key facts:\n"
            f"- Addresses analyzed: {fund_flow.total_addresses if fund_flow else 'N/A'}\n"
            f"- Transactions traced: {fund_flow.total_transactions if fund_flow else 'N/A'}\n"
            f"- Value traced: {fund_flow.total_value_traced if fund_flow else 'N/A'}\n"
            f"- Wallet clusters found: {len(clustering.clusters) if clustering else 0}\n"
            f"- Intent assessments: {len(intents)}\n"
            f"- Findings: {len(findings)}\n"
            f"- Overall risk level: {self._aggregate_risk(findings).value}\n\n"
            f"Top findings:\n"
        )
        for f in findings[:5]:
            prompt += f"- [{f.risk_level.value.upper()}] {f.description}\n"

        try:
            response = await self._client.chat_completion(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are a forensic analyst writing an executive summary. "
                            "Be factual, concise, and professional. Avoid speculation."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                model="mimo-v2.5-100t",
                temperature=0.2,
                max_tokens=512,
            )
            return response.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as exc:
            logger.warning("MiMo summary generation failed: %s", exc)
            return self._fallback_summary(address, fund_flow, clustering, intents, findings)

    @staticmethod
    def _fallback_summary(
        address: str,
        fund_flow: Optional[FundFlowGraph],
        clustering: Optional[ClusteringResult],
        intents: list[IntentAssessment],
        findings: list[Finding],
    ) -> str:
        parts = [
            f"Forensic investigation of address {address}.",
            f"Analyzed {fund_flow.total_addresses if fund_flow else 0} addresses "
            f"and {fund_flow.total_transactions if fund_flow else 0} transactions."
            if fund_flow
            else "",
            f"Identified {len(clustering.clusters) if clustering else 0} wallet clusters."
            if clustering
            else "",
        ]
        if intents:
            top = max(intents, key=lambda i: i.confidence)
            parts.append(
                f"Primary intent detected: {top.primary_intent.value} "
                f"(confidence {top.confidence:.0%})."
            )
        if findings:
            critical = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
            high = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
            parts.append(f"Findings: {critical} critical, {high} high severity.")
        return " ".join(p for p in parts if p)

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_flow_anomalies(graph: FundFlowGraph) -> list[Finding]:
        """Heuristic anomaly detection on fund-flow edges."""
        findings: list[Finding] = []
        if not graph.edges:
            return findings

        avg_value = graph.total_value_traced / max(len(graph.edges), 1)

        for edge in graph.edges:
            # Flag unusually high-value single edges
            if edge.total_value > avg_value * 10 and edge.tx_count == 1:
                findings.append(
                    Finding(
                        finding_id=f"FLW-{uuid.uuid4().hex[:8]}",
                        category="fund_flow_anomaly",
                        description=(
                            f"Anomalous single-transaction flow: "
                            f"{edge.from_address[:10]}… → {edge.to_address[:10]}… "
                            f"({edge.total_value:.4f} {edge.token_symbol}, "
                            f"{edge.total_value / max(avg_value, 0.001):.1f}x average)"
                        ),
                        evidence=[
                            f"From: {edge.from_address}",
                            f"To: {edge.to_address}",
                            f"Value: {edge.total_value} {edge.token_symbol}",
                        ],
                        confidence=0.7,
                        risk_level=RiskLevel.MEDIUM,
                    )
                )

        return findings

    @staticmethod
    def _aggregate_risk(findings: list[Finding]) -> RiskLevel:
        """Return the highest risk level among all findings."""
        priority = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
        }
        if not findings:
            return RiskLevel.LOW
        best = max(findings, key=lambda f: priority.get(f.risk_level, 0))
        return best.risk_level

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(report: ForensicsReport) -> str:
        """Serialize report to JSON string."""
        return report.model_dump_json(indent=2)

    @staticmethod
    def evidence_chain_hash(report: ForensicsReport) -> str:
        """SHA-256 hash of the report content for integrity verification."""
        content = report.model_dump_json(sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
