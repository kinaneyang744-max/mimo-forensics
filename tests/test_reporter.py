"""Tests for the ReporterAgent."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from mimo_forensics.agents.reporter import ReporterAgent
from mimo_forensics.models import (
    ClusteringResult,
    Finding,
    FundFlowEdge,
    FundFlowGraph,
    IntentAssessment,
    IntentType,
    RiskLevel,
)


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
                total_value=100.0,
                tx_count=10,
                first_seen=base,
                last_seen=base,
            ),
        ],
        total_addresses=2,
        total_transactions=10,
        total_value_traced=100.0,
    )


def _make_intent(address: str = "0x" + "a" * 40) -> IntentAssessment:
    return IntentAssessment(
        address=address,
        primary_intent=IntentType.MIXING,
        confidence=0.92,
        reasoning_chain=["Detected mixing pattern"],
        risk_level=RiskLevel.CRITICAL,
        tokens_used=5000,
    )


def _make_clustering() -> ClusteringResult:
    return ClusteringResult(
        target_address="0x" + "a" * 40,
        total_wallets_analyzed=5,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_basic_report():
    reporter = ReporterAgent()

    report = await reporter.generate(
        address="0x" + "a" * 40,
        chain="ethereum",
        fund_flow=_make_graph(),
        intents=[_make_intent()],
    )

    assert report.target_address == "0x" + "a" * 40
    assert report.chain == "ethereum"
    assert report.total_tokens_consumed == 5000
    assert report.risk_level == RiskLevel.CRITICAL
    assert len(report.findings) >= 1


@pytest.mark.asyncio
async def test_generate_report_with_findings():
    reporter = ReporterAgent()
    custom = Finding(
        finding_id="TEST-001",
        category="manual",
        description="Suspicious behavior observed",
        evidence=["Evidence A"],
        confidence=0.8,
        risk_level=RiskLevel.HIGH,
    )

    report = await reporter.generate(
        address="0x" + "a" * 40,
        chain="ethereum",
        custom_findings=[custom],
    )

    assert any(f.finding_id == "TEST-001" for f in report.findings)


@pytest.mark.asyncio
async def test_to_json():
    reporter = ReporterAgent()

    report = await reporter.generate(
        address="0x" + "a" * 40,
        chain="ethereum",
        intents=[_make_intent()],
    )

    json_str = reporter.to_json(report)
    assert '"report_id"' in json_str
    assert '"target_address"' in json_str


@pytest.mark.asyncio
async def test_evidence_chain_hash():
    reporter = ReporterAgent()

    report = await reporter.generate(
        address="0x" + "a" * 40,
        chain="ethereum",
    )

    h1 = reporter.evidence_chain_hash(report)
    h2 = reporter.evidence_chain_hash(report)

    assert len(h1) == 64  # SHA-256 hex
    assert h1 == h2  # Deterministic


@pytest.mark.asyncio
async def test_report_without_mimo_client():
    """Report generation should work without MiMo (fallback summary)."""
    reporter = ReporterAgent(mimo_client=None)

    report = await reporter.generate(
        address="0x" + "a" * 40,
        chain="ethereum",
        fund_flow=_make_graph(),
        intents=[_make_intent()],
    )

    # Should use fallback summary
    assert len(report.executive_summary) > 0
    assert "investigation" in report.executive_summary.lower()
