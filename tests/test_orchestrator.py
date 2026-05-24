"""Tests for the ForensicsOrchestrator."""

import pytest
from datetime import datetime, timezone

from mimo_forensics.forensics import ForensicsOrchestrator
from mimo_forensics.models import (
    Chain,
    FundFlow,
    FundFlowEdge,
    InvestigationReport,
    InvestigationRequest,
    IntentClassification,
    RiskLevel,
    TransactionIntent,
    TransactionType,
    WalletCluster,
    WalletAddress,
)


class TestForensicsOrchestrator:
    """Test suite for the main orchestrator."""

    def setup_method(self):
        self.orchestrator = ForensicsOrchestrator(
            mimo_api_key="test-key",
            etherscan_api_key="test-etherscan",
            max_depth=5,
            max_workers=4,
        )

    def test_initialization(self):
        assert self.orchestrator.max_depth == 5
        assert self.orchestrator.max_workers == 4

    def test_initialization_defaults(self):
        orch = ForensicsOrchestrator()
        assert orch.max_depth == 5

    @pytest.mark.asyncio
    async def test_investigate_basic(self):
        report = await self.orchestrator.investigate(
            target="0x1234567890abcdef1234567890abcdef12345678",
        )
        assert isinstance(report, InvestigationReport)
        assert report.status == "complete"
        assert report.investigation_id.startswith("inv-")
        assert report.completed_at is not None
        assert report.summary != ""

    @pytest.mark.asyncio
    async def test_investigate_with_custom_params(self):
        report = await self.orchestrator.investigate(
            target="0xabc",
            depth=3,
            chains=["ethereum", "arbitrum"],
            max_results=50,
            include_contracts=False,
            time_range_days=30,
        )
        assert report.request.depth == 3
        assert len(report.request.chains) == 2
        assert report.request.include_contracts is False
        assert report.request.time_range_days == 30

    @pytest.mark.asyncio
    async def test_investigate_generates_risk_assessment(self):
        report = await self.orchestrator.investigate(target="0x1234")
        assert report.risk_assessment is not None
        assert report.risk_assessment.risk_level in list(RiskLevel)
        assert 0.0 <= report.risk_assessment.risk_score <= 1.0

    @pytest.mark.asyncio
    async def test_investigate_agent_logs(self):
        report = await self.orchestrator.investigate(target="0x1234")
        phases = [log["phase"] for log in report.agent_logs]
        assert "tracer" in phases
        assert "clusterer" in phases
        assert "intent_analyst" in phases
        assert "reporter" in phases

    @pytest.mark.asyncio
    async def test_get_investigation_returns_none(self):
        result = self.orchestrator.get_investigation("nonexistent")
        assert result is None

    def test_assess_risk_clean(self):
        risk = ForensicsOrchestrator._assess_risk(
            intents=[],
            clusters=[],
            fund_flow=FundFlow(root_address="0x1234"),
        )
        assert risk.risk_level == RiskLevel.LOW
        assert risk.risk_score == 0.0

    def test_assess_risk_with_high_risk_intents(self):
        intents = [
            TransactionIntent(
                classification=IntentClassification.LAYERING,
                confidence=0.9,
                reasoning_chain=["step1"],
                risk_score=0.8,
            ),
            TransactionIntent(
                classification=IntentClassification.MIXERUsage,
                confidence=0.85,
                reasoning_chain=["step1"],
                risk_score=0.9,
            ),
        ]
        risk = ForensicsOrchestrator._assess_risk(
            intents=intents,
            clusters=[],
            fund_flow=FundFlow(root_address="0x1234", total_hops=3),
        )
        assert risk.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert len(risk.flags) > 0

    def test_assess_risk_complex_flow(self):
        edges = [
            FundFlowEdge(
                source=f"0x{i:040x}",
                destination=f"0x{i+1:040x}",
                amount_eth=1.0,
                chain=Chain.ETHEREUM,
                timestamp=datetime.now(timezone.utc),
                transaction_hash=f"0xhash{i}",
                tx_type=TransactionType.TRANSFER,
                hop=i + 1,
            )
            for i in range(15)
        ]
        flow = FundFlow(
            root_address="0x0",
            edges=edges,
            total_hops=15,
        )
        risk = ForensicsOrchestrator._assess_risk(
            intents=[],
            clusters=[],
            fund_flow=flow,
        )
        assert "Complex fund flow" in " ".join(risk.flags)

    @pytest.mark.asyncio
    async def test_investigate_export_report(self, tmp_path):
        report = await self.orchestrator.investigate(target="0x1234")
        output_path = str(tmp_path / "output" / "report.json")
        report.export_json(output_path)

        import json
        with open(output_path) as f:
            data = json.load(f)
        assert data["investigation_id"] == report.investigation_id
        assert "risk_assessment" in data
