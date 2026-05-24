"""Tests for Pydantic data models."""

import json
from datetime import datetime, timezone

import pytest

from mimo_forensics.models import (
    Chain,
    FundFlow,
    FundFlowEdge,
    InvestigationReport,
    InvestigationRequest,
    IntentClassification,
    MiMoPrompt,
    MiMoResponse,
    RiskAssessment,
    RiskLevel,
    Transaction,
    TransactionIntent,
    TransactionType,
    WalletAddress,
    WalletAnalysis,
    WalletCluster,
)


class TestEnums:
    """Test enum definitions and values."""

    def test_chain_values(self):
        assert Chain.ETHEREUM.value == "ethereum"
        assert Chain.ARBITRUM.value == "arbitrum"

    def test_risk_level_ordering(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_transaction_type_completeness(self):
        types = list(TransactionType)
        assert len(types) >= 8

    def test_intent_classification_completeness(self):
        classifications = list(IntentClassification)
        assert "wash_trading" in [c.value for c in classifications]
        assert "layering" in [c.value for c in classifications]
        assert "peel_chain" in [c.value for c in classifications]


class TestWalletAddress:
    """Test WalletAddress model."""

    def test_basic_creation(self):
        addr = WalletAddress(address="0x1234567890abcdef1234567890abcdef12345678")
        assert addr.chain == Chain.ETHEREUM
        assert addr.is_contract is False
        assert addr.label is None

    def test_with_metadata(self):
        addr = WalletAddress(
            address="0xdeadbeef",
            chain=Chain.ARBITRUM,
            label="Known Exchange",
            is_contract=True,
        )
        assert addr.chain == Chain.ARBITRUM
        assert addr.label == "Known Exchange"
        assert addr.is_contract is True


class TestTransaction:
    """Test Transaction model."""

    def test_creation(self):
        tx = Transaction(
            hash="0xabc123",
            chain=Chain.ETHEREUM,
            block_number=18000000,
            timestamp=datetime.now(timezone.utc),
            from_address=WalletAddress(address="0x1111"),
            to_address=WalletAddress(address="0x2222"),
            value_eth=1.5,
            gas_used=21000,
            gas_price_gwei=30.0,
        )
        assert tx.hash == "0xabc123"
        assert tx.value_eth == 1.5
        assert tx.tx_type == TransactionType.TRANSFER

    def test_value_must_be_non_negative(self):
        with pytest.raises(Exception):
            Transaction(
                hash="0xabc",
                chain=Chain.ETHEREUM,
                block_number=1,
                timestamp=datetime.now(timezone.utc),
                from_address=WalletAddress(address="0x1"),
                to_address=WalletAddress(address="0x2"),
                value_eth=-1.0,
                gas_used=21000,
                gas_price_gwei=30.0,
            )


class TestFundFlow:
    """Test FundFlow model."""

    def test_empty_flow(self):
        flow = FundFlow(root_address="0x1234")
        assert flow.total_hops == 0
        assert len(flow.edges) == 0

    def test_flow_with_edges(self):
        edge = FundFlowEdge(
            source="0xaaa",
            destination="0xbbb",
            amount_eth=2.0,
            chain=Chain.ETHEREUM,
            timestamp=datetime.now(timezone.utc),
            transaction_hash="0xhash",
            tx_type=TransactionType.TRANSFER,
            hop=1,
        )
        flow = FundFlow(root_address="0xaaa", edges=[edge])
        assert flow.total_value_eth == 2.0


class TestWalletCluster:
    """Test WalletCluster model."""

    def test_cluster_creation(self):
        cluster = WalletCluster(
            cluster_id="c-001",
            wallets=[
                WalletAddress(address="0xaaa"),
                WalletAddress(address="0xbbb"),
            ],
            confidence=0.85,
            evidence=["Shared gas patterns", "Temporal correlation"],
        )
        assert cluster.confidence == 0.85
        assert len(cluster.wallets) == 2
        assert cluster.risk_level == RiskLevel.LOW


class TestTransactionIntent:
    """Test TransactionIntent model."""

    def test_intent_creation(self):
        intent = TransactionIntent(
            classification=IntentClassification.PEEL_CHAIN,
            confidence=0.92,
            reasoning_chain=[
                "Observed fund splitting at hop 1",
                "Value decreases progressively",
                "Pattern matches known peel chain",
            ],
            risk_score=0.85,
            tags=["peel_chain", "obfuscation"],
            explanation="Strong evidence of peel chain obfuscation.",
        )
        assert intent.classification == IntentClassification.PEEL_CHAIN
        assert len(intent.reasoning_chain) == 3


class TestRiskAssessment:
    """Test RiskAssessment model."""

    def test_critical_risk(self):
        assessment = RiskAssessment(
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.95,
            summary="Critical: Mixer usage detected",
            flags=["Mixer interaction", "Cross-chain bridging"],
            recommendations=["File SAR immediately"],
        )
        assert assessment.risk_level == RiskLevel.CRITICAL


class TestInvestigationModels:
    """Test investigation request/response models."""

    def test_request_defaults(self):
        req = InvestigationRequest(target="0x1234")
        assert req.chains == [Chain.ETHEREUM]
        assert req.depth == 5
        assert req.include_contracts is True

    def test_request_validation(self):
        with pytest.raises(Exception):
            InvestigationRequest(target="0x1234", depth=0)

    def test_report_export_json(self, tmp_path):
        report = InvestigationReport(
            investigation_id="inv-test-001",
            request=InvestigationRequest(target="0x1234"),
            started_at=datetime.now(timezone.utc),
        )
        output_path = str(tmp_path / "test_report.json")
        report.export_json(output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data["investigation_id"] == "inv-test-001"
        assert data["status"] == "running"

    def test_report_risk_summary_empty(self):
        report = InvestigationReport(
            investigation_id="inv-empty",
            request=InvestigationRequest(target="0x1234"),
            started_at=datetime.now(timezone.utc),
        )
        assert report.get_risk_summary() == "No risk assessment available."

    def test_report_risk_summary_with_assessment(self):
        report = InvestigationReport(
            investigation_id="inv-risk",
            request=InvestigationRequest(target="0x1234"),
            started_at=datetime.now(timezone.utc),
            risk_assessment=RiskAssessment(
                risk_level=RiskLevel.HIGH,
                risk_score=0.75,
                summary="High risk activity detected",
            ),
        )
        summary = report.get_risk_summary()
        assert "HIGH" in summary
        assert "High risk" in summary


class TestMiMoModels:
    """Test MiMo prompt and response models."""

    def test_prompt_creation(self):
        prompt = MiMoPrompt(
            system_prompt="You are a forensic analyst.",
            user_prompt="Analyze this transaction.",
        )
        assert prompt.temperature == 0.3
        assert prompt.max_tokens == 4096

    def test_response_creation(self):
        response = MiMoResponse(
            content='{"classification": "layering"}',
            reasoning_steps=["Step 1", "Step 2"],
            tokens_used=150,
            latency_ms=250.0,
        )
        assert response.model == "mimo-v2.5"
        assert response.tokens_used == 150
