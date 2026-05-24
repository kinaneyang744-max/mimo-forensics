"""Pydantic data contracts for the MiMo Forensics system.

All inter-agent data flows are validated through these models to ensure
type safety and schema consistency across the investigation pipeline.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TransactionType(str, enum.Enum):
    TRANSFER = "transfer"
    SWAP = "swap"
    BRIDGE = "bridge"
    MINT = "mint"
    BURN = "burn"
    LIQUIDITY = "liquidity"
    UNKNOWN = "unknown"


class IntentType(str, enum.Enum):
    LEGITIMATE = "legitimate"
    MIXING = "mixing"
    LAYERING = "layering"
    PEELING_CHAIN = "peeling_chain"
    TORNADO_CASH = "tornado_cash"
    BRIDGE_HOP = "bridge_hop"
    SANDBLASTER = "sandblaster"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# On-chain data primitives
# ---------------------------------------------------------------------------

class Address(BaseModel):
    """A blockchain address with optional metadata."""
    address: str = Field(..., description="Checksummed hex address")
    chain: str = Field(default="ethereum", description="Chain identifier")
    label: Optional[str] = Field(default=None, description="Known label (e.g. 'Binance')")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class Transaction(BaseModel):
    """A single on-chain transaction."""
    tx_hash: str
    from_address: str
    to_address: str
    value: float = Field(description="Value in native token (e.g. ETH)")
    token_symbol: str = Field(default="ETH")
    timestamp: datetime
    tx_type: TransactionType = TransactionType.TRANSFER
    gas_used: Optional[float] = None
    block_number: Optional[int] = None
    input_data: Optional[str] = None


# ---------------------------------------------------------------------------
# Tracer agent outputs
# ---------------------------------------------------------------------------

class FundFlowEdge(BaseModel):
    """An edge in the fund-flow graph."""
    from_address: str
    to_address: str
    total_value: float
    tx_count: int
    first_seen: datetime
    last_seen: datetime
    token_symbol: str = "ETH"


class FundFlowGraph(BaseModel):
    """Complete fund-flow graph for a traced address."""
    root_address: str
    edges: list[FundFlowEdge] = Field(default_factory=list)
    total_addresses: int = 0
    total_transactions: int = 0
    total_value_traced: float = 0.0
    max_depth: int = 0


# ---------------------------------------------------------------------------
# Cluster agent outputs
# ---------------------------------------------------------------------------

class WalletCluster(BaseModel):
    """A cluster of wallets believed to be controlled by the same entity."""
    cluster_id: str
    addresses: list[str] = Field(min_length=2)
    confidence: float = Field(ge=0.0, le=1.0, description="Clustering confidence")
    shared_inputs: int = Field(default=0, description="TXs with shared inputs")
    temporal_overlap: float = Field(default=0.0, description="0-1 temporal correlation")
    balance_correlation: float = Field(default=0.0)


class ClusteringResult(BaseModel):
    """Full output of the clustering analysis."""
    target_address: str
    clusters: list[WalletCluster] = Field(default_factory=list)
    total_wallets_analyzed: int = 0


# ---------------------------------------------------------------------------
# Intent agent outputs
# ---------------------------------------------------------------------------

class IntentAssessment(BaseModel):
    """MiMo's assessment of a wallet's or cluster's behavioral intent."""
    address: str
    primary_intent: IntentType
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_chain: list[str] = Field(
        default_factory=list,
        description="Step-by-step reasoning from MiMo",
    )
    risk_level: RiskLevel = RiskLevel.LOW
    indicators: list[str] = Field(default_factory=list)
    tokens_used: int = Field(default=0, description="MiMo tokens consumed")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single forensic finding."""
    finding_id: str
    category: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel


class ForensicsReport(BaseModel):
    """Complete forensic investigation report."""
    report_id: str
    target_address: str
    chain: str
    investigation_date: datetime = Field(default_factory=datetime.utcnow)
    fund_flow: Optional[FundFlowGraph] = None
    clustering: Optional[ClusteringResult] = None
    intents: list[IntentAssessment] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    executive_summary: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    total_tokens_consumed: int = 0
    methodology: str = (
        "Automated on-chain analysis with Xiaomi MiMo V2.5 long-chain reasoning"
    )
