"""PolicyBound — Lightweight governance middleware for AI agents.

PolicyBound helps developers add governance to existing AI agents
without adopting a full governance platform. Every agent action is
evaluated against a declarative policy, recorded in a tamper-evident
ledger, and optionally wrapped in a verifiable receipt.

Quick start:

    from policybound import PolicyGate

    gate = PolicyGate.from_file("policybound.yaml")

    result = gate.check(
        agent="sales-agent",
        tool="crm.update",
        arguments={"customer_id": "123"},
    )

    if result.allowed:
        execute_tool(...)
    elif result.escalated:
        request_approval(result)
    else:
        log_denial(result)
"""

from policybound.errors import (
    InvalidPolicyError,
    LedgerError,
    LedgerTamperError,
    PolicyBoundError,
    PolicyDeniedError,
    PolicyEscalationError,
    PolicyEvaluationError,
    SigningError,
    VerificationError,
)
from policybound.gate import GateResult, PolicyGate
from policybound.ledger import DecisionLedger
from policybound.policy import PolicyEngine, YAMLPolicyEngine
from policybound.receipt import (
    VerificationResult,
    create_receipt,
    load_receipt,
    save_receipt,
    verify_receipt,
)
from policybound.types import ActionRequest, Decision, DecisionRecord, Verdict

__version__ = "0.1.0"

__all__ = [
    "ActionRequest",
    "Decision",
    "DecisionLedger",
    "DecisionRecord",
    "GateResult",
    "InvalidPolicyError",
    "LedgerError",
    "LedgerTamperError",
    "PolicyBoundError",
    "PolicyDeniedError",
    "PolicyEngine",
    "PolicyEscalationError",
    "PolicyEvaluationError",
    "PolicyGate",
    "SigningError",
    "Verdict",
    "VerificationError",
    "VerificationResult",
    "YAMLPolicyEngine",
    "create_receipt",
    "load_receipt",
    "save_receipt",
    "verify_receipt",
]
