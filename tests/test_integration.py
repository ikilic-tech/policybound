"""End-to-end integration tests.

Tests the complete flow:
Agent -> PolicyGate -> Decision -> DecisionRecord -> Receipt -> Verification
"""

from __future__ import annotations

import json

from policybound.gate import PolicyGate
from policybound.receipt import load_receipt, save_receipt, verify_receipt
from policybound.types import Verdict


class TestEndToEndFlow:
    """Test the complete governance flow from check to verification."""

    def test_allow_flow(self, policy_path, db_path, tmp_dir):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        # Agent requests action
        result = gate.check(
            agent="sales-agent",
            tool="crm.read",
            arguments={"customer_id": "123"},
        )

        # Verify decision
        assert result.allowed is True
        assert result.verdict == Verdict.ALLOW
        assert result.decision.rule_name == "allow-crm-read"

        # Record was persisted
        assert result.record is not None
        assert result.record.sequence == 1
        assert result.record.record_hash

        # Receipt was generated
        assert result.receipt is not None

        # Save and verify receipt independently
        receipt_path = tmp_dir / "receipt.json"
        save_receipt(result.receipt, receipt_path)
        loaded = load_receipt(receipt_path)
        verification = verify_receipt(loaded)
        assert verification.valid is True
        assert verification.agent == "sales-agent"
        assert verification.tool == "crm.read"

    def test_deny_flow(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        result = gate.check(
            agent="ops-agent",
            tool="database.delete",
            context={"environment": "production"},
        )

        assert result.denied is True
        assert result.verdict == Verdict.DENY
        assert result.decision.rule_name == "deny-production-delete"

        # Even denied actions are recorded
        assert result.record is not None
        assert result.receipt is not None

        # Receipt is valid even for denials
        verification = verify_receipt(result.receipt)
        assert verification.valid is True
        assert verification.verdict == "deny"

    def test_escalate_flow(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        result = gate.check(
            agent="finance-agent",
            tool="payments.refund",
            arguments={"amount": 5000, "reason": "customer complaint"},
        )

        assert result.escalated is True
        assert result.verdict == Verdict.ESCALATE
        assert result.decision.rule_name == "require-approval-for-refund"

    def test_chain_integrity_after_multiple_decisions(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        # Multiple decisions
        gate.check(agent="a", tool="crm.read")
        gate.check(agent="a", tool="crm.update", arguments={"customer_id": "123"})
        gate.check(agent="b", tool="database.delete", context={"environment": "production"})
        gate.check(agent="c", tool="payments.refund", arguments={"amount": 5000})
        gate.check(agent="a", tool="unknown.tool")  # default deny

        # Verify the entire chain
        assert gate.verify_ledger() is True

    def test_receipt_verification_with_explicit_key(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        result = gate.check(agent="a", tool="crm.read")

        # Verify with the gate's public key
        verification = verify_receipt(result.receipt, gate.public_key)
        assert verification.valid is True

    def test_receipt_tamper_detection(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        result = gate.check(agent="a", tool="crm.read")
        receipt = result.receipt

        # Tamper with the receipt
        tampered = json.loads(json.dumps(receipt))
        tampered["record"]["decision"]["verdict"] = "deny"

        verification = verify_receipt(tampered)
        assert verification.valid is False

    def test_multiple_agents_independent_verification(self, policy_path, db_path, tmp_dir):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        # Different agents, different actions
        r1 = gate.check(agent="agent-1", tool="crm.read")
        r2 = gate.check(agent="agent-2", tool="crm.update", arguments={"customer_id": "456"})

        # Save receipts
        save_receipt(r1.receipt, tmp_dir / "r1.json")
        save_receipt(r2.receipt, tmp_dir / "r2.json")

        # Verify independently
        v1 = verify_receipt(load_receipt(tmp_dir / "r1.json"))
        v2 = verify_receipt(load_receipt(tmp_dir / "r2.json"))

        assert v1.valid is True
        assert v1.agent == "agent-1"
        assert v2.valid is True
        assert v2.agent == "agent-2"
