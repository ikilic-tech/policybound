"""Tests for PolicyGate — the main integration point."""

from __future__ import annotations

import pytest

from policybound.errors import PolicyDeniedError, PolicyEscalationError
from policybound.gate import PolicyGate
from policybound.types import Verdict


class TestPolicyGate:
    def test_from_file(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        assert gate.policy_name == "test-policy"
        assert gate.policy_version == "1"

    def test_from_file_with_key(self, policy_path, db_path, key_files):
        priv_path, _ = key_files
        gate = PolicyGate.from_file(policy_path, db_path=db_path, key_path=priv_path)
        assert gate.policy_name == "test-policy"

    def test_from_file_missing_key(self, policy_path, db_path):
        with pytest.raises(FileNotFoundError):
            PolicyGate.from_file(policy_path, db_path=db_path, key_path="/nonexistent.key")

    def test_check_allow(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="crm.read")
        assert result.allowed is True
        assert result.verdict == Verdict.ALLOW
        assert result.record is not None
        assert result.receipt is not None

    def test_check_deny(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(
            agent="a", tool="database.delete",
            context={"environment": "production"},
        )
        assert result.denied is True
        assert result.verdict == Verdict.DENY

    def test_check_escalate(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(
            agent="a", tool="payments.refund",
            arguments={"amount": 5000},
        )
        assert result.escalated is True
        assert result.verdict == Verdict.ESCALATE

    def test_check_default_deny(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="unknown.tool")
        assert result.denied is True
        assert result.decision.rule_name == "<default>"

    def test_check_or_raise_allow(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check_or_raise(agent="a", tool="crm.read")
        assert result.allowed is True

    def test_check_or_raise_deny(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        with pytest.raises(PolicyDeniedError) as exc_info:
            gate.check_or_raise(
                agent="a", tool="database.delete",
                context={"environment": "production"},
            )
        assert exc_info.value.tool == "database.delete"

    def test_check_or_raise_escalate(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        with pytest.raises(PolicyEscalationError):
            gate.check_or_raise(
                agent="a", tool="payments.refund",
                arguments={"amount": 5000},
            )

    def test_receipt_generation(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="crm.read")
        assert result.receipt is not None
        assert result.receipt["format"] == "policybound-receipt"

    def test_no_receipt_when_disabled(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path, emit_receipts=False)
        result = gate.check(agent="a", tool="crm.read")
        assert result.receipt is None

    def test_verify_ledger(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        gate.check(agent="a", tool="crm.read")
        gate.check(agent="a", tool="crm.update")
        assert gate.verify_ledger() is True


class TestGateResult:
    def test_repr(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="crm.read")
        r = repr(result)
        assert "allow" in r
        assert "crm.read" in r


class TestFailClosed:
    def test_strict_mode_default(self, policy_path, db_path):
        """In strict mode, governance failures result in denial."""
        gate = PolicyGate.from_file(policy_path, db_path=db_path, strict=True)
        # Normal operation should work
        result = gate.check(agent="a", tool="crm.read")
        assert result.allowed is True
