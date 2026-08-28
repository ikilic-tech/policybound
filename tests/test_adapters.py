"""Tests for framework adapters."""

from __future__ import annotations

import pytest

from policybound.adapters.wrapper import GovernedTool
from policybound.errors import PolicyDeniedError
from policybound.gate import PolicyGate


class TestGovernedTool:
    def test_allowed_execution(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        def read_crm(customer_id: str) -> dict:
            return {"id": customer_id, "name": "Test"}

        governed = GovernedTool(
            gate=gate, agent="test-agent",
            tool_name="crm.read", func=read_crm,
        )

        result, gate_result = governed(customer_id="123")
        assert result == {"id": "123", "name": "Test"}
        assert gate_result.allowed is True

    def test_denied_execution(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        def delete_db(table: str) -> None:
            pass  # should never run

        governed = GovernedTool(
            gate=gate, agent="test-agent",
            tool_name="database.delete", func=delete_db,
            context={"environment": "production"},
        )

        with pytest.raises(PolicyDeniedError):
            governed(table="users")

    def test_check_without_execute(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        def read_crm(**kwargs):
            return {}

        governed = GovernedTool(
            gate=gate, agent="test-agent",
            tool_name="crm.read", func=read_crm,
        )

        result = governed.check(customer_id="123")
        assert result.allowed is True

    def test_repr(self, policy_path, db_path):
        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        governed = GovernedTool(
            gate=gate, agent="a", tool_name="t", func=lambda: None,
        )
        r = repr(governed)
        assert "a" in r
        assert "t" in r
