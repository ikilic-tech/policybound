"""Tests for the decision ledger and hash chain."""

from __future__ import annotations

import json
import sqlite3

import pytest

from policybound.crypto import GENESIS_HASH, generate_keypair
from policybound.errors import LedgerTamperError
from policybound.ledger import DecisionLedger, SQLiteBackend
from policybound.types import ActionRequest, Decision, Verdict


def _make_decision(tool="crm.read", agent="a", verdict=Verdict.ALLOW):
    req = ActionRequest(agent=agent, tool=tool)
    return Decision(
        request=req, verdict=verdict,
        rule_name="test", reason="test reason",
        policy_name="p", policy_version="1",
    )


class TestSQLiteBackend:
    def test_initial_state(self, db_path):
        backend = SQLiteBackend(db_path)
        assert backend.get_last_hash() == GENESIS_HASH
        assert backend.get_last_sequence() == 0
        assert backend.count() == 0

    def test_append_and_count(self, db_path):
        backend = SQLiteBackend(db_path)
        record = {
            "decision": {
                "decision_id": "d1",
                "request": {"agent": "a", "tool": "t", "arguments": {}, "context": {},
                            "request_id": "r1", "timestamp": "2026-01-01T00:00:00"},
                "verdict": "allow",
                "rule_name": "r",
                "reason": "ok",
                "policy_name": "p",
                "policy_version": "1",
                "timestamp": "2026-01-01T00:00:00",
            },
            "record_hash": "abc123",
            "previous_hash": GENESIS_HASH,
            "signature": "sig",
            "sequence": 1,
        }
        backend.append(record)
        assert backend.count() == 1
        assert backend.get_last_hash() == "abc123"
        assert backend.get_last_sequence() == 1


class TestDecisionLedger:
    def test_record_creates_chain(self, db_path):
        priv, _ = generate_keypair()
        ledger = DecisionLedger(private_key=priv, db_path=db_path)

        d1 = _make_decision(tool="crm.read")
        r1 = ledger.record(d1)
        assert r1.previous_hash == GENESIS_HASH
        assert r1.sequence == 1
        assert r1.record_hash
        assert r1.signature

        d2 = _make_decision(tool="crm.update")
        r2 = ledger.record(d2)
        assert r2.previous_hash == r1.record_hash
        assert r2.sequence == 2

    def test_verify_chain_passes(self, db_path):
        priv, _ = generate_keypair()
        ledger = DecisionLedger(private_key=priv, db_path=db_path)

        for i in range(5):
            ledger.record(_make_decision(tool=f"tool.{i}"))

        assert ledger.verify_chain() is True
        assert ledger.count() == 5

    def test_tamper_detection(self, db_path):
        priv, _ = generate_keypair()
        ledger = DecisionLedger(private_key=priv, db_path=db_path)

        ledger.record(_make_decision(tool="tool.1"))
        ledger.record(_make_decision(tool="tool.2"))
        ledger.record(_make_decision(tool="tool.3"))

        # Tamper with the database directly
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT record_json FROM decisions WHERE sequence = 2").fetchone()
        data = json.loads(row[0])
        data["decision"]["verdict"] = "deny"  # tamper
        conn.execute(
            "UPDATE decisions SET record_json = ? WHERE sequence = 2",
            (json.dumps(data),),
        )
        conn.commit()
        conn.close()

        with pytest.raises(LedgerTamperError, match="hash mismatch"):
            ledger.verify_chain()

    def test_query_by_agent(self, db_path):
        priv, _ = generate_keypair()
        ledger = DecisionLedger(private_key=priv, db_path=db_path)

        ledger.record(_make_decision(agent="agent-a"))
        ledger.record(_make_decision(agent="agent-b"))
        ledger.record(_make_decision(agent="agent-a"))

        results = ledger.query(agent="agent-a")
        assert len(results) == 2

    def test_query_by_verdict(self, db_path):
        priv, _ = generate_keypair()
        ledger = DecisionLedger(private_key=priv, db_path=db_path)

        ledger.record(_make_decision(verdict=Verdict.ALLOW))
        ledger.record(_make_decision(verdict=Verdict.DENY))
        ledger.record(_make_decision(verdict=Verdict.ALLOW))

        results = ledger.query(verdict="deny")
        assert len(results) == 1
