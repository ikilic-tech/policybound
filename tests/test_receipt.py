"""Tests for receipt generation and verification."""

from __future__ import annotations

import pytest

from policybound.crypto import generate_keypair
from policybound.ledger import DecisionLedger
from policybound.receipt import (
    create_receipt,
    load_receipt,
    save_receipt,
    verify_receipt,
)
from policybound.types import ActionRequest, Decision, Verdict


def _make_record(db_path, keypair):
    priv, pub = keypair
    ledger = DecisionLedger(private_key=priv, db_path=db_path)
    req = ActionRequest(agent="test-agent", tool="crm.read")
    decision = Decision(
        request=req, verdict=Verdict.ALLOW,
        rule_name="allow-read", reason="allowed by policy",
        policy_name="test", policy_version="1",
    )
    return ledger.record(decision), pub


class TestReceipt:
    def test_create_receipt(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)
        assert receipt["format"] == "policybound-receipt"
        assert receipt["version"] == "1.0"
        assert receipt["record"]["record_hash"] == record.record_hash
        assert "public_key" in receipt

    def test_save_and_load(self, db_path, keypair, tmp_dir):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        receipt_path = tmp_dir / "receipt.json"
        save_receipt(receipt, receipt_path)

        loaded = load_receipt(receipt_path)
        assert loaded["format"] == "policybound-receipt"
        assert loaded["record"]["record_hash"] == record.record_hash

    def test_load_missing_file(self):
        from policybound.errors import VerificationError
        with pytest.raises(VerificationError, match="not found"):
            load_receipt("/nonexistent/receipt.json")

    def test_verify_valid_receipt(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        result = verify_receipt(receipt)
        assert result.valid is True
        assert result.agent == "test-agent"
        assert result.tool == "crm.read"
        assert result.verdict == "allow"
        assert result.rule_name == "allow-read"

    def test_verify_with_matching_key(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        result = verify_receipt(receipt, pub)
        assert result.valid is True

    def test_verify_with_wrong_key(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        _, wrong_pub = generate_keypair()
        result = verify_receipt(receipt, wrong_pub)
        assert result.valid is False
        assert "does not match" in result.error

    def test_verify_tampered_record(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        # Tamper with the receipt
        receipt["record"]["decision"]["verdict"] = "deny"

        result = verify_receipt(receipt)
        assert result.valid is False
        assert "hash mismatch" in result.error.lower()

    def test_verify_invalid_format(self):
        result = verify_receipt({"format": "wrong"})
        assert result.valid is False
        assert "Not a PolicyBound receipt" in result.error

    def test_verify_missing_record(self):
        result = verify_receipt({"format": "policybound-receipt"})
        assert result.valid is False
        assert "no record" in result.error.lower()

    def test_verify_missing_public_key(self):
        result = verify_receipt({"format": "policybound-receipt", "record": {"decision": {}}})
        assert result.valid is False
        assert "no public key" in result.error.lower()

    def test_verification_result_bool(self, db_path, keypair):
        record, pub = _make_record(db_path, keypair)
        receipt = create_receipt(record, pub)

        valid_result = verify_receipt(receipt)
        assert bool(valid_result) is True

        invalid_result = verify_receipt({"format": "wrong"})
        assert bool(invalid_result) is False
