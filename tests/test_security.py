"""Security-focused tests for PolicyBound.

Validates defences against concurrency race conditions, input injection,
cryptographic misuse, and unsafe deserialization.
"""

from __future__ import annotations

import os
import platform
import threading

import pytest
import yaml

from policybound.crypto import canonical_json, generate_keypair
from policybound.errors import InvalidPolicyError
from policybound.ledger import DecisionLedger
from policybound.policy import YAMLPolicyEngine
from policybound.receipt import create_receipt, verify_receipt
from policybound.types import ActionRequest, Decision, Verdict

# ---------------------------------------------------------------------------
# H1: Concurrent ledger writes must preserve chain integrity
# ---------------------------------------------------------------------------


def test_concurrent_ledger_writes(db_path, keypair):
    """Multiple threads recording decisions concurrently must produce a
    valid hash chain with no duplicate sequences or broken links."""
    private_key, public_key = keypair
    ledger = DecisionLedger(private_key=private_key, db_path=db_path)

    errors: list[Exception] = []
    num_threads = 8
    records_per_thread = 5

    def _write(thread_id: int) -> None:
        for _i in range(records_per_thread):
            try:
                req = ActionRequest(
                    agent=f"agent-{thread_id}",
                    tool="crm.read",
                )
                decision = Decision(
                    request=req,
                    verdict=Verdict.ALLOW,
                    rule_name="allow-read",
                    reason="allowed",
                    policy_name="test",
                    policy_version="1",
                )
                ledger.record(decision)
            except Exception as exc:
                errors.append(exc)

    threads = [
        threading.Thread(target=_write, args=(tid,))
        for tid in range(num_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Errors during concurrent writes: {errors}"
    assert ledger.count() == num_threads * records_per_thread

    # The chain must verify cleanly
    assert ledger.verify_chain(public_key=public_key) is True


# ---------------------------------------------------------------------------
# I2: canonical_json rejects non-finite floats
# ---------------------------------------------------------------------------


def test_canonical_json_rejects_nan():
    """canonical_json must raise ValueError for NaN values to prevent
    non-deterministic serialization."""
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json({"v": float("nan")})


def test_canonical_json_rejects_infinity():
    """canonical_json must raise ValueError for Infinity values."""
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json({"v": float("inf")})


def test_canonical_json_rejects_negative_infinity():
    """canonical_json must raise ValueError for -Infinity values."""
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json({"v": float("-inf")})


# ---------------------------------------------------------------------------
# Receipt verification with wrong key
# ---------------------------------------------------------------------------


def test_receipt_verification_rejects_wrong_key(db_path, keypair):
    """A receipt verified against a different key than the signer's
    must return valid=False."""
    private_key, public_key = keypair
    ledger = DecisionLedger(private_key=private_key, db_path=db_path)

    req = ActionRequest(agent="test-agent", tool="crm.read")
    decision = Decision(
        request=req,
        verdict=Verdict.ALLOW,
        rule_name="allow-read",
        reason="allowed",
        policy_name="test",
        policy_version="1",
    )
    record = ledger.record(decision)
    receipt = create_receipt(record, public_key)

    # Generate a different keypair
    _, wrong_public_key = generate_keypair()

    result = verify_receipt(receipt, public_key=wrong_public_key)
    assert result.valid is False
    assert "does not match" in result.error


# ---------------------------------------------------------------------------
# I4: MAX_PATTERN_LENGTH enforcement (ReDoS prevention)
# ---------------------------------------------------------------------------


def test_policy_rejects_oversized_pattern():
    """A regex pattern exceeding MAX_PATTERN_LENGTH must be rejected
    at policy load time to prevent ReDoS attacks."""
    oversized_pattern = "a" * (YAMLPolicyEngine.MAX_PATTERN_LENGTH + 1)
    policy_data = {
        "policy": {"name": "test", "version": "1", "default": "deny"},
        "rules": [
            {
                "name": "bad-pattern",
                "action": "deny",
                "when": {"tool": {"pattern": oversized_pattern}},
            }
        ],
    }
    with pytest.raises(InvalidPolicyError, match="exceeds maximum length"):
        YAMLPolicyEngine(policy_data)


def test_policy_rejects_invalid_regex():
    """An invalid regex pattern must be rejected at policy load time."""
    policy_data = {
        "policy": {"name": "test", "version": "1", "default": "deny"},
        "rules": [
            {
                "name": "bad-regex",
                "action": "deny",
                "when": {"tool": {"pattern": "[invalid"}},
            }
        ],
    }
    with pytest.raises(InvalidPolicyError, match="invalid regex"):
        YAMLPolicyEngine(policy_data)


# ---------------------------------------------------------------------------
# I1: yaml.safe_load prevents arbitrary code execution
# ---------------------------------------------------------------------------


def test_yaml_safe_load_rejects_python_objects():
    """Loading YAML with Python object tags must raise an error, not
    execute arbitrary code. This confirms safe_load is used."""
    malicious_yaml = "!!python/object/apply:os.system ['echo pwned']"
    with pytest.raises((yaml.constructor.ConstructorError, InvalidPolicyError)):
        YAMLPolicyEngine.from_string(malicious_yaml)


def test_yaml_safe_load_rejects_python_module():
    """Confirm yaml.safe_load rejects !!python/module tags."""
    malicious_yaml = """\
policy:
  name: !!python/name:os.system
  version: "1"
rules: []
"""
    with pytest.raises((yaml.constructor.ConstructorError, InvalidPolicyError)):
        YAMLPolicyEngine.from_string(malicious_yaml)


# ---------------------------------------------------------------------------
# I3: Private key file permissions (Unix only)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="File permission tests only apply on Unix",
)
def test_private_key_file_permissions(tmp_dir):
    """The init command must create private key files with 0o600
    permissions (owner read/write only)."""
    from click.testing import CliRunner

    from policybound.cli import cli

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["init", "--policy", str(tmp_dir / "policy.yaml"), "--key-dir", str(tmp_dir)],
    )
    assert result.exit_code == 0, f"init failed: {result.output}"

    private_key_path = tmp_dir / "policybound.key"
    assert private_key_path.exists()

    mode = os.stat(private_key_path).st_mode & 0o777
    assert mode == 0o600, (
        f"Private key has permissions {oct(mode)}, expected 0o600"
    )


# ---------------------------------------------------------------------------
# Receipt tampering: modified decision is detected
# ---------------------------------------------------------------------------


def test_receipt_tampered_decision_detected(db_path, keypair):
    """Modifying any field in the receipt's decision record must cause
    verification to fail."""
    private_key, public_key = keypair
    ledger = DecisionLedger(private_key=private_key, db_path=db_path)

    req = ActionRequest(agent="test-agent", tool="crm.read")
    decision = Decision(
        request=req,
        verdict=Verdict.ALLOW,
        rule_name="allow-read",
        reason="allowed",
        policy_name="test",
        policy_version="1",
    )
    record = ledger.record(decision)
    receipt = create_receipt(record, public_key)

    # Tamper with the verdict
    receipt["record"]["decision"]["verdict"] = "deny"

    result = verify_receipt(receipt, public_key=public_key)
    assert result.valid is False
    assert "hash mismatch" in result.error.lower() or "signature" in result.error.lower()


# ---------------------------------------------------------------------------
# Self-referential receipt trust (M1 documentation test)
# ---------------------------------------------------------------------------


def test_receipt_self_verification_without_explicit_key(db_path, keypair):
    """Verifying a receipt without providing a public key uses the
    embedded key. This is the self-referential trust behavior documented
    in M1 — the test confirms the API works this way."""
    private_key, public_key = keypair
    ledger = DecisionLedger(private_key=private_key, db_path=db_path)

    req = ActionRequest(agent="test-agent", tool="crm.read")
    decision = Decision(
        request=req,
        verdict=Verdict.ALLOW,
        rule_name="allow-read",
        reason="allowed",
        policy_name="test",
        policy_version="1",
    )
    record = ledger.record(decision)
    receipt = create_receipt(record, public_key)

    # Verify without explicit key — uses embedded key (self-referential)
    result = verify_receipt(receipt)
    assert result.valid is True

    # A forged receipt with a different keypair also self-verifies
    # (this is the documented M1 limitation)
    attacker_priv, attacker_pub = generate_keypair()
    attacker_ledger = DecisionLedger(
        private_key=attacker_priv, db_path=str(db_path) + ".attacker",
    )
    attacker_record = attacker_ledger.record(decision)
    forged_receipt = create_receipt(attacker_record, attacker_pub)

    forged_result = verify_receipt(forged_receipt)
    assert forged_result.valid is True  # Self-verifies — M1 documented limitation

    # But providing the real public key catches the forgery
    forged_with_key = verify_receipt(forged_receipt, public_key=public_key)
    assert forged_with_key.valid is False
