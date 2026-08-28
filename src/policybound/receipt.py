"""Receipt generation and verification.

A receipt is a portable, self-contained proof of a governance decision.
It can be verified independently — offline, without access to the
original application or ledger.

A receipt contains:
- The full decision record (what happened)
- The public key of the signer (who signed it)
- The signature (proof of authenticity)
- Metadata (format version, creation time)

Receipts are JSON files that can be:
- Stored alongside agent outputs
- Sent to external audit systems
- Archived for compliance
- Verified by any party with the public key
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from policybound.crypto import (
    Ed25519PublicKey,
    canonical_json,
    compute_hash,
    load_public_key,
    serialize_public_key,
    verify,
)
from policybound.errors import VerificationError
from policybound.types import DecisionRecord

RECEIPT_FORMAT_VERSION = "1.0"


def create_receipt(record: DecisionRecord, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Create a portable receipt from a decision record.

    The receipt includes everything needed for independent verification.
    """
    return {
        "format": "policybound-receipt",
        "version": RECEIPT_FORMAT_VERSION,
        "record": record.to_dict(),
        "public_key": serialize_public_key(public_key).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def save_receipt(receipt: dict[str, Any], path: str | Path) -> None:
    """Save a receipt to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2, sort_keys=True)


def load_receipt(path: str | Path) -> dict[str, Any]:
    """Load a receipt from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise VerificationError(f"Receipt file not found: {path}")
    with open(path) as f:
        return json.load(f)


def verify_receipt(
    receipt: dict[str, Any],
    public_key: Ed25519PublicKey | None = None,
) -> VerificationResult:
    """Verify a receipt's integrity and authenticity.

    If no public_key is provided, the key embedded in the receipt is used.
    If a public_key IS provided, it is checked against the embedded key.

    Returns a VerificationResult with details about the verification.
    """
    # Validate format
    if receipt.get("format") != "policybound-receipt":
        return VerificationResult(
            valid=False,
            error="Not a PolicyBound receipt (missing or wrong format field)",
        )

    record = receipt.get("record")
    if not record:
        return VerificationResult(valid=False, error="Receipt has no record")

    # Load the embedded public key
    embedded_key_pem = receipt.get("public_key")
    if not embedded_key_pem:
        return VerificationResult(valid=False, error="Receipt has no public key")

    try:
        embedded_key = load_public_key(embedded_key_pem.encode("ascii"))
    except Exception as e:
        return VerificationResult(valid=False, error=f"Invalid public key in receipt: {e}")

    # If caller provided a key, verify it matches the embedded one
    verification_key = embedded_key
    if public_key is not None:
        caller_pem = serialize_public_key(public_key).decode("ascii")
        if caller_pem != embedded_key_pem:
            return VerificationResult(
                valid=False,
                error="Provided public key does not match the key in the receipt",
            )
        verification_key = public_key

    # Verify content hash
    signable = {
        "decision": record["decision"],
        "previous_hash": record["previous_hash"],
        "sequence": record["sequence"],
    }
    canonical = canonical_json(signable)
    recomputed_hash = compute_hash(canonical)

    if recomputed_hash != record.get("record_hash"):
        return VerificationResult(
            valid=False,
            error=(
                f"Content hash mismatch: expected {recomputed_hash}, "
                f"found {record.get('record_hash')}"
            ),
        )

    # Verify signature
    signature_b64 = record.get("signature", "")
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        return VerificationResult(valid=False, error="Invalid signature encoding")

    if not verify(verification_key, signature_bytes, canonical):
        return VerificationResult(valid=False, error="Signature verification failed")

    return VerificationResult(
        valid=True,
        decision_id=record["decision"].get("decision_id", ""),
        agent=record["decision"]["request"].get("agent", ""),
        tool=record["decision"]["request"].get("tool", ""),
        verdict=record["decision"].get("verdict", ""),
        rule_name=record["decision"].get("rule_name", ""),
        policy_name=record["decision"].get("policy_name", ""),
        policy_version=record["decision"].get("policy_version", ""),
        record_hash=record.get("record_hash", ""),
        sequence=record.get("sequence", 0),
    )


class VerificationResult:
    """Result of receipt verification."""

    def __init__(
        self,
        valid: bool,
        error: str = "",
        decision_id: str = "",
        agent: str = "",
        tool: str = "",
        verdict: str = "",
        rule_name: str = "",
        policy_name: str = "",
        policy_version: str = "",
        record_hash: str = "",
        sequence: int = 0,
    ) -> None:
        self.valid = valid
        self.error = error
        self.decision_id = decision_id
        self.agent = agent
        self.tool = tool
        self.verdict = verdict
        self.rule_name = rule_name
        self.policy_name = policy_name
        self.policy_version = policy_version
        self.record_hash = record_hash
        self.sequence = sequence

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        if self.valid:
            return f"VerificationResult(valid=True, decision_id={self.decision_id!r})"
        return f"VerificationResult(valid=False, error={self.error!r})"
