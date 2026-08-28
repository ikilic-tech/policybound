"""Decision Ledger — append-only, hash-chained storage for decision records.

The ledger stores signed decision records with hash chaining. Each record
includes the hash of the previous record, forming an integrity chain.
Tampering with any record breaks the chain for all subsequent records.

The MVP uses SQLite for storage. The LedgerBackend protocol enables
future backends (PostgreSQL, object storage, remote ledger) without
changing the ledger's API.

Design principles:
- Append-only: records are only ever inserted, never updated or deleted
- Hash-chained: each record includes the previous record's hash
- Signed: each record is cryptographically signed
- Queryable: records can be searched by agent, tool, verdict, time range
- Self-verifiable: the chain can be verified without external systems
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from policybound.crypto import (
    GENESIS_HASH,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    canonical_json,
    compute_hash,
    sign,
    verify,
)
from policybound.errors import LedgerError, LedgerTamperError
from policybound.types import Decision, DecisionRecord


class LedgerBackend(Protocol):
    """Protocol for ledger storage backends."""

    def append(self, record: dict[str, Any]) -> None: ...
    def get_last_hash(self) -> str: ...
    def get_last_sequence(self) -> int: ...
    def query(
        self,
        agent: str | None = None,
        tool: str | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]: ...
    def get_all(self) -> list[dict[str, Any]]: ...
    def count(self) -> int: ...


class SQLiteBackend:
    """SQLite-based ledger backend."""

    def __init__(self, path: str | Path = "policybound.db") -> None:
        self._path = str(path)
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_table()

    def _create_table(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                sequence INTEGER PRIMARY KEY,
                decision_id TEXT NOT NULL UNIQUE,
                agent TEXT NOT NULL,
                tool TEXT NOT NULL,
                verdict TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                policy_name TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent ON decisions(agent)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool ON decisions(tool)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdict ON decisions(verdict)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON decisions(created_at)"
        )
        self._conn.commit()

    def append(self, record: dict[str, Any]) -> None:
        decision = record["decision"]
        try:
            self._conn.execute(
                """INSERT INTO decisions
                   (sequence, decision_id, agent, tool, verdict, rule_name,
                    policy_name, policy_version, record_hash, previous_hash,
                    signature, record_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["sequence"],
                    decision["decision_id"],
                    decision["request"]["agent"],
                    decision["request"]["tool"],
                    decision["verdict"],
                    decision["rule_name"],
                    decision["policy_name"],
                    decision["policy_version"],
                    record["record_hash"],
                    record["previous_hash"],
                    record["signature"],
                    json.dumps(record, sort_keys=True),
                    decision["timestamp"],
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as e:
            raise LedgerError(f"Failed to append record: {e}") from e

    def get_last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT record_hash FROM decisions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row["record_hash"] if row else GENESIS_HASH

    def get_last_sequence(self) -> int:
        row = self._conn.execute(
            "SELECT sequence FROM decisions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row["sequence"] if row else 0

    def query(
        self,
        agent: str | None = None,
        tool: str | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []

        if agent:
            conditions.append("agent = ?")
            params.append(agent)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        if since:
            conditions.append("created_at >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("created_at <= ?")
            params.append(until.isoformat())

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        rows = self._conn.execute(
            f"SELECT record_json FROM decisions {where} ORDER BY sequence ASC LIMIT ?",
            params,
        ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def get_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT record_json FROM decisions ORDER BY sequence ASC"
        ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM decisions").fetchone()
        return row["cnt"] if row else 0

    def close(self) -> None:
        self._conn.close()


class DecisionLedger:
    """Append-only, hash-chained ledger for decision records.

    Each decision is:
    1. Serialized to canonical JSON
    2. Hashed (SHA-256)
    3. Chained to the previous record's hash
    4. Signed with Ed25519
    5. Stored in the backend

    Usage:
        ledger = DecisionLedger(private_key=key)
        record = ledger.record(decision)
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        backend: LedgerBackend | None = None,
        db_path: str | Path = "policybound.db",
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._backend: LedgerBackend = backend or SQLiteBackend(db_path)

    def record(self, decision: Decision) -> DecisionRecord:
        """Record a decision in the ledger.

        Creates a hash-chained, signed record and appends it to the
        ledger. Returns the DecisionRecord for receipt generation.
        """
        previous_hash = self._backend.get_last_hash()
        sequence = self._backend.get_last_sequence() + 1

        # Create the signable content
        decision_dict = decision.to_dict()
        signable = {
            "decision": decision_dict,
            "previous_hash": previous_hash,
            "sequence": sequence,
        }
        canonical = canonical_json(signable)
        record_hash = compute_hash(canonical)

        # Sign the hash
        signature_bytes = sign(self._private_key, canonical)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        record = DecisionRecord(
            decision=decision,
            record_hash=record_hash,
            previous_hash=previous_hash,
            signature=signature_b64,
            sequence=sequence,
        )

        # Persist
        record_dict = record.to_dict()
        try:
            self._backend.append(record_dict)
        except Exception as e:
            raise LedgerError(f"Failed to persist decision record: {e}") from e

        return record

    def verify_chain(
        self, public_key: Ed25519PublicKey | None = None
    ) -> bool:
        """Verify the integrity of the entire hash chain and optionally signatures.

        Always checks:
        1. Hash chain linkage (previous_hash matches)
        2. Content hash integrity (recomputed hash matches stored hash)

        When a public_key is provided, also checks:
        3. Signature validity (Ed25519 signature verifies against content)

        Args:
            public_key: Public key to verify signatures against. If None,
                only hash chain integrity is verified (no signature check).

        Returns True if the chain is intact. Raises LedgerTamperError
        if tampering is detected.
        """
        records = self._backend.get_all()
        expected_previous = GENESIS_HASH

        for _i, record_dict in enumerate(records):
            # Check chain linkage
            if record_dict["previous_hash"] != expected_previous:
                raise LedgerTamperError(
                    f"Chain broken at sequence {record_dict['sequence']}: "
                    f"expected previous_hash {expected_previous}, "
                    f"found {record_dict['previous_hash']}"
                )

            # Recompute hash
            signable = {
                "decision": record_dict["decision"],
                "previous_hash": record_dict["previous_hash"],
                "sequence": record_dict["sequence"],
            }
            canonical = canonical_json(signable)
            recomputed = compute_hash(canonical)

            if recomputed != record_dict["record_hash"]:
                raise LedgerTamperError(
                    f"Content hash mismatch at sequence {record_dict['sequence']}: "
                    f"stored {record_dict['record_hash']}, "
                    f"recomputed {recomputed}"
                )

            # Verify signature when public key is available
            if public_key is not None:
                signature_b64 = record_dict.get("signature", "")
                try:
                    signature_bytes = base64.b64decode(signature_b64)
                except Exception:
                    raise LedgerTamperError(
                        f"Invalid signature encoding at sequence "
                        f"{record_dict['sequence']}"
                    ) from None

                if not verify(public_key, signature_bytes, canonical):
                    raise LedgerTamperError(
                        f"Signature verification failed at sequence "
                        f"{record_dict['sequence']}"
                    )

            expected_previous = record_dict["record_hash"]

        return True

    def query(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Query decision records from the ledger."""
        return self._backend.query(**kwargs)

    def count(self) -> int:
        """Return the total number of records in the ledger."""
        return self._backend.count()
