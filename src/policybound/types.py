"""Core type definitions for PolicyBound.

These types represent the fundamental data structures used throughout
the governance middleware. The Decision is the central primitive —
every agent action produces a Decision that flows through the system.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class Verdict(enum.Enum):
    """The outcome of a policy evaluation.

    - ALLOW: The action is permitted by policy.
    - DENY: The action is explicitly prohibited by policy.
    - ESCALATE: The action requires human review before proceeding.
    - ERROR: The policy engine failed to evaluate (fail-closed: treated as deny).
    """

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    ERROR = "error"


@dataclass(frozen=True)
class ActionRequest:
    """An agent's request to perform an action.

    This is the input to the PolicyGate — what the agent wants to do.
    """

    agent: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class Decision:
    """The result of a policy evaluation.

    This is the core governance primitive. Every agent action that
    passes through the PolicyGate produces a Decision, regardless
    of whether the action is allowed, denied, or escalated.

    A Decision is a first-class object that captures:
    - What the agent wanted to do (the request)
    - What the policy decided (the verdict)
    - Why (the matched rule and reason)
    - The policy context (name, version)
    """

    request: ActionRequest
    verdict: Verdict
    rule_name: str
    reason: str
    policy_name: str
    policy_version: str
    decision_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def allowed(self) -> bool:
        """Whether the action is permitted."""
        return self.verdict == Verdict.ALLOW

    @property
    def denied(self) -> bool:
        """Whether the action is denied."""
        return self.verdict in (Verdict.DENY, Verdict.ERROR)

    @property
    def escalated(self) -> bool:
        """Whether the action requires human review."""
        return self.verdict == Verdict.ESCALATE

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "decision_id": self.decision_id,
            "request": {
                "agent": self.request.agent,
                "tool": self.request.tool,
                "arguments": self.request.arguments,
                "context": self.request.context,
                "request_id": self.request.request_id,
                "timestamp": self.request.timestamp.isoformat(),
            },
            "verdict": self.verdict.value,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class DecisionRecord:
    """A signed, hash-chained record of a Decision.

    This extends a Decision with cryptographic properties:
    - A hash of the record content (for integrity)
    - A link to the previous record's hash (for chain integrity)
    - A cryptographic signature (for authenticity)

    DecisionRecords form an append-only chain. Modifying any record
    breaks the hash chain, making tampering detectable.
    """

    decision: Decision
    record_hash: str
    previous_hash: str
    signature: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "decision": self.decision.to_dict(),
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
            "sequence": self.sequence,
        }
