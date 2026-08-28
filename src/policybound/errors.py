"""PolicyBound error types.

Each error represents a distinct failure mode. The governance system
is fail-closed by default: if the governance infrastructure itself
fails, protected actions are denied.
"""

from __future__ import annotations


class PolicyBoundError(Exception):
    """Base class for all PolicyBound errors."""


class PolicyDeniedError(PolicyBoundError):
    """Raised when a policy explicitly denies an action.

    This is not a failure — it is the policy working as intended.
    The agent attempted an action that the active policy prohibits.
    """

    def __init__(self, tool: str, rule_name: str, reason: str) -> None:
        self.tool = tool
        self.rule_name = rule_name
        self.reason = reason
        super().__init__(f"Policy denied: {tool} (rule: {rule_name}) — {reason}")


class PolicyEscalationError(PolicyBoundError):
    """Raised when a policy requires human approval for an action.

    The action is neither allowed nor denied — it requires review
    by a human operator before proceeding.
    """

    def __init__(self, tool: str, rule_name: str, reason: str) -> None:
        self.tool = tool
        self.rule_name = rule_name
        self.reason = reason
        super().__init__(f"Escalation required: {tool} (rule: {rule_name}) — {reason}")


class PolicyEvaluationError(PolicyBoundError):
    """Raised when the policy engine encounters an error during evaluation.

    This indicates a problem with the policy definition or evaluation
    logic, NOT with the agent's action. When this occurs, the system
    defaults to denying the action (fail-closed).
    """


class InvalidPolicyError(PolicyBoundError):
    """Raised when a policy file is malformed or contains invalid rules.

    The policy cannot be loaded or parsed. No actions will be evaluated
    until a valid policy is provided.
    """


class LedgerError(PolicyBoundError):
    """Raised when the decision ledger encounters a storage error.

    This indicates the decision record could not be persisted. When
    this occurs in strict mode, the action is denied (fail-closed)
    because the governance trail would be incomplete.
    """


class LedgerTamperError(PolicyBoundError):
    """Raised when hash chain verification detects tampering.

    The hash of a stored record does not match its expected value,
    indicating that the record or a preceding record has been modified.
    """


class SigningError(PolicyBoundError):
    """Raised when cryptographic signing fails.

    The decision record cannot be signed. In strict mode, unsigned
    records are not accepted and the action is denied.
    """


class VerificationError(PolicyBoundError):
    """Raised when receipt verification fails.

    The receipt's signature does not match the record content, or
    the signing key cannot be verified. This may indicate tampering
    or use of an incorrect verification key.
    """
