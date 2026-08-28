"""PolicyGate — the main integration point for governance middleware.

The PolicyGate is the single entry point for adding governance to an
agent. It wraps the policy engine, decision ledger, and receipt
generation into a simple API.

Usage:
    from policybound import PolicyGate

    gate = PolicyGate.from_file("policybound.yaml")

    decision = gate.check(
        agent="sales-agent",
        tool="crm.update",
        arguments={"customer_id": "123"},
    )

    if decision.allowed:
        # execute the tool call
        result = execute_tool(...)
    elif decision.escalated:
        # request human approval
        request_approval(decision)
    else:
        # action denied by policy
        log_denial(decision)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from policybound.crypto import Ed25519PrivateKey, Ed25519PublicKey, generate_keypair
from policybound.errors import (
    LedgerError,
    PolicyDeniedError,
    PolicyEscalationError,
    PolicyEvaluationError,
    SigningError,
)
from policybound.ledger import DecisionLedger
from policybound.policy import PolicyEngine, YAMLPolicyEngine
from policybound.receipt import create_receipt
from policybound.types import ActionRequest, Decision, DecisionRecord, Verdict


class PolicyGate:
    """Governance middleware for AI agent actions.

    The PolicyGate evaluates every action against a policy, records
    the decision in a tamper-evident ledger, and optionally generates
    verifiable receipts.

    Configuration:
        strict: If True (default), failures in the governance
            infrastructure (ledger errors, signing errors) cause the
            action to be denied. If False, governance failures are
            logged but the policy decision is still returned.

        emit_receipts: If True (default), a receipt is generated
            for every decision. Receipts can be retrieved from the
            decision result.
    """

    REDACTED_VALUE = "**REDACTED**"

    def __init__(
        self,
        policy_engine: PolicyEngine,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
        ledger: DecisionLedger | None = None,
        db_path: str | Path = "policybound.db",
        strict: bool = True,
        emit_receipts: bool = True,
        redact_keys: set[str] | None = None,
    ) -> None:
        # Generate keys if not provided
        if private_key is None:
            private_key, public_key = generate_keypair()
        elif public_key is None:
            public_key = private_key.public_key()

        self._policy_engine = policy_engine
        self._private_key = private_key
        self._public_key = public_key
        self._ledger = ledger or DecisionLedger(
            private_key=private_key, db_path=db_path
        )
        self._strict = strict
        self._emit_receipts = emit_receipts
        self._redact_keys: set[str] = redact_keys or set()

    @classmethod
    def from_file(
        cls,
        policy_path: str | Path,
        db_path: str | Path = "policybound.db",
        key_path: str | Path | None = None,
        strict: bool = True,
        emit_receipts: bool = True,
        redact_keys: set[str] | None = None,
    ) -> PolicyGate:
        """Create a PolicyGate from a YAML policy file.

        If key_path is provided, loads the signing key from that file.
        Otherwise, generates a new keypair (suitable for development).
        """
        engine = YAMLPolicyEngine.from_file(policy_path)

        private_key: Ed25519PrivateKey | None = None
        public_key: Ed25519PublicKey | None = None

        if key_path is not None:
            from policybound.crypto import load_private_key

            key_file = Path(key_path)
            if not key_file.exists():
                msg = f"Key file not found: {key_file}"
                raise FileNotFoundError(msg)
            private_key = load_private_key(key_file.read_bytes())
            public_key = private_key.public_key()

        return cls(
            policy_engine=engine,
            private_key=private_key,
            public_key=public_key,
            db_path=db_path,
            strict=strict,
            emit_receipts=emit_receipts,
            redact_keys=redact_keys,
        )

    def check(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> GateResult:
        """Evaluate an agent action against policy.

        This is the primary API. Call this before executing any tool.

        Returns a GateResult containing:
        - The Decision (verdict, rule, reason)
        - The DecisionRecord (signed, hash-chained)
        - The Receipt (if emit_receipts is True)

        In strict mode, governance infrastructure failures (ledger
        errors, signing errors) cause the action to be denied.
        """
        # Build the request
        request_kwargs: dict[str, Any] = {
            "agent": agent,
            "tool": tool,
            "arguments": arguments or {},
            "context": context or {},
        }
        if request_id is not None:
            request_kwargs["request_id"] = request_id

        request = ActionRequest(**request_kwargs)

        # Evaluate policy
        try:
            decision = self._policy_engine.evaluate(request)
        except PolicyEvaluationError:
            if self._strict:
                # Fail-closed: treat evaluation errors as denials
                decision = Decision(
                    request=request,
                    verdict=Verdict.ERROR,
                    rule_name="<error>",
                    reason="Policy evaluation failed (fail-closed)",
                    policy_name=self._policy_engine.name,
                    policy_version=self._policy_engine.version,
                )
            else:
                raise

        # Redact sensitive fields before recording
        if self._redact_keys:
            decision = self._redact_decision(decision)

        # Record in ledger
        record: DecisionRecord | None = None
        try:
            record = self._ledger.record(decision)
        except (LedgerError, SigningError) as e:
            if self._strict:
                decision = Decision(
                    request=request,
                    verdict=Verdict.ERROR,
                    rule_name="<error>",
                    reason=f"Governance infrastructure error: {e} (fail-closed)",
                    policy_name=self._policy_engine.name,
                    policy_version=self._policy_engine.version,
                )
            # In non-strict mode, we continue without a record

        # Generate receipt
        receipt: dict[str, Any] | None = None
        if self._emit_receipts and record is not None:
            receipt = create_receipt(record, self._public_key)

        return GateResult(
            decision=decision,
            record=record,
            receipt=receipt,
        )

    def _redact_decision(self, decision: Decision) -> Decision:
        """Create a copy of the decision with sensitive fields redacted."""
        redacted_args = {
            k: self.REDACTED_VALUE if k in self._redact_keys else v
            for k, v in decision.request.arguments.items()
        }
        redacted_ctx = {
            k: self.REDACTED_VALUE if k in self._redact_keys else v
            for k, v in decision.request.context.items()
        }
        redacted_request = ActionRequest(
            agent=decision.request.agent,
            tool=decision.request.tool,
            arguments=redacted_args,
            context=redacted_ctx,
            request_id=decision.request.request_id,
        )
        return Decision(
            request=redacted_request,
            verdict=decision.verdict,
            rule_name=decision.rule_name,
            reason=decision.reason,
            policy_name=decision.policy_name,
            policy_version=decision.policy_version,
        )

    def check_or_raise(
        self,
        agent: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> GateResult:
        """Like check(), but raises on deny/escalate.

        Raises PolicyDeniedError if the action is denied.
        Raises PolicyEscalationError if escalation is required.
        Returns the GateResult if the action is allowed.
        """
        result = self.check(agent=agent, tool=tool, arguments=arguments, context=context)

        if result.decision.denied:
            raise PolicyDeniedError(
                tool=tool,
                rule_name=result.decision.rule_name,
                reason=result.decision.reason,
            )
        if result.decision.escalated:
            raise PolicyEscalationError(
                tool=tool,
                rule_name=result.decision.rule_name,
                reason=result.decision.reason,
            )

        return result

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The public key used for receipt verification."""
        return self._public_key

    @property
    def policy_name(self) -> str:
        return self._policy_engine.name

    @property
    def policy_version(self) -> str:
        return self._policy_engine.version

    def verify_ledger(self) -> bool:
        """Verify the integrity of the decision ledger's hash chain and signatures."""
        return self._ledger.verify_chain(public_key=self._public_key)


class GateResult:
    """Result of a PolicyGate check.

    Contains the decision, the signed record, and optionally a receipt.
    """

    def __init__(
        self,
        decision: Decision,
        record: DecisionRecord | None = None,
        receipt: dict[str, Any] | None = None,
    ) -> None:
        self.decision = decision
        self.record = record
        self.receipt = receipt

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    @property
    def denied(self) -> bool:
        return self.decision.denied

    @property
    def escalated(self) -> bool:
        return self.decision.escalated

    @property
    def verdict(self) -> Verdict:
        return self.decision.verdict

    def __repr__(self) -> str:
        return (
            f"GateResult(verdict={self.decision.verdict.value}, "
            f"rule={self.decision.rule_name!r}, "
            f"tool={self.decision.request.tool!r})"
        )
