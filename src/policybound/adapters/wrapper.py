"""Generic Python wrapper for governed tool execution.

The GovernedTool wraps any callable behind a PolicyGate check.
This is the simplest way to add governance to a Python function
or method.

Usage:

    from policybound import PolicyGate
    from policybound.adapters.wrapper import GovernedTool

    gate = PolicyGate.from_file("policybound.yaml")

    def send_email(to: str, subject: str, body: str) -> dict:
        ...

    governed_send = GovernedTool(
        gate=gate,
        agent="email-agent",
        tool_name="email.send",
        func=send_email,
    )

    # Raises PolicyDeniedError if policy denies the action
    result = governed_send(to="user@example.com", subject="Hello", body="...")
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from policybound.gate import GateResult, PolicyGate

T = TypeVar("T")


class GovernedTool:
    """Wraps a callable behind a PolicyGate check.

    When called, the wrapper:
    1. Evaluates the action against the policy
    2. If allowed, executes the function and returns (result, gate_result)
    3. If denied or escalated, raises the appropriate error

    The wrapped function receives the original keyword arguments.
    """

    def __init__(
        self,
        gate: PolicyGate,
        agent: str,
        tool_name: str,
        func: Callable[..., Any],
        context: dict[str, Any] | None = None,
    ) -> None:
        self._gate = gate
        self._agent = agent
        self._tool_name = tool_name
        self._func = func
        self._context = context or {}

    def __call__(self, **kwargs: Any) -> tuple[Any, GateResult]:
        """Execute the governed tool call.

        Returns a tuple of (function_result, gate_result).
        Raises PolicyDeniedError or PolicyEscalationError if not allowed.
        """
        gate_result = self._gate.check_or_raise(
            agent=self._agent,
            tool=self._tool_name,
            arguments=kwargs,
            context=self._context,
        )

        func_result = self._func(**kwargs)
        return func_result, gate_result

    def check(self, **kwargs: Any) -> GateResult:
        """Check the policy without executing the function.

        Returns the GateResult for inspection. Does not raise.
        """
        return self._gate.check(
            agent=self._agent,
            tool=self._tool_name,
            arguments=kwargs,
            context=self._context,
        )

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def agent(self) -> str:
        return self._agent

    def __repr__(self) -> str:
        return f"GovernedTool(agent={self._agent!r}, tool={self._tool_name!r})"
