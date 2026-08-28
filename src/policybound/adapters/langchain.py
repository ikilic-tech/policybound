"""LangChain callback handler for PolicyBound governance.

Integrates PolicyBound with LangChain by intercepting tool calls
via the callback system. Every tool invocation is evaluated against
the policy before execution.

Usage:

    from langchain_core.tools import tool
    from policybound import PolicyGate
    from policybound.adapters.langchain import PolicyBoundCallbackHandler

    gate = PolicyGate.from_file("policybound.yaml")
    handler = PolicyBoundCallbackHandler(gate=gate, agent="my-agent")

    # Use as a callback with any LangChain chain or agent
    agent.invoke({"input": "..."}, config={"callbacks": [handler]})

Requires the `langchain` extra:

    pip install policybound[langchain]
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError(
        "LangChain integration requires the langchain extra. "
        "Install with: pip install policybound[langchain]"
    ) from None

from policybound.gate import GateResult, PolicyGate


class PolicyBoundCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that enforces PolicyBound governance.

    Intercepts tool calls and evaluates them against the policy.
    Denied actions raise PolicyDeniedError, preventing execution.
    """

    def __init__(
        self,
        gate: PolicyGate,
        agent: str,
        context: dict[str, Any] | None = None,
        raise_on_deny: bool = True,
    ) -> None:
        self._gate = gate
        self._agent = agent
        self._context = context or {}
        self._raise_on_deny = raise_on_deny
        self._last_result: GateResult | None = None

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts. Evaluates the action against policy."""
        tool_name = serialized.get("name", "unknown")

        arguments: dict[str, Any] = {}
        if inputs:
            arguments = dict(inputs)
        elif input_str:
            arguments = {"input": input_str}

        if self._raise_on_deny:
            self._last_result = self._gate.check_or_raise(
                agent=self._agent,
                tool=tool_name,
                arguments=arguments,
                context=self._context,
            )
        else:
            self._last_result = self._gate.check(
                agent=self._agent,
                tool=tool_name,
                arguments=arguments,
                context=self._context,
            )

    @property
    def last_result(self) -> GateResult | None:
        """The result of the most recent policy check."""
        return self._last_result
