"""YAML policy engine for PolicyBound.

Evaluates agent actions against declarative YAML policies. The engine
supports three verdicts: allow, deny, and escalate. Rules are evaluated
in order — the first matching rule wins.

If no rule matches, the default behavior is configurable:
- "deny" (default, fail-closed)
- "allow" (permissive, for development)

Example policy:

    policy:
      name: production-agent
      version: "1"
      default: deny

    rules:
      - name: deny-production-delete
        action: deny
        when:
          tool: database.delete
          environment: production

      - name: require-approval-for-refund
        action: escalate
        when:
          tool: payments.refund
          amount:
            gt: 1000

      - name: allow-crm-read
        action: allow
        when:
          tool: crm.read

The policy engine is designed to be pluggable. The built-in YAML engine
handles the common cases. OPA, Cedar, or custom engines can be added
by implementing the PolicyEngine protocol.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Protocol

import yaml

from policybound.errors import InvalidPolicyError, PolicyEvaluationError
from policybound.types import ActionRequest, Decision, Verdict


class PolicyEngine(Protocol):
    """Protocol for policy engines.

    Any object that implements `evaluate` with this signature can be
    used as a policy engine. This enables pluggable policy evaluation.
    """

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def evaluate(self, request: ActionRequest) -> Decision: ...


class YAMLPolicyEngine:
    """Evaluates actions against YAML policy rules.

    Rules are evaluated in order. The first matching rule determines
    the verdict. If no rule matches, the default verdict applies.
    """

    def __init__(self, policy_data: dict[str, Any]) -> None:
        self._validate(policy_data)
        policy_meta = policy_data["policy"]
        self._name: str = str(policy_meta["name"])
        self._version: str = str(policy_meta["version"])
        self._default: str = str(policy_meta.get("default", "deny"))
        self._rules: list[dict[str, Any]] = policy_data.get("rules", [])

    @classmethod
    def from_file(cls, path: str | Path) -> YAMLPolicyEngine:
        """Load a policy from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise InvalidPolicyError(f"Policy file not found: {path}")
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise InvalidPolicyError(f"Invalid YAML in {path}: {e}") from e
        if not isinstance(data, dict):
            raise InvalidPolicyError(f"Policy file must contain a YAML mapping: {path}")
        return cls(data)

    @classmethod
    def from_string(cls, content: str) -> YAMLPolicyEngine:
        """Load a policy from a YAML string."""
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise InvalidPolicyError(f"Invalid YAML: {e}") from e
        if not isinstance(data, dict):
            raise InvalidPolicyError("Policy must be a YAML mapping")
        return cls(data)

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, request: ActionRequest) -> Decision:
        """Evaluate an action request against the policy rules.

        Returns a Decision with the verdict of the first matching rule,
        or the default verdict if no rule matches.
        """
        try:
            for rule in self._rules:
                if self._matches(rule, request):
                    verdict = self._parse_verdict(rule["action"])
                    return Decision(
                        request=request,
                        verdict=verdict,
                        rule_name=rule["name"],
                        reason=rule.get("reason", f"Matched rule: {rule['name']}"),
                        policy_name=self._name,
                        policy_version=self._version,
                    )

            # No rule matched — apply default
            default_verdict = self._parse_verdict(self._default)
            return Decision(
                request=request,
                verdict=default_verdict,
                rule_name="<default>",
                reason=f"No rule matched; default policy is {self._default}",
                policy_name=self._name,
                policy_version=self._version,
            )
        except (InvalidPolicyError, PolicyEvaluationError):
            raise
        except Exception as e:
            raise PolicyEvaluationError(
                f"Policy evaluation failed: {e}"
            ) from e

    def _matches(self, rule: dict[str, Any], request: ActionRequest) -> bool:
        """Check whether a rule's conditions match the request."""
        conditions = rule.get("when", {})
        if not conditions:
            return True  # Rule with no conditions matches everything

        for key, expected in conditions.items():
            actual = self._resolve_value(key, request)
            if not self._check_condition(actual, expected):
                return False
        return True

    def _resolve_value(self, key: str, request: ActionRequest) -> Any:
        """Resolve a condition key to a value from the request."""
        if key == "tool":
            return request.tool
        if key == "agent":
            return request.agent
        # Check arguments first, then context
        if key in request.arguments:
            return request.arguments[key]
        if key in request.context:
            return request.context[key]
        return None

    def _check_condition(self, actual: Any, expected: Any) -> bool:
        """Check whether an actual value satisfies the expected condition."""
        if isinstance(expected, dict):
            return self._check_operator_condition(actual, expected)

        if isinstance(expected, str) and "*" in expected:
            pattern = re.escape(expected).replace(r"\*", ".*")
            return bool(re.fullmatch(pattern, str(actual))) if actual is not None else False

        return actual == expected

    def _check_operator_condition(self, actual: Any, operators: dict[str, Any]) -> bool:
        """Check operator-based conditions (gt, lt, gte, lte, in, not_in, pattern)."""
        for op, value in operators.items():
            if op == "gt":
                if actual is None or not isinstance(actual, (int, float)):
                    return False
                if not (actual > value):
                    return False
            elif op == "lt":
                if actual is None or not isinstance(actual, (int, float)):
                    return False
                if not (actual < value):
                    return False
            elif op == "gte":
                if actual is None or not isinstance(actual, (int, float)):
                    return False
                if not (actual >= value):
                    return False
            elif op == "lte":
                if actual is None or not isinstance(actual, (int, float)):
                    return False
                if not (actual <= value):
                    return False
            elif op == "in":
                if not isinstance(value, list):
                    return False
                if actual not in value:
                    return False
            elif op == "not_in":
                if not isinstance(value, list):
                    return False
                if actual in value:
                    return False
            elif op == "pattern":
                if actual is None:
                    return False
                if not re.fullmatch(str(value), str(actual)):
                    return False
            else:
                raise PolicyEvaluationError(f"Unknown operator: {op}")
        return True

    @staticmethod
    def _parse_verdict(action: str) -> Verdict:
        """Parse a verdict string into a Verdict enum."""
        try:
            return Verdict(action.lower())
        except ValueError:
            raise InvalidPolicyError(
                f"Invalid action '{action}'. Must be one of: allow, deny, escalate"
            ) from None

    @staticmethod
    def _validate(data: dict[str, Any]) -> None:
        """Validate the structure of a policy document."""
        if "policy" not in data:
            raise InvalidPolicyError("Policy must have a 'policy' section")
        policy = data["policy"]
        if not isinstance(policy, dict):
            raise InvalidPolicyError("'policy' section must be a mapping")
        if "name" not in policy:
            raise InvalidPolicyError("Policy must have a 'name'")
        if "version" not in policy:
            raise InvalidPolicyError("Policy must have a 'version'")

        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise InvalidPolicyError("'rules' must be a list")

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise InvalidPolicyError(f"Rule {i} must be a mapping")
            if "name" not in rule:
                raise InvalidPolicyError(f"Rule {i} must have a 'name'")
            if "action" not in rule:
                raise InvalidPolicyError(
                    f"Rule {i} ('{rule.get('name', i)}') must have an 'action'"
                )
