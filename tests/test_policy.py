"""Tests for the YAML policy engine."""

from __future__ import annotations

import pytest

from policybound.errors import InvalidPolicyError, PolicyEvaluationError
from policybound.policy import YAMLPolicyEngine
from policybound.types import ActionRequest, Verdict


class TestYAMLPolicyEngine:
    def test_from_string(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: allow-all
    action: allow
""")
        assert engine.name == "test"
        assert engine.version == "1"

    def test_from_file(self, policy_path):
        engine = YAMLPolicyEngine.from_file(policy_path)
        assert engine.name == "test-policy"
        assert engine.version == "1"

    def test_file_not_found(self):
        with pytest.raises(InvalidPolicyError, match="not found"):
            YAMLPolicyEngine.from_file("/nonexistent/path.yaml")

    def test_invalid_yaml(self, tmp_dir):
        p = tmp_dir / "bad.yaml"
        p.write_text("{{invalid yaml")
        with pytest.raises(InvalidPolicyError, match="Invalid YAML"):
            YAMLPolicyEngine.from_file(p)

    def test_missing_policy_section(self):
        with pytest.raises(InvalidPolicyError, match="'policy' section"):
            YAMLPolicyEngine.from_string("rules: []")

    def test_missing_name(self):
        with pytest.raises(InvalidPolicyError, match="'name'"):
            YAMLPolicyEngine.from_string("""
policy:
  version: "1"
""")

    def test_missing_version(self):
        with pytest.raises(InvalidPolicyError, match="'version'"):
            YAMLPolicyEngine.from_string("""
policy:
  name: test
""")

    def test_invalid_action(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: bad
    action: invalid_action
    when:
      tool: x
""")
        req = ActionRequest(agent="a", tool="x")
        with pytest.raises(InvalidPolicyError, match="Invalid action"):
            engine.evaluate(req)

    def test_rules_not_list(self):
        with pytest.raises(InvalidPolicyError, match="'rules' must be a list"):
            YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  not_a_list: true
""")


class TestPolicyEvaluation:
    def test_deny_match(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: deny-delete
    action: deny
    when:
      tool: database.delete
      environment: production
""")
        req = ActionRequest(
            agent="a", tool="database.delete",
            context={"environment": "production"},
        )
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY
        assert decision.rule_name == "deny-delete"

    def test_escalate_match(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: escalate-refund
    action: escalate
    when:
      tool: payments.refund
      amount:
        gt: 1000
""")
        req = ActionRequest(
            agent="a", tool="payments.refund",
            arguments={"amount": 5000},
        )
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.ESCALATE
        assert decision.rule_name == "escalate-refund"

    def test_allow_match(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: allow-read
    action: allow
    when:
      tool: crm.read
""")
        req = ActionRequest(agent="a", tool="crm.read")
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.ALLOW

    def test_default_deny(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
  default: deny
rules:
  - name: allow-read
    action: allow
    when:
      tool: crm.read
""")
        req = ActionRequest(agent="a", tool="unknown.tool")
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY
        assert decision.rule_name == "<default>"

    def test_default_allow(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
  default: allow
rules: []
""")
        req = ActionRequest(agent="a", tool="anything")
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.ALLOW

    def test_first_match_wins(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: deny-first
    action: deny
    when:
      tool: x
  - name: allow-second
    action: allow
    when:
      tool: x
""")
        req = ActionRequest(agent="a", tool="x")
        decision = engine.evaluate(req)
        assert decision.rule_name == "deny-first"
        assert decision.verdict == Verdict.DENY

    def test_rule_no_conditions_matches_all(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
rules:
  - name: catch-all
    action: allow
""")
        req = ActionRequest(agent="a", tool="anything")
        decision = engine.evaluate(req)
        assert decision.rule_name == "catch-all"


class TestOperatorConditions:
    def _engine(self, rule_yaml):
        return YAMLPolicyEngine.from_string(f"""
policy:
  name: test
  version: "1"
  default: deny
rules:
  - name: test-rule
    action: allow
    when:
{rule_yaml}
""")

    def _req(self, **kwargs):
        return ActionRequest(agent="a", tool="t", **kwargs)

    def test_gt(self):
        engine = self._engine("      amount:\n        gt: 100")
        assert engine.evaluate(self._req(arguments={"amount": 200})).allowed
        assert not engine.evaluate(self._req(arguments={"amount": 50})).allowed
        assert not engine.evaluate(self._req(arguments={"amount": 100})).allowed

    def test_lt(self):
        engine = self._engine("      amount:\n        lt: 100")
        assert engine.evaluate(self._req(arguments={"amount": 50})).allowed
        assert not engine.evaluate(self._req(arguments={"amount": 200})).allowed

    def test_gte(self):
        engine = self._engine("      amount:\n        gte: 100")
        assert engine.evaluate(self._req(arguments={"amount": 100})).allowed
        assert engine.evaluate(self._req(arguments={"amount": 200})).allowed
        assert not engine.evaluate(self._req(arguments={"amount": 50})).allowed

    def test_lte(self):
        engine = self._engine("      amount:\n        lte: 100")
        assert engine.evaluate(self._req(arguments={"amount": 100})).allowed
        assert not engine.evaluate(self._req(arguments={"amount": 200})).allowed

    def test_in(self):
        engine = self._engine("      env:\n        in: [dev, staging]")
        assert engine.evaluate(self._req(arguments={"env": "dev"})).allowed
        assert not engine.evaluate(self._req(arguments={"env": "prod"})).allowed

    def test_not_in(self):
        engine = self._engine("      env:\n        not_in: [production]")
        assert engine.evaluate(self._req(arguments={"env": "dev"})).allowed
        req = self._req(arguments={"env": "production"})
        assert not engine.evaluate(req).allowed

    def test_pattern(self):
        engine = self._engine("      tool:\n        pattern: 'crm\\..*'")
        assert engine.evaluate(ActionRequest(agent="a", tool="crm.read")).allowed
        assert not engine.evaluate(ActionRequest(agent="a", tool="db.read")).allowed

    def test_wildcard(self):
        engine = YAMLPolicyEngine.from_string("""
policy:
  name: test
  version: "1"
  default: deny
rules:
  - name: allow-crm
    action: allow
    when:
      tool: crm.*
""")
        assert engine.evaluate(ActionRequest(agent="a", tool="crm.read")).allowed
        assert engine.evaluate(ActionRequest(agent="a", tool="crm.update")).allowed
        assert not engine.evaluate(ActionRequest(agent="a", tool="db.read")).allowed

    def test_unknown_operator(self):
        engine = self._engine("      amount:\n        unknown_op: 100")
        with pytest.raises(PolicyEvaluationError, match="Unknown operator"):
            engine.evaluate(ActionRequest(agent="a", tool="t", arguments={"amount": 50}))

    def test_missing_value_returns_false(self):
        engine = self._engine("      amount:\n        gt: 100")
        decision = engine.evaluate(ActionRequest(agent="a", tool="t"))
        assert decision.denied  # no 'amount' arg -> condition fails -> no match -> default deny
