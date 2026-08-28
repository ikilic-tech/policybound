"""Tests for core type definitions."""

from __future__ import annotations

import pytest

from policybound.types import ActionRequest, Decision, DecisionRecord, Verdict


class TestVerdict:
    def test_values(self):
        assert Verdict.ALLOW.value == "allow"
        assert Verdict.DENY.value == "deny"
        assert Verdict.ESCALATE.value == "escalate"
        assert Verdict.ERROR.value == "error"

    def test_from_string(self):
        assert Verdict("allow") == Verdict.ALLOW
        assert Verdict("deny") == Verdict.DENY


class TestActionRequest:
    def test_creation(self):
        req = ActionRequest(agent="a", tool="t")
        assert req.agent == "a"
        assert req.tool == "t"
        assert req.arguments == {}
        assert req.context == {}
        assert req.request_id  # auto-generated

    def test_frozen(self):
        req = ActionRequest(agent="a", tool="t")
        with pytest.raises(AttributeError):
            req.agent = "b"  # type: ignore[misc]

    def test_with_arguments(self):
        req = ActionRequest(agent="a", tool="t", arguments={"k": "v"}, context={"env": "prod"})
        assert req.arguments == {"k": "v"}
        assert req.context == {"env": "prod"}


class TestDecision:
    def test_allowed(self):
        req = ActionRequest(agent="a", tool="t")
        d = Decision(
            request=req, verdict=Verdict.ALLOW,
            rule_name="r", reason="ok",
            policy_name="p", policy_version="1",
        )
        assert d.allowed is True
        assert d.denied is False
        assert d.escalated is False

    def test_denied(self):
        req = ActionRequest(agent="a", tool="t")
        d = Decision(
            request=req, verdict=Verdict.DENY,
            rule_name="r", reason="no",
            policy_name="p", policy_version="1",
        )
        assert d.allowed is False
        assert d.denied is True
        assert d.escalated is False

    def test_escalated(self):
        req = ActionRequest(agent="a", tool="t")
        d = Decision(
            request=req, verdict=Verdict.ESCALATE,
            rule_name="r", reason="review",
            policy_name="p", policy_version="1",
        )
        assert d.allowed is False
        assert d.denied is False
        assert d.escalated is True

    def test_error_is_denied(self):
        req = ActionRequest(agent="a", tool="t")
        d = Decision(
            request=req, verdict=Verdict.ERROR,
            rule_name="r", reason="fail",
            policy_name="p", policy_version="1",
        )
        assert d.denied is True

    def test_to_dict(self):
        req = ActionRequest(agent="a", tool="t", arguments={"x": 1})
        d = Decision(
            request=req, verdict=Verdict.ALLOW,
            rule_name="r", reason="ok",
            policy_name="p", policy_version="1",
        )
        data = d.to_dict()
        assert data["verdict"] == "allow"
        assert data["rule_name"] == "r"
        assert data["request"]["agent"] == "a"
        assert data["request"]["tool"] == "t"
        assert data["request"]["arguments"] == {"x": 1}


class TestDecisionRecord:
    def test_to_dict(self):
        req = ActionRequest(agent="a", tool="t")
        d = Decision(
            request=req, verdict=Verdict.ALLOW,
            rule_name="r", reason="ok",
            policy_name="p", policy_version="1",
        )
        rec = DecisionRecord(
            decision=d, record_hash="abc", previous_hash="000",
            signature="sig", sequence=1,
        )
        data = rec.to_dict()
        assert data["record_hash"] == "abc"
        assert data["previous_hash"] == "000"
        assert data["sequence"] == 1
        assert data["decision"]["verdict"] == "allow"
