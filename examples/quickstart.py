"""PolicyBound quick start example.

Demonstrates the complete governance flow:
  Agent -> PolicyGate -> Decision -> Receipt -> Verification

Run:
    python examples/quickstart.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from policybound import PolicyGate, verify_receipt
from policybound.receipt import save_receipt, load_receipt


def main() -> None:
    # --- 1. Define a policy ---
    policy_yaml = """\
policy:
  name: demo-agent
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

  - name: allow-crm-update
    action: allow
    when:
      tool: crm.update
"""

    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "policy.yaml"
        policy_path.write_text(policy_yaml)
        db_path = Path(tmp) / "decisions.db"
        receipt_path = Path(tmp) / "receipt.json"

        # --- 2. Create a PolicyGate ---
        gate = PolicyGate.from_file(policy_path, db_path=db_path)

        # --- 3. Check an allowed action ---
        print("=" * 60)
        print("Example 1: Allowed action (crm.read)")
        print("=" * 60)
        result = gate.check(
            agent="sales-agent",
            tool="crm.read",
            arguments={"customer_id": "C-1234"},
        )
        print(f"  Verdict:  {result.verdict.value}")
        print(f"  Rule:     {result.decision.rule_name}")
        print(f"  Allowed:  {result.allowed}")
        print()

        # --- 4. Check a denied action ---
        print("=" * 60)
        print("Example 2: Denied action (database.delete in production)")
        print("=" * 60)
        result = gate.check(
            agent="ops-agent",
            tool="database.delete",
            context={"environment": "production"},
        )
        print(f"  Verdict:  {result.verdict.value}")
        print(f"  Rule:     {result.decision.rule_name}")
        print(f"  Denied:   {result.denied}")
        print()

        # --- 5. Check an escalated action ---
        print("=" * 60)
        print("Example 3: Escalated action (refund > $1000)")
        print("=" * 60)
        result = gate.check(
            agent="support-agent",
            tool="payments.refund",
            arguments={"amount": 2500, "reason": "customer complaint"},
        )
        print(f"  Verdict:  {result.verdict.value}")
        print(f"  Rule:     {result.decision.rule_name}")
        print(f"  Escalated: {result.escalated}")
        print()

        # --- 6. Save and verify a receipt ---
        print("=" * 60)
        print("Example 4: Receipt verification")
        print("=" * 60)
        allowed_result = gate.check(
            agent="sales-agent",
            tool="crm.update",
            arguments={"customer_id": "C-1234", "field": "email"},
        )
        save_receipt(allowed_result.receipt, receipt_path)
        print(f"  Receipt saved to: {receipt_path}")

        loaded = load_receipt(receipt_path)
        verification = verify_receipt(loaded)
        print(f"  Valid:    {verification.valid}")
        print(f"  Agent:    {verification.agent}")
        print(f"  Tool:     {verification.tool}")
        print(f"  Verdict:  {verification.verdict}")
        print()

        # --- 7. Verify ledger integrity ---
        print("=" * 60)
        print("Example 5: Ledger integrity check")
        print("=" * 60)
        chain_valid = gate.verify_ledger()
        print(f"  Chain integrity: {'VALID' if chain_valid else 'TAMPERED'}")
        print()

        # --- 8. Default deny (no matching rule) ---
        print("=" * 60)
        print("Example 6: Default deny (unknown tool)")
        print("=" * 60)
        result = gate.check(
            agent="rogue-agent",
            tool="system.shutdown",
        )
        print(f"  Verdict:  {result.verdict.value}")
        print(f"  Rule:     {result.decision.rule_name}")
        print(f"  Reason:   {result.decision.reason}")
        print()

        print("Done. All governance flows demonstrated successfully.")


if __name__ == "__main__":
    main()
