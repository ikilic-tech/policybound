"""PolicyBound CLI — command-line interface for governance operations.

Commands:

    policybound init      Generate a starter policy and signing keypair
    policybound check     Check an action against a policy
    policybound verify    Verify a decision receipt
    policybound audit     Query the decision ledger
    policybound export    Export ledger records to JSON
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import click

from policybound import __version__


@click.group()
@click.version_option(version=__version__, prog_name="policybound")
def cli() -> None:
    """PolicyBound — Lightweight governance middleware for AI agents."""


@cli.command()
@click.option(
    "--policy",
    "-p",
    default="policybound.yaml",
    show_default=True,
    help="Path for the generated policy file.",
)
@click.option(
    "--key-dir",
    "-k",
    default=".",
    show_default=True,
    help="Directory for the generated signing keypair.",
)
@click.option("--force", "-f", is_flag=True, help="Overwrite existing files.")
def init(policy: str, key_dir: str, force: bool) -> None:
    """Generate a starter policy file and Ed25519 signing keypair."""
    from policybound.crypto import generate_keypair, serialize_private_key, serialize_public_key

    policy_path = Path(policy)
    key_dir_path = Path(key_dir)
    private_key_path = key_dir_path / "policybound.key"
    public_key_path = key_dir_path / "policybound.pub"

    # Check for existing files
    for p in (policy_path, private_key_path, public_key_path):
        if p.exists() and not force:
            click.echo(f"Error: {p} already exists. Use --force to overwrite.", err=True)
            sys.exit(1)

    # Generate policy
    starter_policy = """\
# PolicyBound governance policy
# Docs: https://github.com/ikilic-tech/policybound

policy:
  name: my-agent
  version: "1"
  default: deny  # fail-closed: deny actions with no matching rule

rules:
  # Example: deny dangerous operations
  # - name: deny-production-delete
  #   action: deny
  #   when:
  #     tool: database.delete
  #     environment: production

  # Example: require human approval for high-value actions
  # - name: require-approval-for-refund
  #   action: escalate
  #   when:
  #     tool: payments.refund
  #     amount:
  #       gt: 1000

  # Example: allow read operations
  # - name: allow-crm-read
  #   action: allow
  #   when:
  #     tool: crm.read

  - name: allow-all
    action: allow
    reason: "Default allow-all rule (replace with specific rules)"
"""
    policy_path.write_text(starter_policy)
    click.echo(f"Created policy: {policy_path}")

    # Generate keypair
    key_dir_path.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_keypair()
    # Write private key with restricted permissions (owner-only read/write)
    fd = os.open(str(private_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, serialize_private_key(private_key))
    finally:
        os.close(fd)
    public_key_path.write_bytes(serialize_public_key(public_key))

    click.echo(f"Created signing key: {private_key_path}")
    click.echo(f"Created public key: {public_key_path}")
    click.echo("")
    click.echo("Next steps:")
    click.echo(f"  1. Edit {policy_path} to define your governance rules")
    click.echo(f"  2. Keep {private_key_path} secure (do not commit to git)")
    click.echo(f"  3. Distribute {public_key_path} for receipt verification")


@cli.command()
@click.option(
    "--policy",
    "-p",
    default="policybound.yaml",
    show_default=True,
    help="Path to the policy file.",
)
@click.option("--agent", "-a", required=True, help="Agent identifier.")
@click.option("--tool", "-t", required=True, help="Tool being invoked.")
@click.option(
    "--arg",
    "-A",
    multiple=True,
    help="Action argument as key=value (repeatable).",
)
@click.option(
    "--context",
    "-C",
    multiple=True,
    help="Context value as key=value (repeatable).",
)
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON.")
def check(
    policy: str,
    agent: str,
    tool: str,
    arg: tuple[str, ...],
    context: tuple[str, ...],
    json_output: bool,
) -> None:
    """Check an action against a policy (no ledger recording)."""
    from policybound.policy import YAMLPolicyEngine
    from policybound.types import ActionRequest

    engine = YAMLPolicyEngine.from_file(policy)

    arguments = _parse_key_values(arg)
    ctx = _parse_key_values(context)

    request = ActionRequest(agent=agent, tool=tool, arguments=arguments, context=ctx)
    decision = engine.evaluate(request)

    if json_output:
        click.echo(json.dumps(decision.to_dict(), indent=2))
    else:
        verdict_colors = {"allow": "green", "deny": "red", "escalate": "yellow", "error": "red"}
        color = verdict_colors.get(decision.verdict.value, "white")
        click.echo(
            click.style(f"  verdict: {decision.verdict.value}", fg=color, bold=True)
        )
        click.echo(f"  rule:    {decision.rule_name}")
        click.echo(f"  reason:  {decision.reason}")
        click.echo(f"  policy:  {decision.policy_name} v{decision.policy_version}")

    if decision.denied:
        sys.exit(1)
    if decision.escalated:
        sys.exit(2)


@cli.command()
@click.argument("receipt_path", type=click.Path(exists=True))
@click.option(
    "--public-key",
    "-k",
    default=None,
    help="Path to public key file. If omitted, uses key embedded in receipt.",
)
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON.")
def verify(receipt_path: str, public_key: str | None, json_output: bool) -> None:
    """Verify a decision receipt."""
    from policybound.crypto import Ed25519PublicKey, load_public_key
    from policybound.receipt import load_receipt, verify_receipt

    receipt = load_receipt(receipt_path)

    pub_key: Ed25519PublicKey | None = None
    if public_key:
        pub_key = load_public_key(Path(public_key).read_bytes())

    result = verify_receipt(receipt, pub_key)

    if json_output:
        output: dict[str, Any] = {"valid": result.valid}
        if result.valid:
            output.update({
                "decision_id": result.decision_id,
                "agent": result.agent,
                "tool": result.tool,
                "verdict": result.verdict,
                "rule": result.rule_name,
                "policy": result.policy_name,
                "policy_version": result.policy_version,
            })
        else:
            output["error"] = result.error
        click.echo(json.dumps(output, indent=2))
    else:
        if result.valid:
            click.echo(click.style("  VALID", fg="green", bold=True))
            click.echo(f"  decision: {result.decision_id}")
            click.echo(f"  agent:    {result.agent}")
            click.echo(f"  tool:     {result.tool}")
            click.echo(f"  verdict:  {result.verdict}")
            click.echo(f"  rule:     {result.rule_name}")
            click.echo(f"  policy:   {result.policy_name} v{result.policy_version}")
        else:
            click.echo(click.style("  INVALID", fg="red", bold=True))
            click.echo(f"  error: {result.error}")

    if not result.valid:
        sys.exit(1)


@cli.command()
@click.option(
    "--db",
    "-d",
    default="policybound.db",
    show_default=True,
    help="Path to the ledger database.",
)
@click.option("--agent", "-a", default=None, help="Filter by agent.")
@click.option("--tool", "-t", default=None, help="Filter by tool.")
@click.option(
    "--verdict",
    "-v",
    default=None,
    type=click.Choice(["allow", "deny", "escalate", "error"]),
    help="Filter by verdict.",
)
@click.option("--limit", "-n", default=20, show_default=True, help="Maximum records to show.")
@click.option("--verify-chain", is_flag=True, help="Verify the hash chain integrity.")
@click.option(
    "--public-key",
    "-k",
    default=None,
    help="Public key file for signature verification (used with --verify-chain).",
)
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON.")
def audit(
    db: str,
    agent: str | None,
    tool: str | None,
    verdict: str | None,
    limit: int,
    verify_chain: bool,
    public_key: str | None,
    json_output: bool,
) -> None:
    """Query and inspect the decision ledger."""
    from policybound.crypto import generate_keypair, load_public_key
    from policybound.ledger import DecisionLedger

    # We need a key to create a ledger instance, but for audit we only read
    private_key, _ = generate_keypair()
    ledger = DecisionLedger(private_key=private_key, db_path=db)

    if verify_chain:
        pub_key = None
        if public_key:
            pub_key = load_public_key(Path(public_key).read_bytes())
        try:
            ledger.verify_chain(public_key=pub_key)
            msg = "Chain integrity: VALID"
            if pub_key:
                msg = "Chain integrity + signatures: VALID"
            click.echo(click.style(f"  {msg}", fg="green", bold=True))
            click.echo(f"  Records: {ledger.count()}")
        except Exception as e:
            click.echo(click.style("  Chain integrity: TAMPERED", fg="red", bold=True))
            click.echo(f"  Error: {e}")
            sys.exit(1)
        return

    kwargs: dict[str, Any] = {"limit": limit}
    if agent:
        kwargs["agent"] = agent
    if tool:
        kwargs["tool"] = tool
    if verdict:
        kwargs["verdict"] = verdict

    records = ledger.query(**kwargs)

    if json_output:
        click.echo(json.dumps(records, indent=2))
        return

    if not records:
        click.echo("No records found.")
        return

    click.echo(f"Found {len(records)} record(s):\n")
    for rec in records:
        decision = rec["decision"]
        verdict_val = decision["verdict"]
        verdict_colors = {"allow": "green", "deny": "red", "escalate": "yellow", "error": "red"}
        color = verdict_colors.get(verdict_val, "white")

        agent_name = decision["request"]["agent"]
        tool_name = decision["request"]["tool"]
        click.echo(f"  #{rec['sequence']}  {agent_name} -> {tool_name}")
        click.echo(
            "         "
            + click.style(verdict_val, fg=color, bold=True)
            + f"  rule={decision['rule_name']}"
        )
        click.echo(f"         {decision['timestamp']}")
        click.echo("")


@cli.command()
@click.option(
    "--db",
    "-d",
    default="policybound.db",
    show_default=True,
    help="Path to the ledger database.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file (default: stdout).",
)
@click.option("--agent", "-a", default=None, help="Filter by agent.")
@click.option("--tool", "-t", default=None, help="Filter by tool.")
@click.option(
    "--verdict",
    "-v",
    default=None,
    type=click.Choice(["allow", "deny", "escalate", "error"]),
    help="Filter by verdict.",
)
@click.option("--limit", "-n", default=1000, show_default=True, help="Maximum records to export.")
def export(
    db: str,
    output: str | None,
    agent: str | None,
    tool: str | None,
    verdict: str | None,
    limit: int,
) -> None:
    """Export ledger records to JSON."""
    from policybound.crypto import generate_keypair
    from policybound.ledger import DecisionLedger

    private_key, _ = generate_keypair()
    ledger = DecisionLedger(private_key=private_key, db_path=db)

    kwargs: dict[str, Any] = {"limit": limit}
    if agent:
        kwargs["agent"] = agent
    if tool:
        kwargs["tool"] = tool
    if verdict:
        kwargs["verdict"] = verdict

    records = ledger.query(**kwargs)

    export_data = {
        "format": "policybound-export",
        "version": "1.0",
        "record_count": len(records),
        "records": records,
    }

    json_str = json.dumps(export_data, indent=2)

    if output:
        Path(output).write_text(json_str)
        click.echo(f"Exported {len(records)} record(s) to {output}")
    else:
        click.echo(json_str)


def _parse_key_values(pairs: tuple[str, ...]) -> dict[str, Any]:
    """Parse key=value pairs into a dictionary, with type coercion."""
    result: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            click.echo(f"Error: Invalid argument format '{pair}'. Expected key=value.", err=True)
            sys.exit(1)
        key, _, value = pair.partition("=")
        result[key] = _coerce_value(value)
    return result


def _coerce_value(value: str) -> Any:
    """Coerce a string value to int/float/bool if possible."""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
