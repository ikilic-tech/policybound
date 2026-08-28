"""Tests for the CLI."""

from __future__ import annotations

import json

from click.testing import CliRunner

from policybound.cli import cli


class TestInit:
    def test_init_creates_files(self, tmp_dir):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "init",
            "--policy", str(tmp_dir / "policy.yaml"),
            "--key-dir", str(tmp_dir),
        ])
        assert result.exit_code == 0
        assert (tmp_dir / "policy.yaml").exists()
        assert (tmp_dir / "policybound.key").exists()
        assert (tmp_dir / "policybound.pub").exists()

    def test_init_no_overwrite(self, tmp_dir):
        runner = CliRunner()
        # First run
        runner.invoke(cli, [
            "init",
            "--policy", str(tmp_dir / "policy.yaml"),
            "--key-dir", str(tmp_dir),
        ])
        # Second run without --force should fail
        result = runner.invoke(cli, [
            "init",
            "--policy", str(tmp_dir / "policy.yaml"),
            "--key-dir", str(tmp_dir),
        ])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_init_force_overwrite(self, tmp_dir):
        runner = CliRunner()
        runner.invoke(cli, [
            "init",
            "--policy", str(tmp_dir / "policy.yaml"),
            "--key-dir", str(tmp_dir),
        ])
        result = runner.invoke(cli, [
            "init", "--force",
            "--policy", str(tmp_dir / "policy.yaml"),
            "--key-dir", str(tmp_dir),
        ])
        assert result.exit_code == 0


class TestCheck:
    def test_check_allow(self, policy_path):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "-p", str(policy_path),
            "-a", "test-agent", "-t", "crm.read",
        ])
        assert result.exit_code == 0
        assert "allow" in result.output

    def test_check_deny(self, policy_path):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "-p", str(policy_path),
            "-a", "test-agent", "-t", "database.delete",
            "-C", "environment=production",
        ])
        assert result.exit_code == 1
        assert "deny" in result.output

    def test_check_escalate(self, policy_path):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "-p", str(policy_path),
            "-a", "test-agent", "-t", "payments.refund",
            "-A", "amount=5000",
        ])
        assert result.exit_code == 2
        assert "escalate" in result.output

    def test_check_json(self, policy_path):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "-p", str(policy_path),
            "-a", "test-agent", "-t", "crm.read", "-j",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["verdict"] == "allow"


class TestVerify:
    def test_verify_valid_receipt(self, policy_path, db_path, tmp_dir):
        from policybound.gate import PolicyGate
        from policybound.receipt import save_receipt

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="crm.read")
        receipt_path = tmp_dir / "receipt.json"
        save_receipt(result.receipt, receipt_path)

        runner = CliRunner()
        cli_result = runner.invoke(cli, ["verify", str(receipt_path)])
        assert cli_result.exit_code == 0
        assert "VALID" in cli_result.output

    def test_verify_invalid_receipt(self, tmp_dir):
        receipt_path = tmp_dir / "bad.json"
        receipt_path.write_text(json.dumps({"format": "wrong"}))

        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(receipt_path)])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_verify_json_output(self, policy_path, db_path, tmp_dir):
        from policybound.gate import PolicyGate
        from policybound.receipt import save_receipt

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        result = gate.check(agent="a", tool="crm.read")
        receipt_path = tmp_dir / "receipt.json"
        save_receipt(result.receipt, receipt_path)

        runner = CliRunner()
        cli_result = runner.invoke(cli, ["verify", str(receipt_path), "-j"])
        assert cli_result.exit_code == 0
        data = json.loads(cli_result.output)
        assert data["valid"] is True


class TestAudit:
    def test_audit_empty(self, db_path):
        # Create DB first
        from policybound.ledger import SQLiteBackend
        SQLiteBackend(db_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "-d", str(db_path)])
        assert result.exit_code == 0
        assert "No records" in result.output

    def test_audit_with_records(self, policy_path, db_path):
        from policybound.gate import PolicyGate

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        gate.check(agent="a", tool="crm.read")
        gate.check(agent="b", tool="crm.update")

        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "-d", str(db_path)])
        assert result.exit_code == 0
        assert "2 record" in result.output

    def test_audit_verify_chain(self, policy_path, db_path):
        from policybound.gate import PolicyGate

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        gate.check(agent="a", tool="crm.read")

        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "-d", str(db_path), "--verify-chain"])
        assert result.exit_code == 0
        assert "VALID" in result.output


class TestExport:
    def test_export_stdout(self, policy_path, db_path):
        from policybound.gate import PolicyGate

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        gate.check(agent="a", tool="crm.read")

        runner = CliRunner()
        result = runner.invoke(cli, ["export", "-d", str(db_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["format"] == "policybound-export"
        assert data["record_count"] == 1

    def test_export_to_file(self, policy_path, db_path, tmp_dir):
        from policybound.gate import PolicyGate

        gate = PolicyGate.from_file(policy_path, db_path=db_path)
        gate.check(agent="a", tool="crm.read")

        out_path = tmp_dir / "export.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["export", "-d", str(db_path), "-o", str(out_path)])
        assert result.exit_code == 0
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert data["record_count"] == 1
