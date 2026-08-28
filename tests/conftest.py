"""Shared fixtures for PolicyBound tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from policybound.crypto import generate_keypair, serialize_private_key, serialize_public_key

SAMPLE_POLICY_YAML = """\
policy:
  name: test-policy
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


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def policy_path(tmp_dir):
    """Write the sample policy to a temp file and return its path."""
    p = tmp_dir / "policy.yaml"
    p.write_text(SAMPLE_POLICY_YAML)
    return p


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair."""
    return generate_keypair()


@pytest.fixture
def key_files(tmp_dir, keypair):
    """Write keypair to files and return (private_path, public_path)."""
    private_key, public_key = keypair
    priv_path = tmp_dir / "test.key"
    pub_path = tmp_dir / "test.pub"
    priv_path.write_bytes(serialize_private_key(private_key))
    pub_path.write_bytes(serialize_public_key(public_key))
    return priv_path, pub_path


@pytest.fixture
def db_path(tmp_dir):
    """Return a temp path for a test database."""
    return tmp_dir / "test.db"
