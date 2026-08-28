# PolicyBound

[![CI](https://github.com/ikilic-tech/policybound/actions/workflows/ci.yml/badge.svg)](https://github.com/ikilic-tech/policybound/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Add governance to your AI agent in minutes.**

PolicyBound is lightweight governance middleware for AI agents. It lets developers add policy enforcement, decision auditing, and verifiable receipts to any AI agent without adopting a full governance platform.

Every agent action is evaluated against a declarative YAML policy, recorded in a tamper-evident ledger, and wrapped in an independently verifiable receipt.

## The Problem

AI agents are making consequential decisions — accessing databases, processing payments, modifying customer records. Organizations need to answer:

> *What did the agent do? Was it authorized? Can we prove it?*

Existing governance platforms require significant infrastructure investment, vendor lock-in, or framework-specific integrations. Most teams need something simpler.

## Three Primitives

PolicyBound focuses on three primitives:

1. **Policy Gate** — Evaluate every agent action against declarative rules before execution
2. **Decision Ledger** — Record every decision in a tamper-evident, hash-chained audit log
3. **Verifiable Receipts** — Generate portable, cryptographically signed proof of each decision

```
Agent
  |
  v
PolicyGate -----> Policy (YAML rules)
  |
  v
Decision -------> DecisionRecord (signed, hash-chained)
  |
  v
Receipt --------> Independently verifiable proof
  |
  v
Tool execution (or denial)
```

## Quick Start

### Install

```bash
pip install policybound
```

### Define a Policy

Create `policybound.yaml`:

```yaml
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

  - name: allow-crm-update
    action: allow
    when:
      tool: crm.update
```

### Use in Code

```python
from policybound import PolicyGate

gate = PolicyGate.from_file("policybound.yaml")

result = gate.check(
    agent="sales-agent",
    tool="crm.update",
    arguments={"customer_id": "123"},
)

if result.allowed:
    execute_tool(...)
elif result.escalated:
    request_human_approval(result)
else:
    log_denial(result)
```

### Verify a Receipt

```python
from policybound import verify_receipt, load_receipt

receipt = load_receipt("receipt.json")
verification = verify_receipt(receipt)

if verification.valid:
    print(f"Verified: {verification.agent} -> {verification.tool}")
    print(f"Verdict: {verification.verdict}")
else:
    print(f"Verification failed: {verification.error}")
```

## Decision Record

Every governance decision produces a first-class `Decision` object:

```json
{
  "decision_id": "a1b2c3...",
  "request": {
    "agent": "sales-agent",
    "tool": "crm.update",
    "arguments": {"customer_id": "123"},
    "request_id": "d4e5f6...",
    "timestamp": "2026-01-15T10:30:00+00:00"
  },
  "verdict": "allow",
  "rule_name": "allow-crm-update",
  "reason": "Matched rule: allow-crm-update",
  "policy_name": "production-agent",
  "policy_version": "1"
}
```

Each record is hash-chained to the previous record and cryptographically signed with Ed25519.

## CLI

PolicyBound includes a CLI for policy management and auditing:

```bash
# Initialize a new project with policy and signing keys
policybound init

# Check an action against a policy
policybound check -p policybound.yaml -a my-agent -t crm.read

# Verify a receipt
policybound verify receipt.json

# Inspect the decision ledger
policybound audit --verify-chain

# Export ledger records
policybound export -o decisions.json
```

## Policy Language

Rules are evaluated in order. The first matching rule wins. Supported conditions:

| Condition | Example | Description |
|-----------|---------|-------------|
| Exact match | `tool: crm.read` | Exact string equality |
| Wildcard | `tool: crm.*` | Glob-style pattern |
| `gt`, `lt`, `gte`, `lte` | `amount: { gt: 1000 }` | Numeric comparison |
| `in`, `not_in` | `env: { in: [dev, staging] }` | Set membership |
| `pattern` | `tool: { pattern: 'crm\..*' }` | Regex match |

Values are resolved from: `tool`, `agent`, then `arguments`, then `context`.

## Framework Adapters

### Generic Python Wrapper

```python
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
result, gate_result = governed_send(to="user@example.com", subject="Hello", body="...")
```

### LangChain

```python
from policybound import PolicyGate
from policybound.adapters.langchain import PolicyBoundCallbackHandler

gate = PolicyGate.from_file("policybound.yaml")
handler = PolicyBoundCallbackHandler(gate=gate, agent="my-agent")

agent.invoke({"input": "..."}, config={"callbacks": [handler]})
```

Requires: `pip install policybound[langchain]`

## Security Model

### What the cryptographic guarantees provide

- **Integrity**: Any modification to a decision record is detectable via SHA-256 content hashing
- **Chain integrity**: Inserting, deleting, or reordering records is detectable via hash chaining
- **Authenticity**: Ed25519 signatures prove a record was produced by the holder of the signing key
- **Independent verification**: Receipts are self-contained and verifiable offline

### What the cryptographic guarantees do NOT provide

- **Correctness**: A signed record does not prove the recorded action was correct or appropriate
- **Legal non-repudiation**: Depends on key management practices outside this library's scope
- **Key security**: If the private signing key is compromised, an attacker can produce valid signatures
- **Completeness**: The system cannot prove that ALL actions were recorded — if the middleware is bypassed, no record is created

### Compliance Evidence

PolicyBound generates evidence for governance and compliance workflows. It provides technical controls and audit trails. Legal and regulatory compliance (EU AI Act, GDPR, SOC 2, etc.) remains the responsibility of the organization using the software.

## Failure Model

PolicyBound defaults to **fail-closed** behavior. Distinct failure modes:

| Failure | Behavior (strict mode) |
|---------|----------------------|
| Policy denied | Action blocked, decision recorded |
| Policy evaluation error | Action blocked (treated as deny) |
| Invalid policy | Exception raised, no actions evaluated |
| Ledger failure | Action blocked (governance trail incomplete) |
| Signing failure | Action blocked (record cannot be authenticated) |
| Verification failure | Receipt marked invalid with error details |

In non-strict mode, governance infrastructure failures are logged but the policy decision is still returned.

## Limitations

- MVP uses SQLite for the decision ledger (not suitable for high-concurrency production without an external backend)
- No built-in key rotation mechanism
- No real-time policy updates (requires restart or re-initialization)
- Receipt verification requires access to the public key
- YAML policy engine covers common cases; complex logic may require a custom `PolicyEngine` implementation

## Roadmap

- PostgreSQL ledger backend
- Policy hot-reloading
- Key rotation support
- Structured logging integration
- OpenTelemetry export
- Additional framework adapters

## Development

```bash
# Clone and install
git clone https://github.com/ikilic-tech/policybound.git
cd policybound
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src/ tests/

# Run type checking
mypy src/
```

## License

MIT License. See [LICENSE](LICENSE) for details.
