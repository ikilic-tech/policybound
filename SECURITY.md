# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PolicyBound, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/ikilic-tech/policybound/security/advisories/new) to submit your report. This ensures the vulnerability can be assessed and addressed before public disclosure.

If private vulnerability reporting is unavailable, email the maintainer through the contact information on their [GitHub profile](https://github.com/ikilic-tech).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity

## Threat Model

PolicyBound's cryptographic design provides:

- **Integrity**: SHA-256 content hashing detects modification of decision records
- **Chain integrity**: Hash chaining detects insertion, deletion, or reordering of records
- **Authenticity**: Ed25519 signatures prove records were produced by the signing key holder
- **Independent verification**: Receipts are self-contained and verifiable without the original application

PolicyBound's cryptographic design does **not** provide:

- **Correctness**: Signatures do not prove an action was correct, appropriate, or legal
- **Legal non-repudiation**: Depends on key management practices outside this library
- **Key security**: A compromised private key allows forging valid signatures
- **Completeness**: The system cannot prove all actions were recorded if the middleware is bypassed
- **Trust anchoring**: Receipt verification with the embedded key proves integrity, not authenticity — use an explicit trusted public key for full authenticity verification

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Practices

- Dependencies are kept minimal and pinned to minimum versions
- Ed25519 signatures via the `cryptography` library (no custom crypto)
- Canonical JSON serialization for deterministic hashing
- Private keys written with restricted file permissions (0600)
- Regex patterns validated and length-limited at policy load time
- SQLite WAL mode for write durability
- Fail-closed default behavior for governance failures
