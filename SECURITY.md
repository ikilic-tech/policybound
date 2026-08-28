# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PolicyBound, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns to the project maintainers via the contact information in the repository.

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

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Practices

- Dependencies are kept minimal and pinned to minimum versions
- Ed25519 signatures via the `cryptography` library (no custom crypto)
- Canonical JSON serialization for deterministic hashing
- SQLite WAL mode for write durability
- Fail-closed default behavior for governance failures
