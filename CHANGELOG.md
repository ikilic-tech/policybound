# Changelog

All notable changes to PolicyBound will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-08-28

### Added

- PolicyGate for evaluating agent actions against YAML policies
- Decision model as a first-class governance primitive
- DecisionLedger with SQLite backend, hash chaining, and Ed25519 signing
- Verifiable decision receipts with independent offline verification
- YAML policy engine with support for exact match, wildcard, numeric operators, set membership, and regex patterns
- CLI commands: `init`, `check`, `verify`, `audit`, `export`
- Generic Python wrapper adapter (`GovernedTool`)
- LangChain callback handler adapter
- Fail-closed default behavior for governance infrastructure failures
- Comprehensive test suite (109 tests)
