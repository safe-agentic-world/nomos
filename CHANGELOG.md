# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and semantic versioning.

## [Unreleased]

### Added

- `janus doctor` deterministic preflight command (M16)
- MCP runtime logging controls and stderr-safe readiness banner (M14)
- CLI short flags and env fallback ergonomics (M15)

### Changed

- MCP runtime output isolation to keep stdout protocol-safe
- release build metadata injection support for `Version`, `Commit`, `BuildDate`
