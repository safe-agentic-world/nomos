# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and semantic versioning.

## [Unreleased]

### Added

- strong-guarantee deployment guidance and conservative readiness checks (`runtime.strong_guarantee`)
- deterministic `assurance_level` derivation in audit and `nomos policy explain`
- `assurance_level` and `mediation_notice` in `nomos.capabilities`
- normalization corpus, redirect controls, and bypass-suite validation coverage
- corpus-backed redaction harness and secret no-leak integration coverage
- actionable `policy explain` denial context and remediation hints
- workflow-managed release publishing with multi-arch archives, checksums, Homebrew tap updates, and Scoop manifest updates
- `safe` starter policy bundle for safer local file mediation defaults

### Changed

- MCP runtime output isolation to keep stdout protocol-safe
- MCP tool-call adapter compatibility for current Claude Code wrapper shapes (`input` and extra wrapper metadata)
- MCP file-tool error mapping now distinguishes `normalization_error`, `not_found`, and `execution_error`
- release build metadata injection support for `Version`, `Commit`, `BuildDate`
- release assets now publish archives (`.tar.gz` / `.zip`) instead of raw binaries
- install guidance now centers on `go install`, GitHub Releases, Homebrew tap, Scoop, and the provided installer script
