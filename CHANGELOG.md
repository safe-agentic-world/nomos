# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and semantic versioning.

## [Unreleased]

### Added

- strong-guarantee deployment guidance and conservative readiness checks (`runtime.strong_guarantee`)
- deterministic `assurance_level` derivation in audit and `nomos policy explain`
- normalization corpus, redirect controls, and bypass-suite validation coverage
- corpus-backed redaction harness and secret no-leak integration coverage
- actionable `policy explain` denial context and remediation hints
- workflow-managed release publishing with multi-arch archives, checksums, Homebrew tap updates, and Scoop manifest updates

### Changed

- MCP runtime output isolation to keep stdout protocol-safe
- release build metadata injection support for `Version`, `Commit`, `BuildDate`
- release assets now publish archives (`.tar.gz` / `.zip`) instead of raw binaries
- install guidance now centers on `go install`, GitHub Releases, Homebrew tap, Scoop, and the provided installer script
