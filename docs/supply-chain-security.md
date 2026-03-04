# Supply-Chain Security

## Status

Compatibility alias.

## Canonical Doc

- `docs/release-verification.md`

## Current Model Snapshot

- SBOM format is SPDX JSON (`nomos-sbom.spdx.json`)
- provenance artifact is `nomos-provenance.intoto.jsonl`
- provenance predicate alignment uses `https://slsa.dev/provenance/v1`
- the official release workflow does not publish container images
- policy bundle trust remains separate from binary trust
