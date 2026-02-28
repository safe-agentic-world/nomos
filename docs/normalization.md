# Normalization (Stub)

This document defines deterministic normalization rules for action resources and parameters.

## Resource URI Grammar

- Schemes: `file`, `repo`, `url`.
- `file://workspace/<path>` is the canonical workspace resource.
- `repo://<org>/<repo>` represents a repository resource.
- `url://<host>/<path>` represents a network resource.

## Canonicalization Rules

- Lowercase scheme and host components.
- Remove default ports for `url` (80, 443).
- Normalize paths with `/` separators and `path.Clean`.
- Reject traversal attempts (segments resolving to `..`).

## Filesystem Rules

- PDP normalization is pure and MUST NOT touch the filesystem.
- Executor performs runtime resolution to enforce symlink safety.
- Path traversal attempts are rejected during normalization.

## Pattern / Glob Semantics

- Patterns use `/` as the only separator.
- `*` matches a single segment, `**` matches multiple segments.
- Backslashes are rejected to ensure cross-OS determinism.

## URL Normalization

- Hostnames are lowercased.
- Default ports are removed.
- Paths are cleaned deterministically.
