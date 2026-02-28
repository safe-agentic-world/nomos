# Normalization Test Vectors

This document defines the M19 golden-corpus contract for normalization.

## Files

- `testdata/normalization/corpus.jsonl`: valid inputs and their exact normalized form
- `testdata/normalization/bypass_attempts.jsonl`: known bypass-oriented inputs that must fail closed or normalize safely

## Format

Each line is a single JSON object.

Required fields:

- `name`
- `resource`

One of:

- `normalized`: exact expected normalized output
- `error_contains`: required substring for the deterministic error

## Determinism Rules

- Normalize using the same pure PDP logic on every platform.
- Expected output must not depend on OS path separators.
- Query strings and fragments are excluded from normalized network resources.
- Encoded separators (`%2f`, `%5c`) are rejected to prevent hidden path-shape changes.
- Traversal attempts, including percent-encoded dot segments, must fail closed.

## Coverage Expectations

The corpus must remain at or above 250 valid vectors and must cover:

- file paths with POSIX and Windows separators
- percent-encoded Unicode path segments
- traversal and separator-encoding bypass attempts
- URL hosts, default ports, punycode labels, and bracketed IPv6 literals
- repository identity casing forms

## Adding Cases

1. Add a new JSON line to the appropriate file.
2. Keep the expected result fully explicit.
3. Prefer one behavior per line.
4. Recompute the normalization digest if the corpus changes.
