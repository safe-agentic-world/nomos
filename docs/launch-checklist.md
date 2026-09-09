# Contributor Release Checklist

## Working First Use

- Build from a clean checkout on supported Go.
- Run all six checked-in permission cases.
- Install the Python package in a fresh environment.
- Run approved and rejected inbox demos without account credentials.
- Ensure the README describes only available interfaces and real behavior.

## Verification

- Run the checks in [TESTING.md](../TESTING.md).
- Test denial, approval expiry, argument changes, and report failures.
- Build wheel/sdist and inspect installed imports outside the checkout.
- Check documentation links and workflow syntax.
- Record toolchain limits honestly; local checks are not a completed hosted CI run.

## Release Authority

Publishing GitHub releases, PyPI packages, or announcements is a separate
maintainer action. Do not imply the Python package is published until its
release has been verified. Keep the current version and migration notes
in [CHANGELOG.md](../CHANGELOG.md).

## Adoption Feedback

Ask early contributors whether they can run the demo and connect one real
tool. Track reproducible installation failures, first-run friction, and
integration requests. Popularity is not guaranteed by a feature checklist;
use feedback to choose the next small integration.
