# Assurance Levels

This document defines the assurance levels used by audit events and `nomos policy explain`.

## Levels

- `STRONG`: The runtime supplies independent enforcement for mediation boundaries, and Nomos is operating in a strong-guarantee deployment mode.
- `GUARDED`: Nomos is the primary enforcement point, with meaningful runtime controls, but the deployment is not asserting the full strong-guarantee posture.
- `BEST_EFFORT`: Nomos mediates only the actions routed through it; the surrounding environment may still permit bypass.
- `NONE`: Deployment mode is unknown or unsupported, so Nomos intentionally makes no stronger assurance claim.

## Deterministic Derivation

Nomos derives `assurance_level` from runtime config only.

Current mapping:

- deployment mode `k8s` or `ci` with `strong_guarantee=true` -> `STRONG`
- deployment mode `k8s` or `ci` with `strong_guarantee=false` -> `GUARDED`
- deployment mode `remote_dev` -> `BEST_EFFORT`
- deployment mode `unmanaged` -> `BEST_EFFORT`
- unknown/invalid mode -> `NONE`

This derivation is:

- side-effect free
- deterministic
- independent of agent input

## What Can Go Wrong

- `STRONG` still depends on operators actually enforcing the documented runtime controls.
- `GUARDED` does not imply complete bypass resistance.
- `BEST_EFFORT` means local or adjacent tooling may bypass Nomos entirely.
- `NONE` should be treated as a configuration gap until deployment mode is made explicit.

## Scope

This document only defines the assurance label and its documentation contract. It does not change policy decisions or broaden executor capabilities.
