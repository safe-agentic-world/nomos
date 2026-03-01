# HTTP Redirect Semantics

This document defines the redirect policy for `net.http_request`.

## Default Stance

Redirects are denied by default.

Nomos does not follow HTTP redirects unless policy obligations explicitly enable them.

## Enabling Redirects

Redirects are enabled only when the matched policy obligations include:

- `http_redirects: true`

Optional:

- `http_redirect_hop_limit: <integer>`

If no hop limit is provided, Nomos uses a deterministic default of `3`.

## Enforcement Rules

When redirects are enabled:

- each redirect target is normalized before it is followed
- each hop target must remain inside the effective `net_allowlist`
- the hop limit is enforced strictly
- query strings and fragments are excluded from the recorded final destination

If any hop fails these checks, the request fails closed.

## Audit Contract

For allowed requests, audit executor metadata records:

- `final_resource`: normalized final destination, minimized to `url://host/path`
- `redirect_hops`: number of followed redirects

This metadata is intended for audit and replay visibility, not for policy expansion.
