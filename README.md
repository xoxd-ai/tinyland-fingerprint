# @tummycrypt/tinyland-fingerprint

Fingerprint intelligence services: enrichment, search, history, settings,
validation, and caching. The fingerprint is UA-parse + Tempo evidence — this
package does NOT use the fingerprintjs library.

## Install (Bazel only)

This package is distributed only as a Bazel module from the xoxd-ai
bazel-registry; it is not published to npm.

```starlark
bazel_dep(name = "tummycrypt_tinyland_fingerprint", version = "1.0.0")
```

Toolchain: TypeScript 7.0.2, Node 22.22.0, vitest 5.0.3. See CHANGELOG for the
1.0.0 migration notes.

## Evidence, not a credential

This package supplies the print + Tempo evidence plane. The fingerprint is
never an auth credential: `validateSession()` in
[`@tummycrypt/tinyland-auth`](https://github.com/xoxd-ai/tinyland-auth)
never destroys an authenticated session on a missing/changed fingerprint
(TIN-1610, ratified). At the product layer, the same print is what
user-proof-during-session is built from, enabling cookieless persistent
sessions.

### Browser-as-a-factor (doctrine)

> Browser-as-a-factor (operator-canonized 2026-07-05): the Tempo-derived
> browser fingerprint (tinyland-fingerprint — UA-parse + Tempo evidence, NOT
> the fingerprintjs library) is not a traditional factor but correctly
> represents the user by print as a viable element of
> user-proof-during-session, enabling cookieless / localStorage-less
> persistent sessions with browser-backed persistence — the novel tempo +
> print + factors stack iterated for over a year. Boundary invariant
> (TIN-1610, ratified): the print is evidence at the credential boundary,
> never a veto — validateSession() never destroys an authenticated session on
> a missing/changed fingerprint. The two truths are LAYERED, not
> contradictory: evidence-only at the credential boundary; a
> session-persistence factor at the product layer. Do not flatten either half
> away.
