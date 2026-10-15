# Changelog

## 1.0.0 — 2026-10-15

Major release: RU1 toolchain uplift, Bazel-only distribution (RU6/RU8), and the
telemetry privacy fixes that the served Mothership writer already runs from
source pin `ac65946e6a` (never released before). RU10 major bump.

### Migration (all consumers)

1. Consume this package only as the Bazel module
   `bazel_dep(name = "tummycrypt_tinyland_fingerprint", version = "1.0.0")`
   from the xoxd-ai bazel-registry. Nothing is published to npmjs or GitHub
   Packages any more (`private: true`; the Publish workflow is removed). Drop
   any `@tummycrypt/tinyland-fingerprint` npm dependency and any
   `single_version_override` / `git_override` pinning `0.3.0` or the
   `ac65946e6a` source candidate.
2. `@tummycrypt/tinyland-otel` is no longer a dependency, peer or `bazel_dep`
   of this module. Nothing here imported it; telemetry is injected through the
   `FingerprintConfig` ports (`withSpan`, logger). Consumers that use otel
   declare their own `tummycrypt_tinyland_otel` `bazel_dep`.
3. Toolchain: built and type-checked with TypeScript 7.0.2 (rules_ts 3.10.1,
   `typescript.deps(version_from = "//:package.json")`), Node 22.22.0 and
   vitest 5.0.3. Root modules should pin TypeScript 7.0.2 as well. Node
   engines floor is now `>=22.17.0`.
4. Enrichment privacy (behavior change, see below): `sessionId`, `clientIp`
   and full navigation URLs are no longer returned or emitted. Move to the
   `deriveSessionCorrelation` port and the coarse location metadata.
5. The public API (exports `.`, `./services`, `./types`) is otherwise
   unchanged: the only type addition is `sessionCorrelationId?` on
   `EnrichedFingerprint` and `deriveSessionCorrelation?` on
   `FingerprintConfig`.

### Changed (toolchain, RU1/RU5)

- `typescript` 7.0.2, `vitest` 5.0.3 and `vite` 8.3.3 pinned exact; tsconfig
  sets `types: ["node"]` (TS 7 no longer loads every `@types` package).
- Unused devDependencies removed: `@fast-check/vitest`, `fast-check` and
  `@types/ua-parser-js` (ua-parser-js 2 ships its own types).
- New `//:typecheck` Bazel target; `//:test` now declares `MODULE.bazel`,
  `BUILD.bazel` and `package.json` as data for the version-parity test.
- `.bazelrc` registry and package URLs point at xoxd-ai.

### Removed (RU6/RU8)

- npm publish path: `publishConfig`, `prepublishOnly` and
  `.github/workflows/publish.yml`.
- `@tummycrypt/tinyland-otel` devDependency, optional peer and `bazel_dep`
  (it made `npm_translate_lock` fetch otel 0.2.2 from npmjs into every
  consumer graph).

### Security / privacy (from the unreleased 0.3.1 source candidate)

- Fail closed when fingerprint/IP hashing or encryption ports are absent or
  identity-valued. Do not emit raw IP, raw session ID, fingerprint ID, full URL,
  referrer, or user path in enrichment logs and spans.
- Accept only a server-configured `deriveSessionCorrelation` HMAC port that
  returns `fp-session:v1:<64 lowercase hex>` and does not echo the bearer.
  Missing, invalid and throwing ports omit correlation without affecting auth.
- Preserve the nullable legacy `sessionId` and IP result fields for source
  compatibility, but return no raw values from new enrichment.
- Consumers of `sessionId`, raw `clientIp` or full navigation URLs in enrichment
  results must migrate to explicit non-bearer correlation and coarse location
  metadata; historical traces may still need separate read-side filtering.
- Never set the durable `user.id` span attribute, even with tracking consent
  (`ac65946e6a`).

## 0.3.0 — 2026-07-03

Port of the vendored `tinyland.dev/packages/tinyland-fingerprint` 0.3.0 surface
back into this standalone package (TIN-1744). Byte-faithful to the vendored
sources; see PR #10 for the full care-item audit.

### Behavior changes (pre-1.0 minor per semver 0.x — review before upgrading)

- Overlay runtime: `DEFAULT_TEMPO_RECOVERY_MAX_RETRIES` default lowered
  10 → 1, with adjusted retry-delay timing.
- `SearchResult.dataSource` narrowed from `'tempo' | 'loki' | 'none'` to
  `'tempo' | 'none'` — a compile-time break for consumers that narrow on
  `'loki'`.
- `FingerprintHistoryService`: `analyzeLocationChanges`,
  `detectFingerprintChanges`, and `getUserActivitySummary` are now real
  implementations (previously stubs), and `getRecentHistory`'s data authority
  moved from Loki to Tempo-primary.

### Added

- `createFingerprintOverlayRuntime` facade alongside the existing
  `createFingerprintOverlaySyncRuntime` primitive (TIN-454 additive split).
- `FingerprintDataService` data plane; settings-history additions including
  `restoreFullSettings`; security-investigation surface
  (`deriveSecuritySignals`, `getSecurityInvestigation`,
  `FingerprintSecurityInvestigation`).

### Fixed

- `isTempFingerprint` is inlined locally instead of imported from
  `@tummycrypt/tinyland-security`, fixing the browser-bundle /
  server-only-barrel issue.

### Removed

- Dead `@tummycrypt/tinyland-security` Bazel wiring (MODULE.bazel
  `bazel_dep`; BUILD.bazel `npm_link_package`, deps, and test data entries).

## 0.2.3 and earlier

See git tags `v0.1.0`, `v0.2.2`, `v0.2.3`.
