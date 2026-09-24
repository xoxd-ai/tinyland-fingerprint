# Changelog

## 0.3.1 — unreleased source candidate

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
