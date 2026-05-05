# Changelog

All notable changes to `@auraprotector/agent` will be documented in this file.

## [0.6.0] — 2026-05-05

### Added
- **Additive risk-scoring engine** — 0-100 signal-based scoring with 7 weighted signals (UA quality, Accept-Language, Accept header, Connection type, POST-Referer, rate burst).
- **5-tier graduated response** — ALLOW (0-39), SLOW (40-59), CHALLENGE (60-74), DECOY (75-84), BLOCK (85+).
- **Token-bucket rate limiter** — Replaces fixed-window counter. 8 tokens/sec, 24 burst, route-aware multipliers. Memory-safe with 5-minute eviction.
- **`#respondSlow()`** — 2-second delay response to exhaust automated scanners.
- **`#respondDecoy()`** — Serves configurable maintenance-style HTML decoy page.
- **`risk_score` telemetry** — Agent-calculated score forwarded to server in log payload.

### Changed
- Bumped `AGENT_VERSION` to `0.6.0`.

## [0.4.0] — 2026-05-04

### Fixed
- **API endpoint alignment** — All agent HTTP calls now use the canonical `/agent/` prefixed routes (`/agent/verify`, `/agent/log`, `/agent/challenge/init`). Fixes silent connection failures when the server only exposes prefixed routes.

### Changed
- Bumped `AGENT_VERSION` to `0.4.0`.

## [0.3.0] — 2026-05-04

### Changed
- **Geo enrichment architecture hardened** — The server-side `/api/agent/geo-lookup` endpoint now performs local MaxMind GeoLite2 lookups instead of proxying to `ipinfo.io`. Agent behaviour is unchanged; the improvement is server-side.
- Bumped `AGENT_VERSION` to `0.3.0`.

## [0.2.2] — 2026-04-23

### Fixed
- Corrected domain references from `auraguardian.com` to `auraguardian.co` globally.

## [0.2.1] — 2026-04-23

### Changed
- License metadata updated for package registry compliance.
- Added `author`, `funding`, and `peerDependenciesMeta` fields.
- Expanded `description` and `keywords` for discoverability.

## [0.2.0] — 2026-04-15

### Added
- **HMAC payload verification** — Rules payloads are authenticated with HMAC-SHA256 before decryption. Requires platform ≥ 2026-04.
- **`X-Agent-Version` header** — Sent on every `/verify` request for dashboard version tracking.
- **`outdated` status handling** — If the cloud responds with `outdated`, the agent fails open and stops protecting until updated.

## [0.1.7] — 2026-03-01

### Added
- Initial stable release with AES-256-CBC encrypted rules sync.
- Express middleware integration.
- Zero-code preload mode via `NODE_OPTIONS`.
