# Changelog

All notable changes to `@auraprotector/agent` will be documented in this file.

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
