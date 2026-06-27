# @relintio/agent

[![npm version](https://img.shields.io/npm/v/@relintio/agent)](https://www.npmjs.com/package/@relintio/agent)
[![Node.js](https://img.shields.io/node/v/@relintio/agent)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-Proprietary-blue)](./LICENSE)

In-process bot-mitigation agent for Node.js runtimes. Connects to the Relintio cloud to enforce real-time threat detection, IP reputation, adaptive content protection, and **additive risk scoring** with graduated response.

> **Note on Features & Quotas**: Advanced features (like Bot Challenge and Custom Shield Pages) are tied to your subscription plan. If you exceed your monthly API quota, the agent will operate in a degraded mode (basic protection) before ultimately failing-open to prevent locking you out of your own site. All configuration rules are centrally managed via the dashboard.

## Installation

```bash
npm install @relintio/agent
```

## Express Middleware

```js
import express from 'express';
import { ultimateProtectorExpress } from '@relintio/agent/express';

const app = express();

app.use(ultimateProtectorExpress({
  licenseKey: process.env.UP_LICENSE_KEY,
  apiUrl: process.env.UP_API_URL,
}));

app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## Zero-Code Preload

If you prefer not to modify application code, preload the agent via `NODE_OPTIONS`. The agent will auto-wrap Node's HTTP server request listener (fail-open on error).

```bash
export UP_LICENSE_KEY='UP_LIVE_...'
export UP_API_URL='https://relintio.com/api'
export NODE_OPTIONS='--require @relintio/agent/preload'

node server.js
```

## Risk Scoring Engine (v0.10.2)

Every request is evaluated using an **additive 0-100 signal-based score**. Signals include:

| Signal | Weight | Description |
|---|---|---|
| Empty User-Agent | +50 | No UA header sent |
| Short User-Agent | +25 | UA < 20 characters |
| No Accept-Language | +20 | Missing browser locale header |
| Generic Accept | +15 | Wildcard `*/*` only |
| Connection: close | +10 | Non-persistent connection |
| POST without Referer | +15 | Form submission without origin |
| Rate burst | +35 | Token-bucket exhaustion |

### Response Tiers

| Tier | Score Range | Behavior |
|---|---|---|
| **ALLOW** | 0–39 | Request proceeds normally |
| **SLOW** | 40–59 | 2-second delay to exhaust scanners |
| **CHALLENGE** | 60–74 | Browser verification challenge |
| **DECOY** | 75–84 | Serves fake maintenance page |
| **BLOCK** | 85–100 | Hard block with configured response |

### Token-Bucket Rate Limiter

Replaces the legacy fixed-window counter. Default: **8 tokens/sec**, burst capacity of **24**. Route-aware multipliers give extra capacity to static assets and reduce capacity for sensitive endpoints.

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `licenseKey` | `string` | — | **Required.** Your Relintio license key. |
| `apiUrl` | `string` | — | **Required.** API endpoint, e.g. `https://relintio.com/api` |
| `syncIntervalSeconds` | `number` | `60` | How often to re-fetch rules from the cloud. |
| `allowSampleRate` | `number` | `0.01` | Telemetry sampling rate for ALLOW decisions. |
| `onlyPaths` | `string[]` | — | Exact (`/checkout`) or prefix (`/product/*`) path whitelist. |
| `exceptPaths` | `string[]` | — | Paths to exclude from protection. |
| `onlyRegex` | `string` | — | JS regex source, e.g. `^/checkout` or `/.../flags`. |
| `rateLimitPerMinute` | `number` | `120` | Per-IP request cap. `0` disables. |
| `enforceTlsMinVersion` | `boolean` | `true` | Block connections below TLS 1.2. |

## Path Bypass Rules (Server-Side)

If your application serves both browser traffic **and** API/webhook endpoints, machine callers (curl, python-requests, Go-http-client) will be scored as bots by default.

To prevent false positives, configure **Bypass Rules** in the Relintio dashboard:

**Settings → Access Control → Bypass Rules**

```
/api/*
/webhooks/*
/health
/.well-known/*
```

Requests matching a bypass pattern skip **all** bot detection layers — no scoring, no challenge. Use `*` as a wildcard. One pattern per line.

> ⚠️ Bypassed paths have **zero** bot protection. Only bypass paths you fully control (API endpoints, webhook receivers, health checks). Never bypass login or user-facing form routes.

This is a server-side configuration — no code changes needed in your Node.js application.

## Geo Enrichment

When CDN geo headers (`CF-IPCountry`, etc.) are absent, the agent calls the platform's `/api/agent/geo-lookup` endpoint.
The server resolves the country using **local MaxMind GeoLite2 databases** — zero external API calls, zero cost, microsecond latency.
Results are cached in-memory (24h TTL) to minimize round-trips.

## Requirements

- Node.js ≥ 18
- Express ≥ 4 (for middleware mode)
- Active [Relintio](https://relintio.com) license

## Security

If you discover a security vulnerability, please report it to **support@relintio.com**. Do not open a public issue.

### ⚠️ CVE-2026-4926 — `path-to-regexp` ReDoS

**Severity:** High (CVSS 7.5) · **Affects:** Express ≤ 4.21.1 via `path-to-regexp` < 8.4.0

If you use `@relintio/agent` in Express middleware mode, ensure your `express` dependency is **≥ 4.21.2** to include the patched `path-to-regexp`. Run:

```bash
npm update express
```

The agent itself does not bundle Express — it is your application's responsibility to keep it updated.

## License

Proprietary — see [LICENSE](./LICENSE) for details.
