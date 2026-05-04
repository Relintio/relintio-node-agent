# @auraprotector/agent

[![npm version](https://img.shields.io/npm/v/@auraprotector/agent)](https://www.npmjs.com/package/@auraprotector/agent)
[![Node.js](https://img.shields.io/node/v/@auraprotector/agent)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-Proprietary-blue)](./LICENSE)

In-process bot-mitigation agent for Node.js runtimes. Connects to the AuraGuardian cloud to enforce real-time threat detection, IP reputation, and adaptive content protection rules.

## Installation

```bash
npm install @auraprotector/agent
```

## Express Middleware

```js
import express from 'express';
import { ultimateProtectorExpress } from '@auraprotector/agent/express';

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
export UP_API_URL='https://app.auraguardian.co/api'
export NODE_OPTIONS='--require @auraprotector/agent/preload'

node server.js
```

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `licenseKey` | `string` | — | **Required.** Your AuraGuardian license key. |
| `apiUrl` | `string` | — | **Required.** API endpoint, e.g. `https://app.auraguardian.co/api` |
| `syncIntervalSeconds` | `number` | `60` | How often to re-fetch rules from the cloud. |
| `allowSampleRate` | `number` | `0.01` | Telemetry sampling rate for ALLOW decisions. |
| `onlyPaths` | `string[]` | — | Exact (`/checkout`) or prefix (`/product/*`) path whitelist. |
| `exceptPaths` | `string[]` | — | Paths to exclude from protection. |
| `onlyRegex` | `string` | — | JS regex source, e.g. `^/checkout` or `/.../flags`. |
| `rateLimitPerMinute` | `number` | `120` | Per-IP request cap. `0` disables. |
| `enforceTlsMinVersion` | `boolean` | `true` | Block connections below TLS 1.2. |

## Geo Enrichment

When CDN geo headers (`CF-IPCountry`, etc.) are absent, the agent calls the platform's `/api/agent/geo-lookup` endpoint.
The server resolves the country using **local MaxMind GeoLite2 databases** — zero external API calls, zero cost, microsecond latency.
Results are cached in-memory (24h TTL) to minimize round-trips.

## Requirements

- Node.js ≥ 18
- Express ≥ 4 (for middleware mode)
- Active [AuraGuardian](https://auraguardian.co) license

## Security

If you discover a security vulnerability, please report it to **support@auraguardian.co**. Do not open a public issue.

## License

Proprietary — see [LICENSE](./LICENSE) for details.
