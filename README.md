# @auraprotector/agent (Node)

In-process agent for Node runtimes.

## Express usage

```js
import express from 'express';
import { ultimateProtectorExpress } from '@auraprotector/agent/express';

const app = express();

app.use(ultimateProtectorExpress({
  licenseKey: 'UP_LIVE_...',
  apiUrl: 'https://YOUR_CLOUD/api',
}));

app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## Zero-code usage (preload)

If you don't want to modify app code, you can preload the agent and it will
auto-wrap Node's HTTP server request listener (best-effort, fail-open).

```bash
export UP_LICENSE_KEY='UP_LIVE_...'
export UP_API_URL='https://YOUR_CLOUD/api'
export NODE_OPTIONS='--require @auraprotector/agent/preload'

node server.js
```

## Options

- `licenseKey` (required)
- `apiUrl` (required) e.g. `https://cloud.example/api`
- `syncIntervalSeconds` (default: `60`)
- `allowSampleRate` (default: `0.01`) telemetry sampling for ALLOW
- `onlyPaths`: string[] exact (`/checkout`) or prefix (`/product/*`)
- `exceptPaths`: string[]
- `onlyRegex`: string (JS regex source, e.g. `^/checkout`) or `/.../flags`
