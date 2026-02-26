/*
 * UltimateProtector Node agent preload (CommonJS)
 * Enable with:
 *   NODE_OPTIONS="--require @auraprotector/agent/preload" node server.js
 *
 * Reads env:
 *   UP_LICENSE_KEY (required)
 *   UP_API_URL (required)
 *   UP_ONLY_PATHS (optional, comma/newline separated)
 *   UP_EXCEPT_PATHS (optional, comma/newline separated)
 *   UP_ONLY_REGEX (optional)
 */

'use strict';

if (globalThis.__UP_AGENT_PRELOAD_INSTALLED__) {
  // idempotent
  module.exports = {};
  return;
}
globalThis.__UP_AGENT_PRELOAD_INSTALLED__ = true;

const licenseKey = String(process.env.UP_LICENSE_KEY || '').trim();
const apiUrl = String(process.env.UP_API_URL || '').trim();
const disabled = String(process.env.UP_AGENT_DISABLE || '').trim();

if (!licenseKey || !apiUrl || disabled) {
  module.exports = {};
  return;
}

const parseList = (raw) => {
  const s = String(raw || '').trim();
  if (!s) return null;
  const parts = s.split(/[\n,]+/g).map((x) => x.trim()).filter(Boolean);
  return parts.length ? parts : null;
};

const options = {
  licenseKey,
  apiUrl,
  syncIntervalSeconds: Number(process.env.UP_SYNC_INTERVAL_SECONDS || process.env.UP_SYNC_INTERVAL || '') || undefined,
  allowSampleRate: Number(process.env.UP_ALLOW_SAMPLE_RATE || '') || undefined,
  onlyPaths: parseList(process.env.UP_ONLY_PATHS),
  exceptPaths: parseList(process.env.UP_EXCEPT_PATHS),
  onlyRegex: process.env.UP_ONLY_REGEX ? String(process.env.UP_ONLY_REGEX) : null,
};

// drop undefined keys (agent constructor applies defaults)
for (const k of Object.keys(options)) {
  if (options[k] === undefined) delete options[k];
}

const agentPromise = import('./node-agent.js').then((m) => new m.UltimateProtectorNodeAgent(options));

function decorateReq(req) {
  if (!req || typeof req !== 'object') return;
  if (req.originalUrl == null) req.originalUrl = req.url;

  if (req.secure == null) {
    const xf = String(req.headers?.['x-forwarded-proto'] || '');
    const sockSecure = Boolean(req.socket && req.socket.encrypted);
    req.secure = sockSecure || xf.toLowerCase().includes('https');
  }

  if (req.hostname == null) {
    const host = String(req.headers?.host || '');
    req.hostname = host ? host.split(':')[0] : undefined;
  }
}

function decorateRes(res) {
  if (!res || typeof res !== 'object') return;

  // Install minimal Express-like helpers so the agent can respond.
  // These are removed before calling the original listener (to avoid shadowing Express APIs).

  if (typeof res.status !== 'function') {
    res.__up_tmp_status = true;
    res.status = function status(code) {
      res.statusCode = Number(code) || 200;
      return res;
    };
  }

  if (typeof res.type !== 'function') {
    res.__up_tmp_type = true;
    res.type = function type(ct) {
      try { res.setHeader('Content-Type', String(ct)); } catch {}
      return res;
    };
  }

  if (typeof res.send !== 'function') {
    res.__up_tmp_send = true;
    res.send = function send(body) {
      if (body == null) {
        res.end('');
        return res;
      }
      if (Buffer.isBuffer(body)) {
        res.end(body);
        return res;
      }
      if (typeof body === 'string') {
        res.end(body);
        return res;
      }
      try {
        if (!res.getHeader('Content-Type')) res.setHeader('Content-Type', 'application/json; charset=utf-8');
      } catch {}
      res.end(JSON.stringify(body));
      return res;
    };
  }

  if (typeof res.redirect !== 'function') {
    res.__up_tmp_redirect = true;
    res.redirect = function redirect(a, b) {
      let status = 302;
      let loc = a;
      if (typeof b !== 'undefined') {
        status = Number(a) || 302;
        loc = b;
      }
      res.statusCode = status;
      try { res.setHeader('Location', String(loc || '/')); } catch {}
      res.end('');
      return res;
    };
  }
}

function cleanupRes(res) {
  if (!res || typeof res !== 'object') return;
  if (res.__up_tmp_status) { try { delete res.status; } catch {} }
  if (res.__up_tmp_type) { try { delete res.type; } catch {} }
  if (res.__up_tmp_send) { try { delete res.send; } catch {} }
  if (res.__up_tmp_redirect) { try { delete res.redirect; } catch {} }
  try { delete res.__up_tmp_status; } catch {}
  try { delete res.__up_tmp_type; } catch {}
  try { delete res.__up_tmp_send; } catch {}
  try { delete res.__up_tmp_redirect; } catch {}
}

function wrapRequestListener(listener) {
  if (typeof listener !== 'function') return listener;
  if (listener.__up_wrapped) return listener;

  const wrapped = function upWrappedListener(req, res) {
    decorateReq(req);
    decorateRes(res);

    agentPromise
      .then((agent) => agent.handleExpress(req, res, () => {
        cleanupRes(res);
        try {
          const r = listener(req, res);
          return (r && typeof r.then === 'function') ? r : undefined;
        } catch (e) {
          return Promise.reject(e);
        }
      }))
      .catch(() => {
        // fail-open: run original handler
        cleanupRes(res);
        try { listener(req, res); } catch { try { res.statusCode = 500; res.end(''); } catch {} }
      });
  };

  wrapped.__up_wrapped = true;
  return wrapped;
}

function patchCreateServer(mod) {
  if (!mod || typeof mod.createServer !== 'function') return;
  if (mod.createServer.__up_patched) return;

  const orig = mod.createServer;
  mod.createServer = function createServerPatched(...args) {
    if (args.length && typeof args[args.length - 1] === 'function') {
      args[args.length - 1] = wrapRequestListener(args[args.length - 1]);
    }
    return orig.apply(this, args);
  };
  mod.createServer.__up_patched = true;
}

try { patchCreateServer(require('node:http')); } catch {}
try { patchCreateServer(require('node:https')); } catch {}

module.exports = {};
