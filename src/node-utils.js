import net from 'node:net';
import crypto from 'node:crypto';

export function parseCookies(cookieHeader) {
  const raw = String(cookieHeader || '');
  if (!raw) return {};
  const out = {};
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v);
  }
  return out;
}

export function normalizeIp(ip) {
  if (!ip) return '';
  let s = String(ip).trim();
  if (s.startsWith('::ffff:')) s = s.slice('::ffff:'.length);
  if (s.includes('%')) s = s.split('%')[0];
  return net.isIP(s) ? s : '';
}

export function detectCountry(req) {
  const h = req?.headers || {};
  const cf = h['cf-ipcountry'];
  if (cf) return String(cf).toUpperCase().slice(0, 2);
  const keys = [
    'x-country-code',
    'x-azure-geo-country-pc',
    'x-appengine-country',
    'geoip-country-code',
    'x-geo-country',
    'ci-geoip-country-code',
  ];
  for (const k of keys) {
    const v = h[k];
    if (v) return String(v).toUpperCase().slice(0, 2);
  }
  return 'XX';
}

export function isStaticRequest(uri) {
  const p = String(uri || '');
  const pathOnly = p.split('?')[0] || '';
  const dot = pathOnly.lastIndexOf('.');
  if (dot === -1) return false;
  const ext = pathOnly.slice(dot + 1).toLowerCase();
  if (!ext) return false;
  const staticExts = new Set([
    'css', 'js', 'map', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico',
    'woff', 'woff2', 'ttf', 'eot', 'otf',
    'mp3', 'mp4', 'webm', 'wav', 'ogg',
    'pdf', 'zip', 'gz', 'rar',
  ]);
  return staticExts.has(ext);
}

export function isSensitiveRequest(method, uri) {
  const m = String(method || '').toUpperCase();
  if (m === 'POST') return true;
  const pathOnly = String(uri || '').split('?')[0].toLowerCase();
  if (!pathOnly) return false;
  const markers = ['/wp-login', '/wp-admin', '/xmlrpc', '/login', '/admin', '/checkout'];
  return markers.some((x) => pathOnly.includes(x));
}

export function shouldProtectRequest({ path, onlyPaths, exceptPaths, onlyRegex }) {
  const p = String(path || '/') || '/';

  const matchList = (patterns) => {
    for (const pat of patterns) {
      const s = String(pat || '');
      if (!s) continue;
      if (s.endsWith('*')) {
        const prefix = s.slice(0, -1).replace(/\/+$/, '');
        if (prefix && p.startsWith(prefix)) return true;
      } else if (p === s) {
        return true;
      }
    }
    return false;
  };

  if (Array.isArray(exceptPaths) && exceptPaths.length && matchList(exceptPaths)) return false;
  if (Array.isArray(onlyPaths) && onlyPaths.length) return matchList(onlyPaths);
  if (onlyRegex) {
    try {
      const s = String(onlyRegex);
      const re = s.startsWith('/') && s.lastIndexOf('/') > 0
        ? new RegExp(s.slice(1, s.lastIndexOf('/')), s.slice(s.lastIndexOf('/') + 1))
        : new RegExp(s);
      return re.test(p);
    } catch {
      return true;
    }
  }
  return true;
}

// Accept PHP-like regex strings such as "#bot#i" or "/bot/i" and return a JS RegExp.
// If parsing fails, returns null.
export function compilePhpLikeRegex(raw) {
  const s = String(raw || '');
  if (!s) return null;

  const delim = s[0];
  if (/^[a-z0-9\\]$/i.test(delim)) {
    try { return new RegExp(s); } catch { return null; }
  }

  const last = findLastUnescaped(s, delim);
  if (last <= 0) {
    try { return new RegExp(s); } catch { return null; }
  }

  const pattern = s.slice(1, last);
  const flagsRaw = s.slice(last + 1);
  // Keep only JS-supported flags.
  const flags = flagsRaw.replace(/[^gimsuy]/g, '');
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

function findLastUnescaped(s, ch) {
  for (let i = s.length - 1; i > 0; i--) {
    if (s[i] !== ch) continue;
    // count preceding backslashes
    let bs = 0;
    for (let j = i - 1; j >= 0 && s[j] === '\\'; j--) bs++;
    if (bs % 2 === 0) return i;
  }
  return -1;
}

// IPv4+IPv6 CIDR match (no deps)
export function cidrMatch(ip, cidr) {
  const sIp = normalizeIp(ip);
  const sCidr = String(cidr || '');
  const idx = sCidr.indexOf('/');
  if (!sIp || idx === -1) return false;
  const subnet = sCidr.slice(0, idx);
  const bits = Number(sCidr.slice(idx + 1));
  const sSubnet = normalizeIp(subnet);
  if (!sSubnet || !Number.isFinite(bits)) return false;
  const vIp = net.isIP(sIp);
  const vSub = net.isIP(sSubnet);
  if (vIp !== vSub) return false;
  if (vIp === 4) return ipv4CidrMatch(sIp, sSubnet, bits);
  if (vIp === 6) return ipv6CidrMatch(sIp, sSubnet, bits);
  return false;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map((x) => Number(x));
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!Number.isInteger(p) || p < 0 || p > 255) return null;
    n = (n << 8) | p;
  }
  return n >>> 0;
}

function ipv4CidrMatch(ip, subnet, bits) {
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(subnet);
  if (a === null || b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

function ipv6ToBuf(ip) {
  // expand ::
  const parts = ip.split('::');
  let head = parts[0] ? parts[0].split(':') : [];
  let tail = parts[1] ? parts[1].split(':') : [];
  if (parts.length > 2) return null;

  // handle IPv4-mapped tail
  const last = tail[tail.length - 1] || head[head.length - 1];
  if (last && last.includes('.')) {
    const v4 = last;
    const v4Int = ipv4ToInt(v4);
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    if (tail.length) {
      tail = tail.slice(0, -1).concat([hi, lo]);
    } else {
      head = head.slice(0, -1).concat([hi, lo]);
    }
  }

  const missing = 8 - (head.filter(Boolean).length + tail.filter(Boolean).length);
  if (missing < 0) return null;
  const full = head.filter((x) => x !== '').concat(new Array(missing).fill('0')).concat(tail.filter((x) => x !== ''));
  if (full.length !== 8) return null;

  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const v = parseInt(full[i], 16);
    if (!Number.isFinite(v) || v < 0 || v > 0xffff) return null;
    buf.writeUInt16BE(v, i * 2);
  }
  return buf;
}

function ipv6CidrMatch(ip, subnet, bits) {
  const a = ipv6ToBuf(ip);
  const b = ipv6ToBuf(subnet);
  if (!a || !b) return false;
  const bytes = Math.floor(bits / 8);
  const rem = bits % 8;
  if (bytes && !a.subarray(0, bytes).equals(b.subarray(0, bytes))) return false;
  if (rem === 0) return true;
  const mask = 0xff << (8 - rem);
  return (a[bytes] & mask) === (b[bytes] & mask);
}

/**
 * Extract a TLS fingerprint from a Node.js TLS socket.
 * Approximates JA3 by hashing: TLS version + cipher suite.
 * True JA3 requires raw ClientHello (not exposed by Node).
 *
 * @param {import('tls').TLSSocket|null} socket
 * @returns {{hash:string, version:string, cipher:string, minTlsVersion:boolean}|null}
 */
export function extractTlsFingerprint(socket) {
  if (!socket || typeof socket.getProtocol !== 'function') return null;
  try {
    const protocol = socket.getProtocol?.() || '';
    const cipherInfo = socket.getCipher?.() || {};
    const cipher = cipherInfo.name || '';
    const version = cipherInfo.version || protocol || '';
    if (!cipher && !version) return null;

    const raw = `${protocol}|${cipher}|${version}`;
    const hash = crypto.createHash('md5').update(raw).digest('hex');

    // Flag if TLS version is below 1.2
    const minTlsVersion = !protocol ||
      protocol === 'TLSv1.3' ||
      protocol === 'TLSv1.2';

    return { hash, version: protocol, cipher, minTlsVersion };
  } catch {
    return null;
  }
}

// Known-bad TLS fingerprint hashes (bots, scrapers, outdated clients)
// These are MD5(protocol|cipher|version) for known automation tools.
export const KNOWN_BAD_TLS_FINGERPRINTS = new Set([
  // Placeholder entries — populated from threat intel.
  // In production, these are synced from the server via rules.bad_tls_fingerprints
]);

/**
 * In-memory geo lookup cache with TTL.
 * Falls back to API call when no geo header is present.
 */
export class GeoLookupCache {
  constructor({ apiUrl, licenseKey, ttlSeconds = 86400, maxEntries = 10000 }) {
    this.apiUrl = String(apiUrl || '').replace(/\/+$/, '');
    this.licenseKey = String(licenseKey || '');
    this.ttlSeconds = ttlSeconds;
    this.maxEntries = maxEntries;
    this.cache = new Map(); // ip -> { country, ts }
    this.pending = new Map(); // ip -> Promise
  }

  /**
   * Resolve country for an IP. Returns cached value or fetches from API.
   * @param {string} ip
   * @returns {Promise<string>} ISO-3166 country code or 'XX'
   */
  async lookup(ip) {
    ip = normalizeIp(ip);
    if (!ip) return 'XX';

    const now = Math.floor(Date.now() / 1000);
    const hit = this.cache.get(ip);
    if (hit && (now - hit.ts) < this.ttlSeconds) {
      return hit.country;
    }

    // Deduplicate concurrent lookups for same IP
    if (this.pending.has(ip)) {
      return this.pending.get(ip);
    }

    const promise = this._fetch(ip).then((country) => {
      this.cache.set(ip, { country, ts: now });
      this.pending.delete(ip);
      this._evict();
      return country;
    }).catch(() => {
      this.pending.delete(ip);
      return 'XX';
    });

    this.pending.set(ip, promise);
    return promise;
  }

  async _fetch(ip) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    try {
      const res = await fetch(this.apiUrl + '/agent/geo-lookup', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ license_key: this.licenseKey, ip }),
        signal: ctrl.signal,
      });
      const json = await res.json();
      return (json && typeof json.country === 'string' && json.country.length === 2)
        ? json.country.toUpperCase()
        : 'XX';
    } catch {
      return 'XX';
    } finally {
      clearTimeout(t);
    }
  }

  _evict() {
    if (this.cache.size <= this.maxEntries) return;
    const entries = [...this.cache.entries()].sort((a, b) => a[1].ts - b[1].ts);
    const drop = Math.ceil(this.maxEntries * 0.1);
    for (let i = 0; i < drop && i < entries.length; i++) {
      this.cache.delete(entries[i][0]);
    }
  }
}
