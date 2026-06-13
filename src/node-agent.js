import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { shouldProtectRequest, parseCookies, normalizeIp, detectCountry, isStaticRequest, isSensitiveRequest, cidrMatch, compilePhpLikeRegex, extractTlsFingerprint, KNOWN_BAD_TLS_FINGERPRINTS, GeoLookupCache } from './node-utils.js';
import { applyObsidianToResponse, isHoneypotTrap } from './obsidian.js';

// Keep a hardcoded version to avoid JSON import/loader differences across Node runtimes.
// Update this when bumping agents/node/package.json.
const AGENT_VERSION = '0.10.2';

const INTEL_KEYS = [
  'banned_isps',
  'banned_asns',
  'scanner_uas',
  'proxy_domains',
  'cloudflare_cidrs',
  'bot_ua_regex',
  'banned_referrers',
  'bad_tls_fingerprints',
  'scanner_keywords',
  'honeypot_headers',
  'blocked_cidrs',
];

// --- Additive scoring thresholds (ported from OG engine) ---
const THRESHOLDS = { ALLOW: 0, SLOW: 40, CHALLENGE: 60, DECOY: 75, BLOCK: 85 };
const RL_RATE_PER_SEC = 8;
const RL_BURST = 24;
const RL_ROUTE_MULTIPLIERS = [
  [/^\/login/i, 0.4], [/^\/auth/i, 0.4], [/^\/api\//i, 0.7],
  [/^\/assets\//i, 2.0], [/^\/wp-login/i, 0.4], [/^\/wp-admin/i, 0.5],
];

const DECOY_HTML = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scheduled Maintenance</title><style>body{background:#0a0a0a;color:#aaa;font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}.box{text-align:center;max-width:480px}h1{font-size:1.5rem;color:#fff;margin:0 0 1rem}p{color:#666;font-size:.875rem}</style></head><body><div class="box"><h1>Scheduled Maintenance</h1><p>We are currently performing scheduled maintenance. Please try again later.</p><p style="color:#444;font-size:.75rem;margin-top:2rem">ETA: ~15 minutes</p></div></body></html>';

export class UltimateProtectorNodeAgent {
  /**
   * @param {import('./types.js').UltimateProtectorOptions} options
   */
  constructor(options) {
    if (!options || typeof options !== 'object') throw new Error('options required');
    if (!options.licenseKey) throw new Error('licenseKey required');
    if (!options.apiUrl) throw new Error('apiUrl required');

    this.licenseKey = String(options.licenseKey);
    this.apiUrl = String(options.apiUrl).replace(/\/+$/, '');
    this.syncIntervalSeconds = Math.max(10, Number(options.syncIntervalSeconds ?? 60) || 60);
    this.allowSampleRate = Math.max(0, Math.min(1, Number(options.allowSampleRate ?? 0.01) || 0));
    this.rateLimitPerMinute = Math.max(0, Number(options.rateLimitPerMinute ?? 120) || 0);

    this.onlyPaths = Array.isArray(options.onlyPaths) ? options.onlyPaths.map(String) : null;
    this.exceptPaths = Array.isArray(options.exceptPaths) ? options.exceptPaths.map(String) : null;
    this.onlyRegex = typeof options.onlyRegex === 'string' ? options.onlyRegex : null;

    this.agentKind = 'node';
    this.agentVersion = AGENT_VERSION;
    this.capabilities = ['enforce:block', 'enforce:challenge', 'telemetry:v1', 'obsidian', 'tls-fingerprint', 'geo-fallback'];

    this.maxUaLength = 1024;
    this.enforceTlsMinVersion = options.enforceTlsMinVersion !== false; // default true: block TLS < 1.2

    this.cachePath = this.#cacheFilePath();

    this.rules = null;
    this.syncedAt = 0;
    this.status = 'empty'; // empty|success|expired

    this.refreshPromise = null;

    // RDNS cache
    this.rdnsTtlSeconds = 86400;
    this.rdnsMaxEntries = 5000;
    this.rdnsCache = new Map(); // ip -> {t:number,h:string|null,gv?:boolean,sv?:boolean}

    // blocked IP set cache
    this.blockedIpSet = null;
    this.blockedIpSetVersion = null;

    // Server-side cache invalidation version
    this.rulesVersion = 0;

    // Per-IP token-bucket rate limiter (replaces fixed-window)
    this.rlBuckets = new Map(); // ip -> { ts, tokens }
    this.rlEvictAt = 0;

    // CIDR-based geo fallback lookup
    this.geoCache = new GeoLookupCache({
      apiUrl: this.apiUrl,
      licenseKey: this.licenseKey,
      ttlSeconds: 86400,
      maxEntries: 10000,
    });

    // Heartbeat: fire-and-forget ping every 5 minutes (non-blocking, no await)
    this._heartbeatIntervalMs = 300_000; // 5 minutes
    this._lastHeartbeatAt = 0;
  }

  #cacheFilePath() {
    const base = os.tmpdir();
    const safe = crypto.createHash('sha256').update(this.licenseKey).digest('hex').slice(0, 16);
    return path.join(base, `up_rules_${safe}.json`);
  }

  #cacheMacPath() {
    return this.cachePath + '.mac';
  }

  async #loadFromDisk() {
    try {
      const raw = await fs.readFile(this.cachePath, 'utf8');
      // Verify HMAC integrity — prevents cache poisoning on shared hosting
      try {
        const storedMac = await fs.readFile(this.#cacheMacPath(), 'utf8');
        const expectedMac = crypto.createHmac('sha256', this.licenseKey).update(raw).digest('hex');
        if (!storedMac || storedMac.length !== expectedMac.length ||
            !crypto.timingSafeEqual(Buffer.from(expectedMac), Buffer.from(storedMac))) {
          // HMAC mismatch — cache was tampered with, delete and re-fetch
          await fs.unlink(this.cachePath).catch(() => {});
          await fs.unlink(this.#cacheMacPath()).catch(() => {});
          return;
        }
      } catch {
        // No MAC file — legacy cache or first run; delete and re-fetch
        await fs.unlink(this.cachePath).catch(() => {});
        return;
      }
      const json = JSON.parse(raw);
      if (!json || typeof json !== 'object') return;
      if (json.status === 'expired') {
        this.status = 'expired';
        this.syncedAt = Number(json.synced_at ?? 0) || 0;
        this.rules = null;
        return;
      }
      if (json.rules && typeof json.rules === 'object') {
        this.status = 'success';
        this.syncedAt = Number(json.synced_at ?? 0) || 0;
        this.rules = json.rules;
      }
    } catch {
      // ignore
    }
  }

  async #saveToDisk() {
    try {
      const payload = this.status === 'expired'
        ? { synced_at: this.syncedAt, status: 'expired' }
        : { synced_at: this.syncedAt, status: 'success', rules: this.rules };
      const jsonStr = JSON.stringify(payload);
      await fs.writeFile(this.cachePath + '.tmp', jsonStr, 'utf8');
      await fs.rename(this.cachePath + '.tmp', this.cachePath);
      // Write HMAC sidecar for integrity verification on next read
      const mac = crypto.createHmac('sha256', this.licenseKey).update(jsonStr).digest('hex');
      await fs.writeFile(this.#cacheMacPath() + '.tmp', mac, 'utf8');
      await fs.rename(this.#cacheMacPath() + '.tmp', this.#cacheMacPath());
    } catch {
      // ignore
    }
  }

  #uaHash(ua) {
    return crypto.createHash('sha256').update(String(ua ?? '')).digest('hex');
  }

  #aesDecryptBase64(base64Payload) {
    const buf = Buffer.from(String(base64Payload), 'base64');
    // Wire format: IV[16] + ciphertext[N] + HMAC-SHA256[32]
    if (buf.length < 49) return null; // 16 IV + 1 min cipher + 32 HMAC
    const mac = buf.subarray(buf.length - 32);
    const body = buf.subarray(0, buf.length - 32);
    const iv = body.subarray(0, 16);
    const ciphertext = body.subarray(16);
    const encKey = crypto.createHash('sha256').update(this.licenseKey).digest();
    const macKey = crypto.createHash('sha256').update(this.licenseKey + ':hmac').digest();
    const expectedMac = crypto.createHmac('sha256', macKey).update(body).digest();
    try {
      if (!crypto.timingSafeEqual(expectedMac, mac)) return null;
    } catch {
      return null;
    }
    try {
      const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
      const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      const json = JSON.parse(plain);
      return json && typeof json === 'object' ? json : null;
    } catch {
      return null;
    }
  }

  async #postJson(endpoint, body, timeoutMs) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(this.apiUrl + endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'X-Agent-Version': this.agentVersion,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      const text = await res.text();
      try {
        return { ok: res.ok, status: res.status, json: JSON.parse(text) };
      } catch {
        return { ok: res.ok, status: res.status, json: null };
      }
    } finally {
      clearTimeout(t);
    }
  }

  async refreshRules(domain) {
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = (async () => {
      if (this.status === 'empty') {
        await this.#loadFromDisk();
      }

      const blockedVer = Number(this.rules?.blocked_ips_version ?? 0) || 0;
      const intelVer = Number(this.rules?.intel_version ?? 0) || 0;

      const payload = {
        license_key: this.licenseKey,
        domain: domain ?? 'unknown',
        blocked_ips_version: blockedVer,
        intel_version: intelVer,
        protocol_version: 1,
        agent_kind: this.agentKind,
        agent_version: this.agentVersion,
        capabilities: this.capabilities,
      };

      let res;
      try {
        res = await this.#postJson('/agent/verify', payload, 5000);
      } catch {
        // fail-open: keep current rules on transient network errors
        return;
      }

      const now = Math.floor(Date.now() / 1000);

      if (res.json?.status === 'expired') {
        this.status = 'expired';
        this.rules = null;
        this.syncedAt = now;
        await this.#saveToDisk();
        return;
      }

      // Outdated agent: fail-open, stop protecting.
      if (res.json?.status === 'outdated') {
        this.status = 'expired';
        this.rules = null;
        this.syncedAt = now;
        await this.#saveToDisk();
        return;
      }

      // Quota exceeded: fail-open, stop protecting temporarily.
      if (res.json?.status === 'quota_exceeded') {
        this.status = 'expired';
        this.rules = null;
        this.syncedAt = now;
        await this.#saveToDisk();
        return;
      }

      if (res.json?.status === 'success') {
        if (res.json.encrypted && res.json.payload) {
          const decoded = this.#aesDecryptBase64(res.json.payload);
          if (decoded && typeof decoded === 'object') {
            const merged = { ...decoded };

            // merge unchanged intel lists
            // Detect remote cache purge: if server's rules_version changed,
            // discard stale intel instead of merging — forces full re-download.
            const serverRulesVer = Number(res.json.rules_version ?? merged.rules_version ?? 0) || 0;
            if (serverRulesVer > this.rulesVersion && this.rulesVersion > 0) {
              // Server bumped rules_version → this is a purge signal.
              // Accept the new payload as-is without merging old intel lists.
              this.blockedIpSet = null;
              this.blockedIpSetVersion = null;
            } else if (this.rules && typeof this.rules === 'object') {
              for (const k of INTEL_KEYS) {
                if (Object.prototype.hasOwnProperty.call(merged, k) && merged[k] === null) {
                  merged[k] = this.rules[k];
                }
              }
              if (Object.prototype.hasOwnProperty.call(merged, 'global_blocked_ips') && merged.global_blocked_ips === null) {
                merged.global_blocked_ips = this.rules.global_blocked_ips;
              }
            }

            this.rulesVersion = serverRulesVer;
            this.status = 'success';
            this.rules = merged;
            this.syncedAt = now;
            await this.#saveToDisk();
            return;
          }
        }

        // non-encrypted success with null payload (domain blocked / revoked)
        if (res.json.encrypted === false && (res.json.payload ?? null) === null) {
          this.status = 'success';
          this.rules = null;
          this.syncedAt = now;
          await this.#saveToDisk();
          return;
        }
      }
    })().finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  async getRules(domain) {
    if (this.status === 'empty') {
      await this.#loadFromDisk();
    }

    const now = Math.floor(Date.now() / 1000);
    const stale = (now - (this.syncedAt || 0)) > this.syncIntervalSeconds;

    if (!this.rules && this.status !== 'expired') {
      await this.refreshRules(domain);
      return this.rules;
    }

    if (stale && this.status !== 'expired') {
      this.refreshRules(domain).catch(() => {});
    }

    return this.rules;
  }

  #passportValue() {
    return crypto.createHash('sha256').update('verified' + this.licenseKey).digest('hex');
  }

  #verifyToken(token) {
    const decoded = Buffer.from(String(token), 'base64').toString('utf8');
    if (!decoded.includes('::')) return false;
    const [tsRaw, sig] = decoded.split('::');
    const ts = Number(tsRaw);
    if (!Number.isFinite(ts)) return false;
    if ((Date.now() / 1000) - ts > 120) return false;
    const raw = `${ts}|${this.licenseKey}`;
    const calc = crypto.createHmac('sha256', this.licenseKey).update(raw).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(String(sig)));
  }

  async #rdnsLookup(ip) {
    ip = normalizeIp(ip);
    if (!ip) return null;

    const now = Math.floor(Date.now() / 1000);
    const hit = this.rdnsCache.get(ip);
    if (hit && (now - hit.t) < this.rdnsTtlSeconds) {
      return hit.h;
    }

    let hostname = null;
    try {
      const hosts = await dns.reverse(ip);
      if (Array.isArray(hosts) && hosts[0]) hostname = String(hosts[0]);
    } catch {
      hostname = null;
    }

    const prev = hit ?? {};
    this.rdnsCache.set(ip, { ...prev, t: now, h: hostname });

    if (this.rdnsCache.size > this.rdnsMaxEntries) {
      // drop oldest ~10%
      const entries = [...this.rdnsCache.entries()].sort((a, b) => (a[1].t ?? 0) - (b[1].t ?? 0));
      const toDrop = Math.ceil(this.rdnsMaxEntries * 0.1);
      for (let i = 0; i < toDrop && i < entries.length; i++) this.rdnsCache.delete(entries[i][0]);
    }

    return hostname;
  }

  async #dnsForwardIps(hostname) {
    const host = String(hostname ?? '').trim().toLowerCase().replace(/\.$/, '');
    if (!host) return [];
    try {
      const res = await dns.lookup(host, { all: true });
      return Array.isArray(res) ? res.map((r) => normalizeIp(r.address)).filter(Boolean) : [];
    } catch {
      return [];
    }
  }

  async #isVerifiedGoogleIp(ip) {
    ip = normalizeIp(ip);
    if (!ip) return false;

    const now = Math.floor(Date.now() / 1000);
    const hit = this.rdnsCache.get(ip);
    if (hit && typeof hit.gv === 'boolean' && (now - hit.t) < this.rdnsTtlSeconds) {
      return hit.gv;
    }

    const host = await this.#rdnsLookup(ip);
    const h = String(host ?? '').toLowerCase().replace(/\.$/, '');
    let verified = false;
    if (h && (h.endsWith('.googlebot.com') || h.endsWith('.google.com'))) {
      const ips = await this.#dnsForwardIps(h);
      verified = ips.includes(ip);
    }

    this.rdnsCache.set(ip, { ...(hit ?? {}), t: now, h: host ?? null, gv: verified });
    return verified;
  }

  async #isVerifiedSeoIp(ip) {
    ip = normalizeIp(ip);
    if (!ip) return false;

    const suffixes = [
      '.search.msn.com',
      '.yandex.ru', '.yandex.net', '.yandex.com',
      '.baidu.com',
      '.duckduckgo.com',
      '.applebot.apple.com',
      '.sogou.com',
      '.exabot.com',
      '.seznam.cz',
      '.naver.com',
      '.petalbot.com',
      '.bytespider.com',
      '.crawl.yahoo.net', '.yahoo.com',
      // Social media crawlers (rDNS-verifiable)
      '.facebook.com', '.fbsv.net', '.tfbnw.net',
      '.linkedin.com',
      '.twttr.com', '.twitter.com', '.x.com',
      '.pinterest.com',
    ];

    const now = Math.floor(Date.now() / 1000);
    const hit = this.rdnsCache.get(ip);
    if (hit && typeof hit.sv === 'boolean' && (now - hit.t) < this.rdnsTtlSeconds) {
      return hit.sv;
    }

    const host = await this.#rdnsLookup(ip);
    const h = String(host ?? '').toLowerCase().replace(/\.$/, '');
    let verified = false;
    if (h) {
      for (const s of suffixes) {
        if (h.endsWith(s)) {
          const ips = await this.#dnsForwardIps(h);
          verified = ips.includes(ip);
          break;
        }
      }
    }

    this.rdnsCache.set(ip, { ...(hit ?? {}), t: now, h: host ?? null, sv: verified });
    return verified;
  }

  async #isSafeSeoCrawler(ua, ip) {
    const uaLower = String(ua ?? '').toLowerCase();
    const tokensGoogle = [
      'googlebot',
      'adsbot-google',
      'mediapartners-google',
      'google-inspectiontool',
      'googleother',
      'google-extended',
      'apis-google',
    ];

    if (tokensGoogle.some((t) => uaLower.includes(t))) {
      return this.#isVerifiedGoogleIp(ip);
    }

    const tokens = [
      'bingbot', 'msnbot',
      'yandex',
      'baiduspider',
      'duckduckbot',
      'applebot',
      'sogou',
      'exabot',
      'seznambot',
      'naverbot',
      'petalbot',
      'bytespider',
      'slurp',
      // Social media crawlers (rDNS-verifiable)
      'facebookexternalhit', 'facebookcatalog', 'meta-externalagent',
      'linkedinbot',
      'twitterbot',
      'pinterest',
    ];

    if (!tokens.some((t) => uaLower.includes(t))) return false;
    return this.#isVerifiedSeoIp(ip);
  }

  /**
   * Social preview bots that use cloud infra without consistent rDNS.
   * These only fetch page metadata (OG tags) for link unfurling — low risk.
   * Allowed by UA match alone when SEO safety is enabled.
   */
  #isKnownSocialPreviewBot(ua) {
    const uaLower = String(ua ?? '').toLowerCase();
    const socialTokens = ['slackbot', 'slack-imgproxy', 'discordbot', 'telegrambot', 'whatsapp'];
    return socialTokens.some((t) => uaLower.includes(t));
  }

  #buildBlockedIpSet(rules) {
    const ver = rules?.blocked_ips_version ?? null;
    if (!ver) return;
    if (this.blockedIpSet && this.blockedIpSetVersion === ver) return;
    this.blockedIpSet = new Set(Array.isArray(rules.global_blocked_ips) ? rules.global_blocked_ips : []);
    this.blockedIpSetVersion = ver;
  }

  /**
   * Non-blocking heartbeat ping (fire-and-forget, no await).
   * Throttled to once every 5 minutes via in-memory timestamp.
   * Network failures are silently swallowed via .catch().
   */
  #sendHeartbeat(domain) {
    const now = Date.now();
    if ((now - this._lastHeartbeatAt) < this._heartbeatIntervalMs) return;
    this._lastHeartbeatAt = now;

    // Fire-and-forget — do NOT use await, attach .catch() for silent failure.
    this.#postJson('/agent/heartbeat', {
      license_key: this.licenseKey,
      domain: domain ?? 'unknown',
      agent_version: this.agentVersion,
      timestamp: Math.floor(now / 1000),
    }, 2000).catch(() => {});
  }

  async #log(action, reason, reasonCode, ctx) {
    if (!ctx || !ctx.ip) return;
    if (action === 'ALLOW' && this.allowSampleRate > 0) {
      if (Math.random() > this.allowSampleRate) return;
    }

    const body = {
      license_key: this.licenseKey,
      ip: ctx.ip,
      action,
      reason,
      reason_code: reasonCode ?? undefined,
      user_agent: ctx.ua,
      ua_hash: ctx.ua ? this.#uaHash(ctx.ua) : undefined,
      country: ctx.country,
      method: ctx.method,
      host: ctx.host,
      path: ctx.path,
      risk_score: ctx.risk_score ?? undefined,
      tls_hash: ctx.tls_hash ?? undefined,
      tls_version: ctx.tls_version ?? undefined,

      protocol_version: 1,
      agent_kind: this.agentKind,
      agent_version: this.agentVersion,
      capabilities: this.capabilities,
    };

    this.#postJson('/agent/log', body, 2000).catch(() => {});
  }

  #expiredHtml() {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Service Notice</title><style>body{background:#050507;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.card{background:#0E0E10;padding:40px;border-radius:20px;border:1px solid rgba(255,255,255,.1);text-align:center}h1{color:#ef4444}</style></head><body><div class="card"><h1>Subscription Expired</h1><p>Security license inactive. Protection disabled.</p><script>setTimeout(()=>location.reload(),6000)</script></div></body></html>`;
  }

  #blockHtml(ip, reason, rid) {
    const time = new Date().toISOString();
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied \u2014 AuraGuardian</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#08080c;color:#d4d4d8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;overflow:hidden}.bg{position:fixed;inset:0;z-index:0}.bg::before{content:"";position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(99,102,241,.08) 0%,transparent 60%),radial-gradient(ellipse at 70% 80%,rgba(244,63,94,.06) 0%,transparent 60%);animation:drift 20s ease-in-out infinite alternate}@keyframes drift{0%{transform:translate(0,0) rotate(0deg)}100%{transform:translate(30px,-20px) rotate(2deg)}}.card{position:relative;z-index:1;max-width:520px;width:90%;background:rgba(15,15,20,.85);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:48px 40px;text-align:center;backdrop-filter:blur(40px);-webkit-backdrop-filter:blur(40px);box-shadow:0 25px 50px -12px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.05)}.shield{width:64px;height:64px;margin:0 auto 24px;position:relative}.shield svg{width:100%;height:100%;filter:drop-shadow(0 0 20px rgba(99,102,241,.3))}.shield::after{content:"";position:absolute;inset:-4px;border-radius:50%;background:conic-gradient(from 0deg,transparent 0%,rgba(99,102,241,.4) 25%,transparent 50%,rgba(244,63,94,.4) 75%,transparent 100%);animation:spin 3s linear infinite;mask:radial-gradient(farthest-side,transparent calc(100% - 2px),#000 calc(100% - 2px));-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 2px),#000 calc(100% - 2px))}@keyframes spin{to{transform:rotate(360deg)}}h1{font-size:24px;font-weight:700;color:#fff;margin-bottom:8px;letter-spacing:-.02em}.subtitle{font-size:15px;color:#71717a;line-height:1.5;margin-bottom:32px}.meta{background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:16px 20px;text-align:left;font-family:"SF Mono","Cascadia Code","Fira Code",monospace;font-size:12px;color:#52525b}.meta .row{display:flex;justify-content:space-between;padding:4px 0}.meta .row+.row{border-top:1px solid rgba(255,255,255,.04)}.meta .label{color:#71717a}.meta .value{color:#a1a1aa;text-align:right;max-width:60%;word-break:break-all}.footer{margin-top:32px;font-size:11px;color:#3f3f46}.footer a{color:#6366f1;text-decoration:none;font-weight:500}.footer a:hover{text-decoration:underline}@media(max-width:480px){.card{padding:32px 24px}h1{font-size:20px}}</style></head><body><div class="bg"></div><div class="card"><div class="shield"><svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="url(#g)" opacity=".15"/><path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" stroke="url(#g)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="g" x1="3" y1="2" x2="21" y2="24" gradientUnits="userSpaceOnUse"><stop stop-color="#818cf8"/><stop offset="1" stop-color="#f43f5e"/></linearGradient></defs></svg></div><h1>Access Denied</h1><p class="subtitle">This request has been blocked by the site&#39;s security system.</p><div class="meta"><div class="row"><span class="label">Ray ID</span><span class="value">${rid}</span></div><div class="row"><span class="label">Your IP</span><span class="value">${ip}</span></div><div class="row"><span class="label">Reason</span><span class="value">${reason}</span></div><div class="row"><span class="label">Time</span><span class="value">${time}</span></div></div><p class="footer">Protected by <a href="https://auraguardian.co" target="_blank" rel="noopener">AuraGuardian</a></p></div></body></html>`;
  }

  async handleExpress(req, res, next) {
    const reqUrl = new URL(req.originalUrl || req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathOnly = reqUrl.pathname || '/';

    // Non-blocking heartbeat (throttled internally, no await)
    this.#sendHeartbeat(String(req.hostname || req.headers.host || 'unknown'));

    if (!shouldProtectRequest({
      path: pathOnly,
      onlyPaths: this.onlyPaths,
      exceptPaths: this.exceptPaths,
      onlyRegex: this.onlyRegex,
    })) {
      return next();
    }

    // Honeypot trap — any client hitting this is a bot
    if (isHoneypotTrap(req)) {
      const ip = normalizeIp(req.ip || req.socket?.remoteAddress) || '0.0.0.0';
      await this.#log('BLOCK', 'Honeypot Trap', 'honeypot', { ip, ua: String(req.headers['user-agent'] || ''), method: String(req.method || ''), host: String(req.headers.host || ''), path: pathOnly, country: detectCountry(req) });
      return this.#respondBlock(res, this.rules || {}, ip, 'Honeypot Trap');
    }

    // up_token exchange (challenge success)
    const upToken = reqUrl.searchParams.get('up_token');
    if (upToken) {
      if (!this.#verifyToken(upToken)) {
        res.status(403).type('text/plain').send('Invalid Token');
        return;
      }

      const secure = Boolean(req.secure);
      const cookieVal = this.#passportValue();
      res.setHeader('Set-Cookie', `aura_passport=${cookieVal}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`);

      // redirect to clean URL (remove query)
      res.redirect(302, pathOnly);
      return;
    }

    const cookies = parseCookies(req.headers.cookie);
    const passportVal = this.#passportValue();
    if (
      (cookies.aura_passport && cookies.aura_passport === passportVal) ||
      (cookies.up_passport && cookies.up_passport === passportVal)
    ) {
      // Verified human
      // log sampled allow
      const ip = normalizeIp(req.ip || req.socket?.remoteAddress);
      const ua = String(req.headers['user-agent'] || '');
      await this.#log('ALLOW', 'Verified Human', null, {
        ip,
        ua,
        country: detectCountry(req),
        method: String(req.method || ''),
        host: String(req.headers.host || ''),
        path: pathOnly,
      });
      return next();
    }

    const domain = String(req.hostname || req.headers.host || 'unknown');
    let rules;
    try {
      rules = await this.getRules(domain);
    } catch {
      // fail-open
      return next();
    }

    if (this.status === 'expired') {
      res.status(503).type('text/html').send(this.#expiredHtml());
      return;
    }

    if (!rules || typeof rules !== 'object') {
      // fail-open if no rules (parity with PHP agent)
      return next();
    }

    // Check server-provided bypass_paths
    if (Array.isArray(rules.bypass_paths) && rules.bypass_paths.length) {
      if (!shouldProtectRequest({
        path: pathOnly,
        onlyPaths: null,
        exceptPaths: rules.bypass_paths,
        onlyRegex: null,
      })) {
        return next();
      }
    }

    // Obsidian (best-effort)
    if (rules.obsidian_active) {
      applyObsidianToResponse(req, res, rules);
    }

    const uaRaw = String(req.headers['user-agent'] || '');
    const ua = uaRaw.length > this.maxUaLength ? uaRaw.slice(0, this.maxUaLength) : uaRaw;
    const method = String(req.method || '');
    const host = String(req.headers.host || '');
    const ref = String(req.headers.referer || '');
    const origin = String(req.headers.origin || '');

    const remote = normalizeIp(req.socket?.remoteAddress);
    const ip = this.#detectClientIp(req, rules, remote);

    // Geo detection — always resolve via API when CDN headers are absent
    let country = detectCountry(req);
    if (country === 'XX') {
      try {
        country = await this.geoCache.lookup(ip);
      } catch {
        // fail-open: keep XX
      }
    }

    const ctx = { ip, ua, method, host, path: pathOnly, country };

    // whitelist ips
    if (Array.isArray(rules.whitelist_ips) && rules.whitelist_ips.includes(ip)) {
      await this.#log('ALLOW', 'Whitelisted IP', null, ctx);
      return next();
    }

    // SEO safety
    if (rules.seo_safety_enabled) {
      const ok = await this.#isSafeSeoCrawler(ua, ip);
      if (ok) {
        await this.#log('ALLOW', 'SEO Safety', null, ctx);
        return next();
      }
      if (this.#isKnownSocialPreviewBot(ua)) {
        await this.#log('ALLOW', 'SEO Safety (Social Preview)', null, ctx);
        return next();
      }
    } else {
      // SEO safety OFF: ALL bots are denied.
      // Verified real crawlers → soft block (no ban). Fakes → hard block (ban).
      const crawlerTokens = ['googlebot','bingbot','yandex','baiduspider','duckduckbot','slurp','applebot','facebookexternalhit','twitterbot','linkedinbot','pinterestbot'];
      const uaLower = ua.toLowerCase();
      const matchedBot = crawlerTokens.find(t => uaLower.includes(t));
      if (matchedBot) {
        const verified = await this.#isSafeSeoCrawler(ua, ip);
        if (verified) {
          // Real crawler — soft block (no ban, just 403)
          await this.#log('BLOCK', `SEO Disabled \u2014 Verified Crawler: ${matchedBot}`, 'seo_disabled_crawler', ctx);
          return this.#respondSoftBlock(res, rules, ip, 'SEO Disabled');
        }
        // Fake crawler — hard block + ban
        await this.#log('BLOCK', `Fake Crawler: ${matchedBot}`, 'fake_crawler', ctx);
        return this.#respondBlock(res, rules, ip, 'Fake Crawler Detected');
      }
    }

    // L1 global blocklist
    this.#buildBlockedIpSet(rules);
    if (this.blockedIpSet && this.blockedIpSet.has(ip)) {
      await this.#log('BLOCK', 'Global Blocklist', 'global_blocklist', ctx);
      return this.#respondBlock(res, rules, ip, 'Global Blocklist');
    }

    // L1.5 per-IP rate limiter (token-bucket — scoring handles the decision)
    // (Token-bucket consumed inside #scoreRequest below)

    // L1.6 TLS/JA3 Fingerprint
    const tlsFp = extractTlsFingerprint(req.socket);
    if (tlsFp) {
      ctx.tls_hash = tlsFp.hash;
      ctx.tls_version = tlsFp.version;
      ctx.tls_cipher = tlsFp.cipher;

      // Block deprecated TLS versions (< 1.2) when enforcement enabled
      if (this.enforceTlsMinVersion && !tlsFp.minTlsVersion) {
        await this.#log('BLOCK', 'Deprecated TLS', 'tls_version', ctx);
        return this.#respondBlock(res, rules, ip, 'Insecure TLS Version');
      }

      // Check against known-bad fingerprint hashes (server-synced + local)
      const serverBadFps = Array.isArray(rules.bad_tls_fingerprints) ? rules.bad_tls_fingerprints : [];
      if (KNOWN_BAD_TLS_FINGERPRINTS.has(tlsFp.hash) || serverBadFps.includes(tlsFp.hash)) {
        await this.#log('BLOCK', 'Bad TLS Fingerprint', 'tls_fingerprint', ctx);
        return this.#respondBlock(res, rules, ip, 'Suspicious TLS Fingerprint');
      }
    }

    // L2 geo firewall (soft-block: IP is NOT auto-banned)
    // Real humans can retry with VPN or request whitelist.
    if (Array.isArray(rules.block_geo) && rules.block_geo.length) {
      const isWhitelist = (rules.geo_mode || 'blacklist') === 'whitelist';
      const inList = rules.block_geo.includes(country);
      if ((isWhitelist && !inList) || (!isWhitelist && inList)) {
        await this.#log('BLOCK', 'Geo Firewall', 'geo_soft', ctx);
        return this.#respondSoftBlock(res, rules, ip, 'Geo Firewall');
      }
    }

    // L2.5 CIDR infrastructure blocking
    if (Array.isArray(rules.blocked_cidrs) && rules.blocked_cidrs.length) {
      for (const cidr of rules.blocked_cidrs) {
        if (cidr && cidrMatch(ip, String(cidr))) {
          await this.#log('BLOCK', 'Blocked CIDR', 'blocked_cidr', ctx);
          return this.#respondBlock(res, rules, ip, 'Blocked CIDR');
        }
      }
    }

    // L2.7 Honeypot header detection
    if (Array.isArray(rules.honeypot_headers) && rules.honeypot_headers.length) {
      for (const header of rules.honeypot_headers) {
        const key = String(header).toLowerCase();
        if (key && req.headers[key] != null && req.headers[key] !== '') {
          await this.#log('BLOCK', 'Honeypot Header', 'honeypot_header', ctx);
          return this.#respondBlock(res, rules, ip, 'Honeypot Header');
        }
      }
    }

    // L3 scanner signatures
    if (Array.isArray(rules.scanner_uas)) {
      for (const bad of rules.scanner_uas) {
        if (bad && ua.toLowerCase().includes(String(bad).toLowerCase())) {
          await this.#log('BLOCK', 'Bot Signature', 'bot_signature', ctx);
          return this.#respondBlock(res, rules, ip, 'Bot Signature');
        }
      }
    }

    // L3 bot regex
    if (rules.bot_ua_regex) {
      try {
        const re = compilePhpLikeRegex(rules.bot_ua_regex) ?? new RegExp(String(rules.bot_ua_regex));
        if (re.test(ua)) {
          await this.#log('BLOCK', 'Bot Regex', 'bot_regex', ctx);
          return this.#respondBlock(res, rules, ip, 'Bot Regex');
        }
      } catch {
        // ignore invalid regex
      }
    }

    // L4 VPN shield
    if (rules.block_vpn) {
      const uri = String(req.originalUrl || req.url || '/');
      const doRdns = !isStaticRequest(uri) && method !== 'HEAD' && isSensitiveRequest(method, uri);
      let hostname = null;
      if (doRdns) {
        hostname = await this.#rdnsLookup(ip);
      }

      if (hostname && hostname !== ip) {
        if (Array.isArray(rules.proxy_domains)) {
          for (const d of rules.proxy_domains) {
            if (d && String(hostname).toLowerCase().includes(String(d).toLowerCase())) {
              await this.#log('CHALLENGE', 'Challenge', 'challenge', ctx);
              return this.#respondChallenge(req, res);
            }
          }
        }

        if (Array.isArray(rules.banned_isps)) {
          for (const isp of rules.banned_isps) {
            if (isp && String(hostname).toLowerCase().includes(String(isp).toLowerCase())) {
              await this.#log('BLOCK', 'Banned ISP', 'banned_isp', ctx);
              return this.#respondBlock(res, rules, ip, 'Banned ISP');
            }
          }
        }

        if (Array.isArray(rules.banned_asns)) {
          for (const asn of rules.banned_asns) {
            if (asn && String(hostname).toLowerCase().includes(String(asn).toLowerCase())) {
              await this.#log('BLOCK', 'Banned ASN', 'banned_asn', ctx);
              return this.#respondBlock(res, rules, ip, 'Banned ASN');
            }
          }
        }
      }
    }

    // L5 referrer security
    if (Array.isArray(rules.banned_referrers) && rules.banned_referrers.length) {
      if (method === 'POST' && !ref && !origin) {
        await this.#log('CHALLENGE', 'Challenge', 'challenge', ctx);
        return this.#respondChallenge(req, res);
      }

      if (ref) {
        try {
          const refUrl = new URL(ref);
          const refHost = refUrl.host;
          const refScheme = refUrl.protocol.replace(':', '');
          const isHttps = Boolean(req.secure);

          if (refHost === host && isHttps && refScheme === 'http') {
            await this.#log('BLOCK', 'Header Spoofing', null, ctx);
            return this.#respondBlock(res, rules, ip, 'Header Spoofing');
          }
        } catch {
          // ignore
        }

        for (const badRef of rules.banned_referrers) {
          if (badRef && ref.toLowerCase().includes(String(badRef).toLowerCase())) {
            await this.#log('BLOCK', 'Bad Referrer', 'bad_referrer', ctx);
            return this.#respondBlock(res, rules, ip, 'Bad Referrer');
          }
        }
      }
    }
    // L5.5 Custom WAF Rules (per-license, premium feature)
    if (Array.isArray(rules.custom_waf_rules) && rules.custom_waf_rules.length) {
      const wafResult = this.#evaluateCustomWafRules(rules.custom_waf_rules, ctx, req);
      if (wafResult) {
        if (wafResult.action === 'block') {
          await this.#log('BLOCK', `Custom WAF: ${wafResult.type}`, 'custom_waf', ctx);
          return this.#respondBlock(res, rules, ip, 'Custom WAF Rule');
        }
        if (wafResult.action === 'challenge') {
          await this.#log('CHALLENGE', `Custom WAF: ${wafResult.type}`, 'custom_waf', ctx);
          return this.#respondChallenge(req, res);
        }
        if (wafResult.action === 'log') {
          await this.#log('ALLOW', `Custom WAF (log-only): ${wafResult.type}`, 'custom_waf_log', ctx);
        }
      }
    }

    // --- Deep Scan: Additive Scoring Engine ---
    const [riskScore, scoreReasons] = this.#scoreRequest(req, ip, ua, pathOnly);
    ctx.risk_score = riskScore;

    if (riskScore >= THRESHOLDS.BLOCK) {
      await this.#log('BLOCK', `High Risk Score (${riskScore}): ${scoreReasons.join(', ')}`, 'high_risk_score', ctx);
      return this.#respondBlock(res, rules, ip, 'Risk Assessment');
    }
    if (riskScore >= THRESHOLDS.DECOY) {
      await this.#log('DECOY', `Decoy Score (${riskScore}): ${scoreReasons.join(', ')}`, 'decoy', ctx);
      return this.#respondDecoy(res, rules);
    }
    if (riskScore >= THRESHOLDS.CHALLENGE) {
      await this.#log('CHALLENGE', `Challenge Score (${riskScore}): ${scoreReasons.join(', ')}`, 'challenge_score', ctx);
      return this.#respondChallenge(req, res);
    }
    if (riskScore >= THRESHOLDS.SLOW) {
      await this.#log('SLOW', `Slow Score (${riskScore}): ${scoreReasons.join(', ')}`, 'slow', ctx);
      await this.#respondSlow();
      // continues to allow after delay
    }

    await this.#log('ALLOW', 'Clean Traffic', null, ctx);
    return next();
  }

  // =======================================================
  // Additive scoring engine (ported from OG UltimateProtector)
  // =======================================================

  #routeMultiplier(path) {
    for (const [rx, m] of RL_ROUTE_MULTIPLIERS) {
      if (rx.test(path)) return m;
    }
    return 1.0;
  }

  #consumeToken(ip, mult) {
    const now = Date.now() / 1000;
    let bucket = this.rlBuckets.get(ip);
    if (!bucket) {
      bucket = { ts: now, tokens: RL_BURST };
      this.rlBuckets.set(ip, bucket);
    }

    const elapsed = now - bucket.ts;
    const added = elapsed * RL_RATE_PER_SEC * mult;
    bucket.tokens = Math.min(RL_BURST * mult, bucket.tokens + added);
    bucket.ts = now;

    let exceeded = false;
    if (bucket.tokens >= 1) {
      bucket.tokens--;
    } else {
      exceeded = true;
    }

    // Evict stale entries every 5 minutes
    if (now > this.rlEvictAt) {
      this.rlEvictAt = now + 300;
      for (const [k, v] of this.rlBuckets) {
        if (now - v.ts > 120) this.rlBuckets.delete(k);
      }
    }

    return { exceeded };
  }

  #scoreRequest(req, ip, ua, pathOnly) {
    let score = 0;
    const reasons = [];

    // Token-bucket rate limit
    const mult = this.#routeMultiplier(pathOnly);
    const rl = this.#consumeToken(ip, mult);
    if (rl.exceeded) { score += 35; reasons.push('rate_burst'); }

    // UA quality signals
    if (!ua || ua === '') { score += 50; reasons.push('ua_empty'); }
    else if (ua.length < 10) { score += 25; reasons.push('ua_too_short'); }

    // Missing Accept-Language
    if (!req.headers['accept-language']) { score += 20; reasons.push('no_accept_language'); }

    // Missing or generic Accept
    const accept = req.headers['accept'] || '';
    if (!accept || accept === '*/*') { score += 15; reasons.push('generic_accept'); }

    // Connection: close
    if (String(req.headers['connection'] || '').toLowerCase() === 'close') {
      score += 10; reasons.push('conn_close');
    }

    // POST with no Referer
    if (String(req.method || '').toUpperCase() === 'POST' && !req.headers['referer']) {
      score += 15; reasons.push('post_no_referer');
    }

    // Scanner keyword match in UA (soft signal via scoring, not hard block)
    const scannerKeywords = this.rules?.scanner_keywords;
    if (Array.isArray(scannerKeywords) && scannerKeywords.length && ua) {
      const uaLower = ua.toLowerCase();
      for (const kw of scannerKeywords) {
        if (kw && uaLower.includes(String(kw).toLowerCase())) {
          score += 40; reasons.push('scanner_keyword');
          break;
        }
      }
    }

    return [Math.max(0, Math.min(100, score)), reasons];
  }

  /**
   * Evaluate per-license custom WAF rules.
   * @param {Array<{type:string,value:string,action:string}>} wafRules
   * @param {{ip:string,ua:string,path:string}} ctx
   * @param {import('http').IncomingMessage} req
   * @returns {{type:string,value:string,action:string}|null}
   */
  #evaluateCustomWafRules(wafRules, ctx, req) {
    for (const rule of wafRules) {
      if (!rule || typeof rule !== 'object') continue;
      const { type, value, action } = rule;
      if (!type || !value) continue;

      try {
        switch (type) {
          case 'ip_block':
            if (value.includes('/')) {
              // CIDR match
              if (cidrMatch(ctx.ip, value)) return { type, value, action: action || 'block' };
            } else if (ctx.ip === value) {
              return { type, value, action: action || 'block' };
            }
            break;

          case 'path_block': {
            // Regex test — wrap in delimiters if needed
            let pattern = value;
            if (pattern[0] !== '/' && pattern[0] !== '#' && pattern[0] !== '~') {
              pattern = value;
            }
            const re = new RegExp(pattern, 'i');
            if (re.test(ctx.path)) return { type, value, action: action || 'block' };
            break;
          }

          case 'header_match': {
            // value format: "Header-Name" or "Header-Name: expectedValue"
            const colonIdx = value.indexOf(':');
            if (colonIdx === -1) {
              // Just check header presence
              if (req.headers[value.toLowerCase()] != null) {
                return { type, value, action: action || 'block' };
              }
            } else {
              const headerName = value.substring(0, colonIdx).trim().toLowerCase();
              const headerVal = value.substring(colonIdx + 1).trim().toLowerCase();
              const actual = String(req.headers[headerName] || '').toLowerCase();
              if (actual && actual.includes(headerVal)) {
                return { type, value, action: action || 'block' };
              }
            }
            break;
          }

          case 'ua_block':
            if (ctx.ua && ctx.ua.toLowerCase().includes(value.toLowerCase())) {
              return { type, value, action: action || 'block' };
            }
            break;
        }
      } catch {
        // Skip malformed rules (e.g. invalid regex)
      }
    }
    return null;
  }

  async #respondSlow() {
    await new Promise(r => setTimeout(r, 2000));
  }

  #respondDecoy(res, rules) {
    const html = rules.cloak_html || DECOY_HTML;
    res.status(200).type('text/html').send(html);
  }

  #respondChallenge(req, res) {
    const proto = Boolean(req.secure) ? 'https' : 'http';
    const host = String(req.headers.host || '');
    const pathOnly = String(req.originalUrl || req.url || '/').split('?')[0] || '/';
    const currentUrl = `${proto}://${host}${pathOnly}`;
    const baseUrl = this.apiUrl.replace(/\/?api$/i, '');

    const rid = `RAY-${crypto.randomBytes(6).toString('hex')}`;
    const ip = normalizeIp(req.ip || req.socket?.remoteAddress) || '0.0.0.0';

    this.#postJson('/agent/challenge/init', {
      license_key: this.licenseKey,
      return_url: currentUrl,
    }, 2000)
      .then((r) => {
        const token = r?.json?.token;
        if (r?.ok && typeof token === 'string' && token.length > 20) {
          res.redirect(302, `${baseUrl}/security-check?token=${encodeURIComponent(token)}`);
          return;
        }
        // Fallback: block page instead of leaking license_key in URL
        res.status(403).type('text/html').send(this.#blockHtml(ip, 'Verification Required', rid));
      })
      .catch(() => res.status(403).type('text/html').send(this.#blockHtml(ip, 'Verification Required', rid)));
  }

  #respondBlock(res, rules, ip, reason) {
    if (rules.cloak_html) {
      res.status(200).type('text/html').send(String(rules.cloak_html));
      return;
    }

    const rid = `RAY-${crypto.randomBytes(6).toString('hex')}`;
    res.status(403).type('text/html').send(this.#blockHtml(ip, reason, rid));
  }

  /**
   * Soft block — same visual as #respondBlock but uses a non-escalating reason code.
   * The platform's ban pipeline ignores 'geo_soft' and 'seo_disabled_crawler' codes.
   */
  #respondSoftBlock(res, rules, ip, reason) {
    if (rules.cloak_html) {
      res.status(200).type('text/html').send(String(rules.cloak_html));
      return;
    }

    const rid = `RAY-${crypto.randomBytes(6).toString('hex')}`;
    res.status(403).type('text/html').send(this.#blockHtml(ip, reason, rid));
  }

  #detectClientIp(req, rules, remote) {
    const remoteIp = normalizeIp(remote) || '0.0.0.0';
    const cfRanges = Array.isArray(rules.cloudflare_cidrs) ? rules.cloudflare_cidrs : [];

    for (const cidr of cfRanges) {
      if (cidr && cidrMatch(remoteIp, String(cidr))) {
        const cfIp = normalizeIp(req.headers['cf-connecting-ip']);
        if (cfIp) return cfIp;

        const xff = String(req.headers['x-forwarded-for'] || '');
        if (xff) {
          const first = normalizeIp(xff.split(',')[0]?.trim());
          if (first) return first;
        }
        break;
      }
    }

    return normalizeIp(req.ip) || remoteIp;
  }
}
