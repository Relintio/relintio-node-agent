const SCRIPT_ID = 'aura-obsidian';

// Invisible honeypot link — any client that follows this is a bot.
// The href points to a trap path the main app can detect and auto-block.
const HONEYPOT_HTML = '<a href="/.well-known/aura-trap" style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none" tabindex="-1" aria-hidden="true">&nbsp;</a>';

export function applyObsidianToResponse(req, res, rules) {
  if (!rules || typeof rules !== 'object') return;

  if (rules.obsidian_headers) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
  }

  const mode = (rules.obsidian_mode === 'aggressive') ? 'aggressive' : 'compat';
  const scriptPayload = buildClientScript(rules, mode);

  // Build combined injection: honeypot + obsidian script
  let injection = '';
  if (rules.obsidian_active) {
    injection += HONEYPOT_HTML;
  }
  if (scriptPayload) {
    injection += `<script id="${SCRIPT_ID}">${scriptPayload}</script>`;
  }
  if (!injection) return;

  const origSend = res.send?.bind(res);
  if (typeof origSend === 'function') {
    res.send = function patchedSend(body) {
      const out = tryInjectHtml(body, injection, res);
      return origSend(out);
    };
  }

  const origEnd = res.end?.bind(res);
  if (typeof origEnd === 'function') {
    res.end = function patchedEnd(chunk, encoding, cb) {
      const out = tryInjectHtml(chunk, injection, res);
      return origEnd(out, encoding, cb);
    };
  }
}

/**
 * Check if the request hit the honeypot trap.
 * Call this from the agent's handleExpress before normal enforcement.
 * Returns true if the request should be blocked.
 */
export function isHoneypotTrap(req) {
  const path = String(req.originalUrl || req.url || '/').split('?')[0] || '/';
  return path === '/.well-known/aura-trap';
}

function tryInjectHtml(body, injection, res) {
  if (body == null) return body;

  const ce = String(res.getHeader?.('content-encoding') || '');
  if (ce && ce.toLowerCase() !== 'identity') {
    return body;
  }

  let s;
  if (Buffer.isBuffer(body)) {
    s = body.toString('utf8');
  } else if (typeof body === 'string') {
    s = body;
  } else {
    return body;
  }

  const ct = String(res.getHeader?.('content-type') || '');
  const isHtml = ct.includes('text/html') || /<html/i.test(s);
  if (!isHtml) return body;

  const injected = s.includes('</body>')
    ? s.replace(/<\/body>/i, injection + '</body>')
    : (s + injection);

  return Buffer.isBuffer(body) ? Buffer.from(injected, 'utf8') : injected;
}

function buildClientScript(rules, mode) {
  let js = '';

  if (rules.guard_rightclick) {
    js += "document.addEventListener('contextmenu',e=>e.preventDefault());";
  }
  if (rules.guard_devtools) {
    js += "document.onkeydown=function(e){if(e.keyCode==123||(e.ctrlKey&&e.shiftKey&&e.keyCode=='I'.charCodeAt(0))||(e.ctrlKey&&e.shiftKey&&e.keyCode=='J'.charCodeAt(0))||(e.ctrlKey&&e.keyCode=='U'.charCodeAt(0)))return false;};";
  }
  if (rules.guard_copy) {
    js += "document.addEventListener('copy',function(e){try{var t=(e.clipboardData||window.clipboardData);if(!t)return;var s=window.getSelection?String(window.getSelection()):'';if(!s)return;t.setData('text/plain',s+'\\n\\n[Protected by Aura]');e.preventDefault();}catch(_e){}});";
  }

  if (rules.obsidian_text) {
    if (mode === 'aggressive') {
      js += "(function(){function s(n){if(n.nodeType===3){n.nodeValue=n.nodeValue.split('').join('\\u200C');}else if(n.nodeType===1&&n.tagName!=='SCRIPT'&&n.tagName!=='STYLE'){for(var i=0;i<n.childNodes.length;i++){s(n.childNodes[i]);}}}}window.addEventListener('load',function(){try{s(document.body);}catch(_e){}},{once:true});})();";
    }
  }

  if (rules.obsidian_css) {
    if (mode === 'aggressive') {
      js += "(function(){function run(){try{var n=['ax-99','bz-22','c-al'];var all=document.querySelectorAll('*');for(var j=0;j<all.length;j++){all[j].classList.add(n[Math.floor(Math.random()*n.length)]);}}catch(_e){}}window.addEventListener('load',function(){setTimeout(run,50);},{once:true});})();";
    } else {
      js += "(function(){function run(){try{var roots=['#app','#__next','[data-reactroot]'];for(var i=0;i<roots.length;i++){if(document.querySelector(roots[i]))return;}var n=['ax-99','bz-22','c-al'];var all=document.querySelectorAll('*');for(var j=0;j<all.length;j++){all[j].classList.add(n[Math.floor(Math.random()*n.length)]);}}catch(_e){}}if('requestIdleCallback' in window){requestIdleCallback(run,{timeout:1200});}else{window.addEventListener('load',function(){setTimeout(run,250);});}})();";
    }
  }

  if (!js) return '';
  return `(function(){try{${js}}catch(_e){}})();`;
}
