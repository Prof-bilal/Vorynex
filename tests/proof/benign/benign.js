// Benign corpus for the false-positive measurement.
//
// A containment number with no false-positive number is not a result: a policy
// that blocks everything scores 100% containment and is useless. This drives the
// operations the application legitimately performs and reports which ones the
// policy denied.
//
// "Denied" means the sandbox refused an operation the app attempted (EACCES/
// EPERM), not merely that a response was unhappy — an app failing for its own
// reasons is not our false positive.
//
// Usage: node benign.js <baseUrl> <out.json>
// Env:   SCRATCH (a directory the policy grants for writes)
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const BASE = (process.argv[2] || 'http://127.0.0.1:3210').replace(/\/$/, '');
const OUT = process.argv[3] || '/tmp/benign.json';
const SCRATCH = process.env.SCRATCH || '/tmp/vorynex-benign-scratch';
const SCRATCH_FILE = path.join(SCRATCH, 'benign-write.txt');

const q = (s) => encodeURIComponent(s);

function get(pathAndQuery) {
  return new Promise((resolve) => {
    const req = http.get(BASE + pathAndQuery, { timeout: 5000 }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
  });
}

// Each operation states what "legitimate success" means for it.
const ops = [
  {
    name: 'health',
    count: 20,
    path: () => '/health',
    ok: (r) => r.status === 200 && !/"error"/.test(r.body),
  },
  {
    name: 'echo',
    count: 60,
    path: () => '/api/echo?x=1',
    ok: (r) => r.status === 200 && /"ok":true/.test(r.body),
  },
  {
    name: 'read_own_file',
    count: 20,
    path: () => '/api/read?file=server.js',
    ok: (r) => r.status === 200 && /createServer/.test(r.body),
  },
  {
    name: 'write_granted_dir',
    count: 20,
    path: () => `/api/write?path=${q(SCRATCH_FILE)}&data=benign`,
    ok: (r) => r.status === 200 && /"ok":true/.test(r.body),
  },
  {
    // The application's own feature: `ping -c 1 <host>`. Legitimate, and it
    // needs a shell. A refused execve surfaces as code:1 with empty stderr
    // (node reports the error out of band), which is how a denied spawn is told
    // apart from a command that ran and failed.
    name: 'legit_exec',
    count: 20,
    path: () => '/api/ping?host=127.0.0.1',
    ok: (r) => r.status === 200 && /"code":0/.test(r.body),
    // A refused execve: non-zero code with nothing on stderr, which is not how a
    // command that ran and failed looks.
    denied: (r) => /"code":1/.test(r.body) && /"stderr":""/.test(r.body),
  },
];

// Default denial signature for operations that report the errno themselves.
const DENIAL = /"error":"(EACCES|EPERM)"/;

(async () => {
  try { fs.mkdirSync(SCRATCH, { recursive: true }); } catch { /* ignore */ }

  const results = [];
  for (const op of ops) {
    let failures = 0;
    let denied = 0;
    let sample = '';
    for (let i = 0; i < op.count; i++) {
      const r = await get(op.path());
      if (!op.ok(r)) {
        failures++;
        if ((op.denied || ((x) => DENIAL.test(x.body)))(r)) denied++;
        if (!sample) sample = String(r.body).slice(0, 120);
      }
    }
    results.push({ name: op.name, count: op.count, failures, denied, sample });
  }

  const total = results.reduce((n, r) => n + r.count, 0);
  const denied = results.reduce((n, r) => n + r.denied, 0);
  const failures = results.reduce((n, r) => n + r.failures, 0);
  const summary = {
    total_ops: total,
    failed_ops: failures,
    sandbox_denials: denied,
    fp_rate: total ? Math.round((denied / total) * 10000) / 100 : null,
    ops: results,
  };
  fs.writeFileSync(OUT, JSON.stringify(summary, null, 2) + '\n');
  for (const r of results) {
    process.stdout.write(
      `  ${r.denied ? 'DENIED' : r.failures ? 'failed' : 'ok    '}  ${r.name.padEnd(18)} ` +
      `${r.count - r.failures}/${r.count}${r.denied ? `  (sandbox denied ${r.denied})` : ''}\n`
    );
    if (r.failures && r.sample) process.stdout.write(`          sample: ${r.sample}\n`);
  }
  process.stdout.write(
    `  benign total: ${total - failures}/${total} legitimate operations succeeded, ` +
    `${denied} denied by the sandbox (FP rate ${summary.fp_rate}%)\n`
  );
})();
