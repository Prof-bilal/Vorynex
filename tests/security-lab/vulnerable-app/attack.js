// Post-exploitation action set for the Vorynex security lab.
//
// Runs the same actions that follow a real web-app RCE (see
// docs/COMPETITIVE_RESEARCH.md): spawn a shell, read secrets, reach cloud
// metadata, exfiltrate, write to system paths. Each action is attempted
// independently and reported as blocked/allowed, so the same script can be run
// unprotected (control) and under enforcement (protected).
//
// Usage: node attack.js <results.jsonl>
// Env:   DECOY_ENV, DECOY_SSH, COLLECTOR_URL, WRITE_TARGET

'use strict';

const fs = require('fs');
const http = require('http');
const cp = require('child_process');
const OUT = process.argv[2] || '/tmp/lab-results.jsonl';
const DECOY_ENV = process.env.DECOY_ENV || '/nonexistent/.env';
const DECOY_SSH = process.env.DECOY_SSH || '/nonexistent/id_rsa';
const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://127.0.0.1:9/collect';
// In the lab this points at a local stub representing the IMDS endpoint; in a
// real deployment it is http://169.254.169.254/.
const METADATA_URL = process.env.METADATA_URL || 'http://169.254.169.254/latest/meta-data/';
const WRITE_TARGET = process.env.WRITE_TARGET || '/usr/bin/vorynex-lab-probe';

const results = [];

// Prefer /usr/bin paths: on merged-/usr systems /bin is a symlink that a
// spawn-time sandbox may not materialize, which would make an exec look
// "blocked" for the wrong reason. Testing a real, present shell path is the
// honest test of whether execution is actually restricted.
function firstExisting(paths, fallback) {
  for (const p of paths) {
    try { if (fs.existsSync(p)) return p; } catch { /* ignore */ }
  }
  return fallback;
}
const SHELL = firstExisting(['/usr/bin/bash', '/bin/bash'], '/bin/sh');
const SH = firstExisting(['/usr/bin/sh', '/bin/sh'], '/bin/sh');

function readFile(p) {
  try {
    const d = fs.readFileSync(p);
    return { blocked: false, reason: `read ${d.length} bytes` };
  } catch (e) {
    return { blocked: true, reason: e.code || e.message };
  }
}

// Direct execve of an explicit binary. This is the honest test of whether
// execution is restricted: it does not rely on Node routing through /bin/sh
// (which a spawn-time sandbox may simply not mount, masking the real behavior).
function execShell(bin, args) {
  const r = cp.spawnSync(bin, args, { timeout: 5000, encoding: 'utf8' });
  if (r.error) return { blocked: true, reason: r.error.code || r.error.message };
  return { blocked: false, reason: `ran, status ${r.status}` };
}

function writeFile(p) {
  try {
    fs.writeFileSync(p, 'vorynex-lab-escape-probe\n');
    const ok = fs.existsSync(p);
    if (ok) { try { fs.unlinkSync(p); } catch {} }
    return { blocked: !ok, reason: ok ? 'wrote and removed' : 'write did not persist' };
  } catch (e) {
    return { blocked: true, reason: e.code || e.message };
  }
}

function httpGet(url, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let req;
    try {
      req = http.get(url, (res) => {
        let d = '';
        res.on('data', (c) => { d += c; });
        res.on('end', () => finish({ blocked: false, reason: `HTTP ${res.statusCode}` }));
      });
    } catch (e) {
      return finish({ blocked: true, reason: e.code || e.message });
    }
    req.on('error', (e) => finish({ blocked: true, reason: e.code || e.message }));
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('timeout')); });
  });
}

async function scenario(attack, expected, fn) {
  let actual = 'blocked';
  let reason = '';
  try {
    const r = await fn();
    actual = r.blocked ? 'blocked' : 'allowed';
    reason = r.reason || '';
  } catch (e) {
    actual = 'blocked';
    reason = String(e && e.message ? e.message : e);
  }
  const result = expected === actual ? 'PASS' : 'FAIL';
  results.push({ attack, expected, actual, result, reason });
  process.stdout.write(`${result} ${attack} (expected ${expected}, got ${actual}) ${reason}\n`);
}

async function main() {
  await scenario('shell_spawn', 'blocked', () => execShell(SH, ['-c', 'id']));
  await scenario('bash_spawn', 'blocked', () => execShell(SHELL, ['-c', 'echo pwned']));
  await scenario('secret_read', 'blocked', () => readFile(DECOY_ENV));
  await scenario('ssh_read', 'blocked', () => readFile(DECOY_SSH));
  await scenario('cloud_metadata', 'blocked', () => httpGet(METADATA_URL));
  await scenario('egress_c2', 'blocked', () => httpGet(COLLECTOR_URL));
  await scenario('write_system', 'blocked', () => writeFile(WRITE_TARGET));

  fs.writeFileSync(OUT, results.map((r) => JSON.stringify(r)).join('\n') + '\n');
}

main().catch((e) => {
  process.stderr.write(`attack harness error: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
