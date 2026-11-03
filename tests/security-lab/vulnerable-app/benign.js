// Benign-operation check for the Vorynex security lab.
//
// Containment is worthless if it breaks the application. This runs the
// operations a legitimate Node service performs and asserts they still work
// under enforcement. Any "blocked" here is a FAIL, not a tuning note.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const TESTDIR = process.env.BENIGN_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'vorynex-benign-'));
const ALLOWED_URL = process.env.ALLOWED_URL || ''; // e.g. http://127.0.0.1:<port>/ok

let failures = 0;

function check(name, ok, detail) {
  const result = ok ? 'PASS' : 'FAIL';
  if (!ok) failures++;
  process.stdout.write(`${result} ${name} ${detail || ''}\n`);
}

function httpGet(url) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const req = http.get(url, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => finish({ ok: true, status: res.statusCode }));
    });
    req.on('error', (e) => finish({ ok: false, reason: e.code || e.message }));
    req.setTimeout(3000, () => req.destroy(new Error('timeout')));
  });
}

async function main() {
  // Write to a granted, app-owned directory.
  try {
    const p = path.join(TESTDIR, 'cache.tmp');
    fs.writeFileSync(p, 'ok');
    check('write_app_owned', fs.existsSync(p), p);
  } catch (e) {
    check('write_app_owned', false, e.code || e.message);
  }

  // Read the app's own tree.
  try {
    fs.readFileSync(path.join(__dirname, 'server.js'));
    check('read_app_tree', true);
  } catch (e) {
    check('read_app_tree', false, e.code || e.message);
  }

  // Legitimate egress to an allowlisted host, if configured.
  if (ALLOWED_URL) {
    const r = await httpGet(ALLOWED_URL);
    check('egress_allowed_host', r.ok, r.ok ? `HTTP ${r.status}` : r.reason);
  }

  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { process.stderr.write(String(e) + '\n'); process.exit(1); });
