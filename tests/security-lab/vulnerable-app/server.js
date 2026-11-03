// DELIBERATELY VULNERABLE — DO NOT DEPLOY
//
// Purpose: a controlled target for the Vorynex security lab
// (tests/security-lab/). It exists only to demonstrate that containment holds
// when an application is exploited. It uses Node's built-in http module so the
// lab has no package dependencies and runs offline.
//
// The `/run` endpoint is an INTENTIONAL command-injection sink. Do not copy it.

'use strict';

const http = require('http');
const { exec } = require('child_process');
const { URL } = require('url');

if (process.env.NODE_ENV === 'production') {
  console.error('security-lab app refuses to run with NODE_ENV=production');
  process.exit(2);
}

const PORT = Number(process.env.PORT || 3210);
const HOST = process.env.HOST || '127.0.0.1';

function json(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': body.length });
  res.end(body);
}

const server = http.createServer((req, res) => {
  let u;
  try {
    u = new URL(req.url, `http://${HOST}:${PORT}`);
  } catch {
    return json(res, 400, { error: 'bad request' });
  }

  if (u.pathname === '/health') {
    return json(res, 200, { ok: true, pid: process.pid });
  }

  if (u.pathname === '/api/data') {
    return json(res, 200, { data: 'legit', items: [1, 2, 3] });
  }

  if (u.pathname === '/run') {
    const cmd = u.searchParams.get('cmd');
    if (!cmd) return json(res, 400, { error: 'cmd required' });
    // INTENTIONAL command injection — the whole point of the lab.
    exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
      json(res, 200, {
        cmd,
        stdout: String(stdout || '').slice(0, 500),
        stderr: String(stderr || '').slice(0, 500),
        code: err ? (err.code || 1) : 0,
      });
    });
    return;
  }

  if (u.pathname === '/exfil') {
    const target = u.searchParams.get('url');
    if (!target) return json(res, 400, { error: 'url required' });
    const r = http.get(target, (up) => {
      let d = '';
      up.on('data', (c) => { d += c; });
      up.on('end', () => json(res, 200, { status: up.statusCode, body: d.slice(0, 200) }));
    });
    r.on('error', (e) => json(res, 200, { error: String(e.message) }));
    r.setTimeout(3000, () => { r.destroy(new Error('timeout')); });
    return;
  }

  return json(res, 404, { error: 'not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`LAB_APP_READY ${HOST}:${PORT} pid=${process.pid}`);
});
