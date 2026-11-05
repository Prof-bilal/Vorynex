// DELIBERATELY VULNERABLE — DO NOT DEPLOY.
//
// Controlled target for the Vorynex containment proof (tests/proof). Every
// endpoint exists to be exploited; the shape mirrors a Node/Next route handler.
// No dependencies, so the harness runs offline.
//
//   GET /health                 liveness + pid
//   GET /api/echo?x=            benign echo (control for false positives)
//   GET /api/ping?host=         INTENTIONAL command injection (exec with input)
//   GET /api/read?file=         INTENTIONAL path traversal (readFile with input)
//   GET /api/fetch?url=         INTENTIONAL SSRF (http.get with input)
//   GET /api/write?path=&data=  INTENTIONAL arbitrary write
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

if (process.env.NODE_ENV === 'production') {
  console.error('proof target refuses to run with NODE_ENV=production');
  process.exit(2);
}

const PORT = Number(process.env.PORT || 3220);
const HOST = '127.0.0.1';
const BASE = __dirname;

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

  if (u.pathname === '/health') return json(res, 200, { ok: true, pid: process.pid });

  if (u.pathname === '/api/echo') {
    return json(res, 200, { ok: true, x: u.searchParams.get('x') || '' });
  }

  if (u.pathname === '/api/ping') {
    const host = u.searchParams.get('host') || '127.0.0.1';
    // INTENTIONAL command injection: user input reaches the shell.
    return exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
      json(res, 200, {
        stdout: String(stdout || '').slice(0, 300),
        stderr: String(stderr || '').slice(0, 300),
        code: err ? 1 : 0,
      });
    });
  }

  if (u.pathname === '/api/read') {
    const file = u.searchParams.get('file') || '';
    try {
      // INTENTIONAL traversal: no root confinement.
      return json(res, 200, { content: fs.readFileSync(path.join(BASE, file), 'utf8').slice(0, 4000) });
    } catch (e) {
      return json(res, 200, { error: e.code || e.message });
    }
  }

  if (u.pathname === '/api/fetch') {
    const target = u.searchParams.get('url');
    if (!target) return json(res, 400, { error: 'url required' });
    // INTENTIONAL SSRF: whatever URL the caller asks for.
    const r = http.get(target, (up) => {
      let d = '';
      up.on('data', (c) => { d += c; });
      up.on('end', () => json(res, 200, { status: up.statusCode, body: d.slice(0, 500) }));
    });
    r.on('error', (e) => json(res, 200, { error: String(e.message) }));
    r.setTimeout(3000, () => r.destroy(new Error('timeout')));
    return;
  }

  if (u.pathname === '/api/write') {
    const target = u.searchParams.get('path');
    const data = u.searchParams.get('data') || 'pwned';
    if (!target) return json(res, 400, { error: 'path required' });
    // INTENTIONAL arbitrary write.
    try {
      fs.writeFileSync(target, data);
      return json(res, 200, { ok: true, wrote: target });
    } catch (e) {
      return json(res, 200, { error: e.code || e.message });
    }
  }

  return json(res, 404, { error: 'not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`PROOF_APP_READY ${HOST}:${PORT} pid=${process.pid}`);
});
