// Benign fixture: the same feature set as the proof target, written without the
// intentional vulnerabilities. In particular ping does NOT use a shell: it runs
// one fixed binary with an argv array and a validated host.
//
// Env: PORT, SCRATCH (writable dir), PING_BIN (absolute path of the ping binary)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns');
const { execFile } = require('child_process');

const PORT = Number(process.env.PORT || 3230);
const BASE = __dirname;
const SCRATCH = process.env.SCRATCH || '/tmp';
const PING_BIN = process.env.PING_BIN || '/usr/bin/ping';
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/; // no leading '-', no shell metacharacters

const json = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': b.length });
  res.end(b);
};
const within = (root, p) => { const r = path.resolve(root, p); return r === root || r.startsWith(root + path.sep) ? r : null; };

// Background job: a heartbeat the verifier can observe.
let beats = 0;
const beat = () => { try { fs.writeFileSync(path.join(SCRATCH, 'job-heartbeat'), String(++beats)); } catch (e) { beats = -1; } };
beat();
setInterval(beat, 200).unref();

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    switch (u.pathname) {
      case '/health': return json(res, 200, { status: 'ok' });
      case '/api/echo': return json(res, 200, { ok: true, x: u.searchParams.get('x') || '' });
      case '/api/read': {
        const f = within(BASE, u.searchParams.get('file') || '');
        return json(res, 200, f ? { content: fs.readFileSync(f, 'utf8').slice(0, 4000) } : { error: 'outside root' });
      }
      case '/api/write': {
        const f = within(SCRATCH, path.relative(SCRATCH, u.searchParams.get('path') || ''));
        if (!f) return json(res, 200, { error: 'outside scratch' });
        fs.writeFileSync(f, u.searchParams.get('data') || '');
        return json(res, 200, { ok: true });
      }
      case '/api/ping': {
        const host = u.searchParams.get('host') || '127.0.0.1';
        if (!HOST_RE.test(host)) return json(res, 400, { error: 'invalid host' });
        return execFile(PING_BIN, ['-c', '1', '-W', '2', host], { timeout: 5000 }, (err, stdout, stderr) =>
          json(res, 200, { code: err ? 1 : 0, stdout: String(stdout || '').slice(0, 300), stderr: String(stderr || '').slice(0, 300), error: err && err.code === 'EACCES' ? 'EACCES' : undefined }));
      }
      case '/api/upload': {
        let n = 0; const f = path.join(SCRATCH, 'upload.bin'); const ws = fs.createWriteStream(f);
        req.on('data', (c) => { n += c.length; });
        req.pipe(ws); return ws.on('finish', () => json(res, 200, { ok: true, bytes: n }));
      }
      case '/api/tmpfile': {
        const f = path.join(SCRATCH, 'tmp-' + process.pid);
        fs.writeFileSync(f, 'x'); const back = fs.readFileSync(f, 'utf8'); fs.unlinkSync(f);
        return json(res, 200, { ok: back === 'x' });
      }
      case '/api/dns':
        return dns.lookup('localhost', (err, addr) => json(res, 200, err ? { error: err.code } : { ok: true, addr }));
      case '/api/job':
        return json(res, 200, { ok: beats > 0, beats });
      default: return json(res, 404, { error: 'not found' });
    }
  } catch (e) { return json(res, 200, { error: e.code || e.message }); }
}).listen(PORT, '127.0.0.1');
