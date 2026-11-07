// Open-loop load generator for the P4 benchmark.
//
// Requests are scheduled on a fixed clock, not in a closed loop: a slow
// response does not delay the next scheduled request. That matters because a
// closed-loop generator ("N concurrent clients looping") stops issuing requests
// while a response is stalled, which hides exactly the tail latency a defence
// added in the request path would introduce (coordinated omission).
//
// Usage: node loadgen.js --url http://127.0.0.1:PORT --rate 200 --seconds 8 --out file.json
//   --rate 0 means "as fast as 32 workers can go" (closed-loop; reported as
//   throughput only, never as a latency figure).
'use strict';

const fs = require('fs');
const http = require('http');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : def;
}

const TARGET = arg('url', 'http://127.0.0.1:3210');
const PATH = arg('path', '/api/echo?x=1');
const RATE = parseInt(arg('rate', '200'), 10);
const SECONDS = parseFloat(arg('seconds', '8'));
const TIMEOUT_MS = parseInt(arg('timeout', '2000'), 10);
const OUT = arg('out', '');
const MAX_IN_FLIGHT = 512;

const target = new URL(TARGET);
const agent = new http.Agent({ keepAlive: true, maxSockets: 64 });

const samples = [];
let sent = 0;
let ok = 0;
let errors = 0;
let timeouts = 0;
let dropped = 0;
let inFlight = 0;

function one() {
  sent++;
  inFlight++;
  const t0 = process.hrtime.bigint();
  return new Promise((resolve) => {
    const req = http.request(
      { host: target.hostname, port: target.port, path: PATH, method: 'GET', agent },
      (res) => {
        res.resume();
        res.on('end', () => {
          samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
          ok++;
          inFlight--;
          resolve();
        });
      }
    );
    req.on('error', () => { errors++; inFlight--; resolve(); });
    req.setTimeout(TIMEOUT_MS, () => { timeouts++; req.destroy(); });
    req.end();
  });
}

function percentile(sorted, q) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1);
  return sorted[idx];
}

async function openLoop() {
  const intervalMs = 1000 / RATE;
  const started = Date.now();
  const deadline = started + SECONDS * 1000;
  const pending = [];
  while (Date.now() < deadline) {
    if (inFlight >= MAX_IN_FLIGHT) {
      dropped++;            // the target cannot keep up with the schedule
    } else {
      pending.push(one());
    }
    const next = started + pending.length * intervalMs - Date.now();
    const wait = Math.min(Math.max(next, 0), intervalMs);
    await new Promise((r) => setTimeout(r, wait));
  }
  await Promise.all(pending);
}

async function closedLoop() {
  const deadline = Date.now() + SECONDS * 1000;
  const workers = Array.from({ length: 32 }, async () => {
    while (Date.now() < deadline) await one();
  });
  await Promise.all(workers);
}

async function main() {
  const started = Date.now();
  if (RATE > 0) await openLoop();
  else await closedLoop();
  const elapsed = (Date.now() - started) / 1000;
  agent.destroy();

  const sorted = samples.slice().sort((a, b) => a - b);
  const result = {
    target: TARGET,
    path: PATH,
    mode: RATE > 0 ? 'open-loop' : 'closed-loop',
    target_rate: RATE > 0 ? RATE : null,
    seconds: Math.round(elapsed * 1000) / 1000,
    sent,
    ok,
    errors,
    timeouts,
    dropped,
    achieved_rps: Math.round((ok / elapsed) * 10) / 10,
    latency_ms: {
      p50: percentile(sorted, 0.5), p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
      max: sorted.length ? sorted[sorted.length - 1] : null,
    },
  };
  const text = JSON.stringify(result, null, 2);
  if (OUT) fs.writeFileSync(OUT, text + '\n');
  process.stdout.write(text + '\n');
}

main().catch((e) => {
  process.stderr.write(`loadgen error: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
