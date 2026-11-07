// SSRF collector for the P3 arm.
//
// Lives as a sibling container on the app's Docker network so the target can
// reach it by service name (`http://collector:3290/probe`). It records every
// request path into /proof, which is bind-mounted from the host, so the harness
// verifies the server-side fetch actually happened instead of trusting the
// application's HTTP response.
const fs = require('fs');
const http = require('http');

const OUT = '/proof/hits.log';

http.createServer((req, res) => {
  try {
    fs.appendFileSync(OUT, `${req.url}\n`);
  } catch {
    /* a collector that cannot log must not take the app down */
  }
  res.end('DECOY-COLLECTOR-NOT-REAL');
}).listen(3290, '0.0.0.0', () => console.log('collector listening on 3290'));
