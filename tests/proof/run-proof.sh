#!/usr/bin/env bash
# Vorynex containment proof — arm A (bare) vs arm C (Vorynex Tier 0).
#
# The claim: every attack lands when unprotected, and none of the post-
# exploitation effects land when Vorynex is enforcing — while legitimate
# requests keep working.
#
# Safety: PROOF_AUTHORIZED=1 is required; targets are loopback-only, fixtures are
# decoys, and payloads only create/read files under the run's temp dir.
#
# Usage: PROOF_AUTHORIZED=1 ./run-proof.sh
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${PROOF_OUT:-$HERE/evidence/$STAMP}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vorynex-proof.XXXXXX")"

if [[ "${PROOF_AUTHORIZED:-0}" != "1" ]]; then
  cat >&2 <<'MSG'
Refusing to run.

This harness sends real exploit payloads. Only run it against a system you own.
It uses loopback only and decoy data, but authorization is a human act:

    PROOF_AUTHORIZED=1 ./run-proof.sh
MSG
  exit 2
fi

for bin in node python3 go curl; do
  command -v "$bin" >/dev/null || { echo "prerequisite missing: $bin" >&2; exit 2; }
done
# The caller's NODE_ENV is irrelevant; the target is explicitly a test fixture and
# refuses production itself.
export NODE_ENV=test

mkdir -p "$OUT" "$WORK/out"
APP_PID=""
COLLECTOR_PID=""
WAF_PID=""
cleanup() {
  [[ -n "$APP_PID" ]] && kill "$APP_PID" 2>/dev/null || true
  [[ -n "$WAF_PID" ]] && kill "$WAF_PID" 2>/dev/null || true
  [[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
VORYNEX="$WORK/vorynex"
(cd "$ROOT" && go build -o "$VORYNEX" ./cmd/vorynex)
echo "engine: $VORYNEX"

# --- loopback collector (host-side evidence for SSRF/egress) ----------------
HITS="$WORK/collector.hits"
: > "$HITS"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
python3 - "$HITS" "$PORT" <<'PY' &
import http.server, pathlib, sys
hits = pathlib.Path(sys.argv[1]); port = int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with hits.open("a") as f:
            f.write(self.path + "\n")
        body = b"DECOY-METADATA-NOT-REAL"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
COLLECTOR_PID=$!
for _ in $(seq 1 50); do
  python3 -c "import socket,sys;s=socket.socket();s.settimeout(0.2);sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" && break
  sleep 0.1
done

DECOY_ENV="$HERE/fixtures/decoy.env"
MARKER="$WORK/marker"
LEAK_OUT="$WORK/leak"
WRITE_TARGET="$WORK/written"
COLLECTOR_URL="http://127.0.0.1:$PORT/probe"
# The same destination spelled as a decimal IPv4 (127.0.0.1 -> 2130706433).
# getaddrinfo accepts it; signature engines match the dotted form.
INTERNAL_DECIMAL="http://2130706433:$PORT/probe"

# Per-run copy of the target, so the persistence scenario can never write into
# the repository, and so the protected arm can be given a read-only app tree.
APP_DIR="$WORK/app"
mkdir -p "$APP_DIR" "$WORK/fixtures"
cp -r "$HERE/targets/vulnerable-node/." "$APP_DIR/"
cp "$HERE/fixtures/decoy.env" "$WORK/fixtures/decoy.env"
APP_WRITE="$APP_DIR/uploaded.js"
TRAVERSAL_FILE="../fixtures/decoy.env"

export MARKER LEAK_OUT WRITE_TARGET APP_WRITE DECOY_ENV TRAVERSAL_FILE \
  COLLECTOR_HITS="$HITS" COLLECTOR_URL INTERNAL_DECIMAL NODE_ENV=test

start_app() { # $1=port, rest=command
  local port=$1; shift
  PORT=$port "$@" >"$WORK/app-$port.log" 2>&1 &
  APP_PID=$!
  for _ in $(seq 1 80); do
    if curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$APP_PID" 2>/dev/null; then break; fi
    sleep 0.1
  done
  echo "target failed to start on port $port" >&2
  cat "$WORK/app-$port.log" >&2 || true
  return 1
}

# Ports are allocated per run. Fixed ports collide with leftovers from an
# interrupted earlier run, which makes the attacker hit a stale app.
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}
PORT_A="$(free_port)"
PORT_B="$(free_port)"
PORT_W="$(free_port)"
PORT_C="$(free_port)"

stop_app() {
  [[ -n "$APP_PID" ]] || return 0
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
}

echo
echo "== arm A — bare target (attacks must land) =="
: > "$HITS"
start_app "$PORT_A" node "$APP_DIR/server.js"
node "$HERE/attacker.js" "http://127.0.0.1:$PORT_A" "$OUT/arm-a.jsonl" | tee "$OUT/arm-a.log"
stop_app

echo
echo "== arm B — OWASP CRS request layer (PL1 and PL2) =="
WAF_BIN="$WORK/proof-waf"
(cd "$HERE/waf" && go build -o "$WAF_BIN" .)
for PL in 1 2; do
  echo "-- CRS paranoia level $PL (blocking) --"
  : > "$HITS"
  start_app "$PORT_B" node "$APP_DIR/server.js"
  "$WAF_BIN" --listen "127.0.0.1:$PORT_W" --upstream "http://127.0.0.1:$PORT_B" \
    --mode blocking --paranoia "$PL" --audit "$OUT/waf-pl$PL-audit.jsonl" \
    >"$WORK/waf-pl$PL.log" 2>&1 &
  WAF_PID=$!
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$PORT_W/health" >/dev/null 2>&1 && break
    sleep 0.1
  done
  node "$HERE/attacker.js" "http://127.0.0.1:$PORT_W" "$OUT/arm-b-pl$PL.jsonl" | tee "$OUT/arm-b-pl$PL.log"
  kill "$WAF_PID" 2>/dev/null || true
  wait "$WAF_PID" 2>/dev/null || true
  WAF_PID=""
  stop_app
done

echo
echo "== arm C — Vorynex Tier 0 (effects must not land) =="
POLICY="$WORK/protect.yaml"
sed -e "s|__APP__|$APP_DIR|g" -e "s|__OUT__|$WORK/out|g" \
  "$HERE/policy/protect.yaml.template" > "$POLICY"
: > "$HITS"
start_app "$PORT_C" "$VORYNEX" exec --policy "$POLICY" -- node "$APP_DIR/server.js"
node "$HERE/attacker.js" "http://127.0.0.1:$PORT_C" "$OUT/arm-c.jsonl" | tee "$OUT/arm-c.log"
stop_app

# --- environment capture -----------------------------------------------------
python3 - "$OUT" "$ROOT" "$VORYNEX" <<'PY'
import json, os, pathlib, subprocess, sys
out, root, engine = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def sh(cmd):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception as e: return f"error: {e}"
env = {
    "git": {"sha": sh(f"cd {root} && git rev-parse HEAD"),
            "dirty": bool(sh(f"cd {root} && git status --porcelain"))},
    "kernel": sh("uname -r"),
    "os": sh("uname -srm"),
    "node": sh("node --version"),
    "engine": sh(f"{engine} version"),
    "landlock_abi": next((l.split("ABI")[1].split()[0] for l in sh(f"{engine} doctor").splitlines() if "landlock" in l.lower() and "ABI" in l), "unknown"),
    "cpu": sh("nproc"),
    "authorized": os.environ.get("PROOF_AUTHORIZED") == "1",
}
(out / "env.json").write_text(json.dumps(env, indent=2) + "\n")
PY

# --- verdicts ----------------------------------------------------------------
python3 - "$OUT" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])

def load(name):
    p = out / name
    if not p.exists(): return {}
    return {r["scenario"]: r for r in (json.loads(l) for l in p.read_text().splitlines() if l.strip())}

a, c = load("arm-a.jsonl"), load("arm-c.jsonl")
b1, b2 = load("arm-b-pl1.jsonl"), load("arm-b-pl2.jsonl")

def waf_state(entry):
    if not entry:
        return "n/a"
    if entry.get("waf") == "blocked" or entry.get("status") == 403:
        return "blocked"
    if entry.get("landed"):
        return "landed"
    return "passed"

rows, passed, failed, void, benign_fail = [], 0, 0, 0, []
crs_blocked = {1: 0, 2: 0}
crs_false_pos = {1: 0, 2: 0}
for name in a:
    if name.startswith("benign_"):
        ok = a.get(name, {}).get("landed") and c.get(name, {}).get("landed")
        if not ok:
            benign_fail.append(name)
        for pl, table in ((1, b1), (2, b2)):
            if waf_state(table.get(name)) == "blocked":
                crs_false_pos[pl] += 1
        rows.append({"scenario": name, "kind": "benign",
                     "control": bool(a.get(name, {}).get("landed")),
                     "crs_pl1": waf_state(b1.get(name)),
                     "crs_pl2": waf_state(b2.get(name)),
                     "protected": bool(c.get(name, {}).get("landed")),
                     "verdict": "PASS" if ok else "FAIL"})
        continue
    landed_control = bool(a.get(name, {}).get("landed"))
    landed_protected = bool(c.get(name, {}).get("landed"))
    for pl, table in ((1, b1), (2, b2)):
        if waf_state(table.get(name)) == "blocked":
            crs_blocked[pl] += 1
    if not landed_control:
        verdict = "VOID"; void += 1
    elif landed_protected:
        verdict = "FAIL"; failed += 1
    else:
        verdict = "PASS"; passed += 1
    rows.append({"scenario": name, "kind": "attack",
                 "control": landed_control,
                 "crs_pl1": waf_state(b1.get(name)),
                 "crs_pl2": waf_state(b2.get(name)),
                 "protected": landed_protected,
                 "verdict": verdict})

overall = "PASS" if failed == 0 and void == 0 and not benign_fail else "FAIL"
attacks = sum(1 for r in rows if r["kind"] == "attack")
summary = {
    "claim": "attacks land unprotected, are contained by Vorynex Tier 0; CRS blocks only what it recognises",
    "attacks": attacks,
    "passed": passed, "failed": failed, "void": void,
    "benign_fail": benign_fail, "benign_ok": not benign_fail,
    "crs_blocked": {"pl1": crs_blocked[1], "pl2": crs_blocked[2], "of": attacks},
    "crs_false_positives": {"pl1": crs_false_pos[1], "pl2": crs_false_pos[2]},
    "overall": overall, "rows": rows,
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
(out / "results.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

lines = ["# Vorynex containment proof — bare vs CRS vs Vorynex", "",
         f"Attacks: {attacks}  PASS {passed} / FAIL {failed} / VOID {void}  "
         f"Benign: {'ok' if not benign_fail else 'BROKEN: ' + ', '.join(benign_fail)}", "",
         f"CRS blocked {crs_blocked[1]}/{attacks} at PL1 and {crs_blocked[2]}/{attacks} at PL2. "
         f"CRS false positives on benign traffic: PL1 {crs_false_pos[1]}, PL2 {crs_false_pos[2]}.", "",
         "| Scenario | Bare | CRS PL1 | CRS PL2 | Vorynex | Verdict |", "|---|---|---|---|---|---|"]
for r in rows:
    lines.append(f"| {r['scenario']} | {'landed' if r['control'] else 'blocked'} | "
                 f"{r['crs_pl1']} | {r['crs_pl2']} | "
                 f"{'landed' if r['protected'] else 'blocked'} | **{r['verdict']}** |")
lines += ["", f"**Overall: {overall}**", "",
          "VOID means the attack did not land even unprotected — it proves nothing.",
          "CRS 'blocked' means the request never reached the app. Vorynex never blocks",
          "the request; it denies the effect, so it does not need to recognise the payload."]
(out / "evidence.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
sys.exit(0 if overall == "PASS" else 1)
PY

RC=$?
( cd "$OUT" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256 )
echo
echo "evidence: $OUT"
exit $RC
