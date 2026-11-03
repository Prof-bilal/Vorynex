#!/usr/bin/env bash
# Vorynex security lab — defensive proof of value.
#
# Runs the post-exploitation action set twice: once unprotected (control, the
# attack must land) and once under enforcement (protected, it must be contained).
# Containment is confirmed host-side from the loopback collector log, not from
# the workload's own output.
#
# Interim engine: the Warden binary from upstream/warden. When the Vorynex agent
# exists, set PROTECTED_CMD to its wrapper and drop the policy generation below.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
APP="$HERE/vulnerable-app"
FIX="$HERE/fixtures"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${LAB_OUT:-$HERE/evidence/$STAMP}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vorynex-lab.XXXXXX")"

# APPOUT is the only directory granted writable to the protected workload.
# OUTSIDE is deliberately NOT granted, so a write there must be denied.
APPOUT="$WORK/appout"
OUTSIDE="$WORK/outside"
mkdir -p "$OUT" "$APPOUT" "$OUTSIDE"

command -v node >/dev/null || { echo "prerequisite missing: node" >&2; exit 2; }
command -v python3 >/dev/null || { echo "prerequisite missing: python3" >&2; exit 2; }

COLLECTOR_PID=""
cleanup() {
  [[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- enforcement wrapper -----------------------------------------------------
# PROTECTED_CMD is a prefix applied before `node <attack.js> ...`.
#
# Default engine is `vorynex` (the Tier 0 spawn-time Landlock shim). Set
# LAB_ENGINE=warden to run the protection phase under the interim Warden engine
# instead (kept for comparison; it does not contain shell execution).
LAB_ENGINE="${LAB_ENGINE:-vorynex}"
POLICY="$WORK/protect.yaml"
sed -e "s|__APP__|$APP|g" -e "s|__OUT__|$APPOUT|g" \
    "$HERE/policy/protect.yaml.template" > "$POLICY"

PROTECTED_CMD="${PROTECTED_CMD:-}"
if [[ -z "$PROTECTED_CMD" ]]; then
  if ! command -v go >/dev/null; then
    echo "no PROTECTED_CMD and Go is unavailable to build the engine." >&2
    echo "Install Go, or set PROTECTED_CMD to your enforcement wrapper." >&2
    exit 2
  fi
  if [[ "$LAB_ENGINE" == "warden" ]]; then
    WARDEN="$WORK/warden"
    (cd "$ROOT/upstream/warden/warden-starter/warden" && go build -o "$WARDEN" ./cmd/warden) || {
      echo "failed to build the Warden engine" >&2; exit 2; }
    PROTECTED_CMD="$WARDEN run --backend linux --policy $POLICY --"
  else
    VORYNEX="$WORK/vorynex"
    (cd "$ROOT" && go build -o "$VORYNEX" ./cmd/vorynex) || {
      echo "failed to build the vorynex engine" >&2; exit 2; }
    PROTECTED_CMD="$VORYNEX exec --policy $POLICY --"
  fi
fi

# --- loopback collector (host-side evidence) ---------------------------------
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
        body = b"DESTINATION_REACHED"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
COLLECTOR_PID=$!
for _ in $(seq 1 50); do
  python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" && break
  sleep 0.1
done

DECOY_ENV="$FIX/decoy.env"
DECOY_SSH="$FIX/decoy_ssh_key"
WRITE_TARGET="$OUTSIDE/probe.bin"
COLLECTOR_URL="http://127.0.0.1:$PORT/collect"
METADATA_URL="http://127.0.0.1:$PORT/meta"

export DECOY_ENV DECOY_SSH WRITE_TARGET COLLECTOR_URL METADATA_URL NODE_ENV=test

hits_count() { [[ -f "$HITS" ]] && wc -l < "$HITS" | tr -d ' ' || echo 0; }

# --- control phase -----------------------------------------------------------
echo "== control phase (unprotected; attacks must land) =="
CONTROL_JSONL="$OUT/control.jsonl"
node "$APP/attack.js" "$CONTROL_JSONL" | tee "$OUT/control-stdout.log" || true
CONTROL_HITS="$(hits_count)"

# --- protected phase ---------------------------------------------------------
echo
echo "== protected phase (under enforcement; attacks must be contained) =="
: > "$HITS"                                  # reset so protected hits are conclusive
PROTECTED_TMP="$APPOUT/protected.jsonl"      # written inside the granted dir
PROTECTED_JSONL="$OUT/protected.jsonl"
# shellcheck disable=SC2086
$PROTECTED_CMD node "$APP/attack.js" "$PROTECTED_TMP" | tee "$OUT/protected-stdout.log" || true
[[ -f "$PROTECTED_TMP" ]] && cp "$PROTECTED_TMP" "$PROTECTED_JSONL"
PROTECTED_HITS="$(hits_count)"

# --- benign phase ------------------------------------------------------------
echo
echo "== benign phase (legitimate operations must still work) =="
BENIGN_RC=0
# shellcheck disable=SC2086
BENIGN_DIR="$APPOUT" $PROTECTED_CMD node "$APP/benign.js" | tee "$OUT/benign-stdout.log" || BENIGN_RC=$?

# --- verdicts ----------------------------------------------------------------
python3 - "$CONTROL_JSONL" "$PROTECTED_JSONL" "$CONTROL_HITS" "$PROTECTED_HITS" "$OUT" "$BENIGN_RC" "$HITS" "$LAB_ENGINE" <<'PY'
import json, pathlib, sys

control_p = pathlib.Path(sys.argv[1]); protected_p = pathlib.Path(sys.argv[2])
control_hits = int(sys.argv[3]); protected_hits = int(sys.argv[4])
out = pathlib.Path(sys.argv[5]); benign_rc = int(sys.argv[6]); hits_p = pathlib.Path(sys.argv[7])
engine = sys.argv[8] if len(sys.argv) > 8 else "unknown"

def load(p):
    if not p.exists():
        return {}
    return {r["attack"]: r for r in
            (json.loads(l) for l in p.read_text().splitlines() if l.strip())}

control, protected = load(control_p), load(protected_p)
scenarios = sorted(set(control) | set(protected))
verdicts, passed, failed, void = [], 0, 0, 0
for name in scenarios:
    c, p = control.get(name), protected.get(name)
    if not c or c.get("actual") != "allowed":
        v = "VOID"; void += 1
    elif p and p.get("actual") == "blocked":
        v = "PASS"; passed += 1
    else:
        v = "FAIL"; failed += 1
    verdicts.append({"attack": name, "verdict": v,
                     "control": c.get("actual") if c else None,
                     "protected": p.get("actual") if p else None})

# Containment is only real if the protected phase caused no collector hits.
egress_contained = protected_hits == 0
overall = (failed == 0 and void == 0 and benign_rc == 0 and egress_contained
           and control_hits > 0)

summary = {
    "engine": engine, "attacks": len(scenarios),
    "passed": passed, "failed": failed, "void": void,
    "benign_rc": benign_rc, "benign_ok": benign_rc == 0,
    "control_hits": control_hits, "protected_hits": protected_hits,
    "egress_contained": egress_contained,
    "verdicts": verdicts,
    "overall": "PASS" if overall else "FAIL",
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
(out / "results.jsonl").write_text("\n".join(json.dumps(v) for v in verdicts) + "\n")

lines = ["# Vorynex security lab — evidence", "",
         f"Engine: {summary['engine']}  Attacks: {summary['attacks']}  "
         f"PASS {passed} / FAIL {failed} / VOID {void}  "
         f"Benign: {'ok' if benign_rc == 0 else 'BROKEN'}  "
         f"Collector hits: control {control_hits}, protected {protected_hits}", "",
         "| Attack | Control | Protected | Verdict |", "|---|---|---|---|"]
for v in verdicts:
    lines.append(f"| {v['attack']} | {v['control']} | {v['protected']} | **{v['verdict']}** |")
lines += ["", f"**Overall: {summary['overall']}**"]
(out / "evidence.md").write_text("\n".join(lines) + "\n")

print("\n".join(lines))
sys.exit(0 if overall else 1)
PY
RC=$?
echo
echo "evidence: $OUT"
exit $RC
