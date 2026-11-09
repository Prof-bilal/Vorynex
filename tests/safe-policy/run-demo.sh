#!/usr/bin/env bash
# Safe Policy Engine demo. Six scenarios, all local, synthetic data, no root.
#   1 unsafe default policy  -> verify says DO NOT ENFORCE (ping conflict)
#   2 corrected policy       -> verify passes; legitimate ping works
#   3 shell attempt          -> denied, effect checked (marker file absent)
#   4 secret read            -> denied, effect checked (synthetic secret not returned)
#   5 unapproved egress      -> denied, effect checked (lab listener saw nothing)
#   6 rollback               -> broken candidate fails verify, previous policy stays active
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
W="$(mktemp -d /tmp/vorynex-safe.XXXXXX)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

(cd "$ROOT" && go build -o "$W/vorynex" ./cmd/vorynex) || exit 1
V="$W/vorynex"
SAFE="$W/safe"; VULN="$W/vuln"; SCRATCH="$W/scratch"; HELPERS="$W/helpers"
mkdir -p "$SAFE" "$VULN" "$SCRATCH" "$HELPERS"
cp -r "$ROOT/tests/proof/targets/safe-api/." "$SAFE/"
cp -r "$ROOT/tests/proof/targets/vulnerable-node/." "$VULN/"
cp "$(command -v ping)" "$HELPERS/ping"          # exclusive exec directory: only ping lives here
echo "SYNTHETIC-SECRET-$$" > "$W/secret.txt"        # synthetic; outside every grant
export SCRATCH PING_BIN="$HELPERS/ping"

policy() { # $1=file $2=app dir $3=extra exec allow ("" for none)
  cat > "$1" <<P
filesystem:
  read: ["$2", "$HELPERS"]
  write: ["$SCRATCH"]
network:
  allow: []
env:
  allow: [PATH, NODE_ENV, PORT, HOST, HOME, TMPDIR, SCRATCH, PING_BIN]
limits: {memory_mb: 512, timeout_s: 120}
$3
P
}
policy "$W/unsafe.yaml" "$SAFE" ""                                              # generator default: no exec
policy "$W/good.yaml"   "$SAFE" "process: {exec: {allow: [\"$HELPERS/ping\"]}}"  # narrow, enforceable
policy "$W/broad.yaml"  "$SAFE" "process: {exec: {allow: [\"/usr/bin/ping\"]}}"  # what an operator would naturally write
policy "$W/good-vuln.yaml" "$VULN" "process: {exec: {allow: [\"$HELPERS/ping\"]}}"

VERIFY_FLAGS=""
verify() { local pol=$1 p; p=$(port); PORT=$p "$V" verify $VERIFY_FLAGS --policy "$pol" --corpus "$SAFE/corpus.json" --base "http://127.0.0.1:$p" -- node "$SAFE/server.js" 2>"$W/verify.err"; }

echo "== 1. unsafe default policy (no exec) =="
OUT=$(VERIFY_FLAGS=--trace verify "$W/unsafe.yaml"); RC=$?; echo "$OUT" | sed 's/^/    /'
[[ $RC -eq 2 && "$OUT" == *"ping"*"FAIL"* && "$OUT" == *"DO NOT ENFORCE"* ]] && ok "conflict detected before rollout" || bad "conflict not detected (rc=$RC)"
[[ "$OUT" == *"execve   $HELPERS/ping  x20"* ]] && ok "trace names the denied call (execve $HELPERS/ping x20)" || bad "trace did not identify the denied execve"

echo "== 1b. natural fix /usr/bin/ping is refused as unenforceable =="
OUT=$(verify "$W/broad.yaml"); RC=$?; echo "$OUT" | sed 's/^/    /' | head -4
[[ $RC -eq 2 && "$OUT" == *"NOT ENFORCEABLE AS WRITTEN"* ]] && ok "broad exec grant rejected with capability error" || bad "broad grant accepted (rc=$RC)"

echo "== 2. corrected policy =="
OUT=$(verify "$W/good.yaml"); RC=$?; echo "$OUT" | sed 's/^/    /'
[[ $RC -eq 0 && "$OUT" == *"ping"*"PASS 20/20"* ]] && ok "all required workflows pass, ping 20/20" || bad "corrected policy failed (rc=$RC)"

# Security regression: an INTENTIONALLY vulnerable app, attacked identically in
# two arms. The bare arm is the control: if an attack does not land there, a
# "denied" result in the sandboxed arm would prove nothing.
MARK="$W/marker"; HITS="$W/hits"; STOLEN="$SCRATCH/stolen"
LAB=$(port); : > "$HITS"
python3 - "$LAB" "$HITS" <<'PY' &
import http.server,sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): open(sys.argv[2],'a').write('hit\n'); s.send_response(200); s.end_headers(); s.wfile.write(b'lab')
    def log_message(*a): pass
http.server.HTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
PY
LABPID=$!; sleep 0.5
enc() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
TRAV="$(python3 -c 'import os,sys;print(os.path.relpath(sys.argv[1],sys.argv[2]))' "$W/secret.txt" "$VULN")"

attack() { # $1=port ; sets A_SHELL A_INGRANT A_SECRET A_EGRESS (1 = attack landed)
  rm -f "$MARK" "$STOLEN"; : > "$HITS"
  curl -s "http://127.0.0.1:$1/api/ping?host=$(enc "127.0.0.1; touch $MARK")" >/dev/null
  curl -s "http://127.0.0.1:$1/api/ping?host=$(enc "127.0.0.1; cp $VULN/server.js $STOLEN")" >/dev/null
  SECRET_BODY=$(curl -s "http://127.0.0.1:$1/api/read?file=$(enc "$TRAV")")
  EGRESS_BODY=$(curl -s "http://127.0.0.1:$1/api/fetch?url=$(enc "http://127.0.0.1:$LAB/")")
  A_SHELL=0; [[ -e $MARK ]] && A_SHELL=1
  A_INGRANT=0; [[ -e $STOLEN ]] && A_INGRANT=1
  A_SECRET=0; [[ "$SECRET_BODY" == *SYNTHETIC-SECRET* ]] && A_SECRET=1
  A_EGRESS=0; [[ -s $HITS ]] && A_EGRESS=1
}
wait_up() { for _ in $(seq 100); do curl -sf "http://127.0.0.1:$1/health" >/dev/null && return; sleep 0.1; done; }

BP=$(port); PORT=$BP NODE_ENV=test node "$VULN/server.js" >/dev/null 2>&1 & BPID=$!
wait_up $BP; attack $BP; kill $BPID 2>/dev/null
echo "== control (no sandbox): attacks must land, or the tests below prove nothing =="
[[ $A_SHELL$A_INGRANT$A_SECRET$A_EGRESS == 1111 ]] && ok "bare: shell, in-grant cp, secret read and egress all landed" || bad "control did not reproduce all attacks ($A_SHELL$A_INGRANT$A_SECRET$A_EGRESS)"

VP=$(port); PORT=$VP NODE_ENV=test "$V" exec --policy "$W/good-vuln.yaml" -- node "$VULN/server.js" >"$W/vuln.log" 2>&1 & VPID=$!
wait_up $VP; attack $VP; kill $VPID 2>/dev/null
echo "== 3. shell execution attempt (injection through ping) =="
[[ $A_SHELL == 0 ]] && ok "shell denied: marker file does not exist" || bad "shell ran"
[[ $A_INGRANT == 0 ]] && ok "in-grant injection (cp into writable dir) did not happen" || bad "in-grant injection landed"
echo "== 4. prohibited synthetic secret =="
[[ $A_SECRET == 0 && "$SECRET_BODY" == *EACCES* ]] && ok "secret not returned; sandbox reported EACCES" || bad "secret leaked or not denied: ${SECRET_BODY:0:80}"
echo "== 5. unapproved egress to local lab destination =="
[[ $A_EGRESS == 0 && "$EGRESS_BODY" == *EACCES* ]] && ok "lab listener saw no connection; sandbox reported EACCES" || bad "egress landed or not denied: ${EGRESS_BODY:0:80}"
kill $LABPID 2>/dev/null

echo "== 6. rollback of a broken candidate =="
# Active state = a verified policy. A candidate is staged only if verify passes;
# otherwise the active pointer is untouched and the running workload is not replaced.
ACTIVE="$W/active.yaml"; cp "$W/good.yaml" "$ACTIVE"
AP=$(port); PORT=$AP "$V" exec --policy "$ACTIVE" -- node "$SAFE/server.js" >/dev/null 2>&1 &
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$AP/health" >/dev/null && break; sleep 0.1; done
OUT=$(verify "$W/unsafe.yaml"); RC=$?
if [[ $RC -ne 0 ]]; then echo "    candidate failed verification; active policy kept"; else cp "$W/unsafe.yaml" "$ACTIVE"; fi
cmp -s "$ACTIVE" "$W/good.yaml" && ok "active policy is still the previous verified one" || bad "active policy was replaced"
curl -s "http://127.0.0.1:$AP/api/ping?host=127.0.0.1" | grep -q '"code":0' && ok "running application still serves ping" || bad "application degraded"

echo "== 6b. feature regression AFTER startup triggers rollback (health alone would not) =="
export XDG_STATE_HOME="$W/state"; mkdir -p "$XDG_STATE_HOME"
RP=$(port)
PORT=$RP "$V" run --policy "$W/unsafe.yaml" --health "http://127.0.0.1:$RP/health" --health-interval 200ms \
  --corpus "$SAFE/corpus.json" --base "http://127.0.0.1:$RP" --watch 10s --watch-interval 500ms \
  -- node "$SAFE/server.js" >"$W/run.out" 2>&1; RC=$?
grep -q "health check passed" "$W/run.out" && ok "health check passed (so a startup-only rollback would have kept the policy)" || bad "health did not pass first"
[[ $RC -ne 0 ]] && grep -q "regression under policy: ping" "$W/run.out" && ok "watch window detected the ping regression and rolled back" || bad "no rollback (rc=$RC)"
"$V" status --json 2>/dev/null | grep -q '"mode": *"observe"' && ok "state reverted to observe" || bad "state not reverted"
curl -sf "http://127.0.0.1:$RP/health" >/dev/null && bad "workload still running after rollback" || ok "regressed workload was stopped"
unset XDG_STATE_HOME

echo; echo "demo: $PASS passed, $FAIL failed"; [[ $FAIL -eq 0 ]]
