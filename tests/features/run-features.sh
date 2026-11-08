#!/usr/bin/env bash
# Every command in the CLI, invoked and asserted.
#
# The other suites test behaviour deeply but touch only the commands they need.
# This one exists to answer a different question: is there anything we ship that
# no test ever runs? It is a contract test — exit codes and output shape — not a
# behaviour test.
#
# No root, no Docker, no network. State is isolated under the run's temp dir.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /tmp/vorynex-features.XXXXXX)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${FEATURES_OUT:-$ROOT/tests/features/evidence/$STAMP}"
export XDG_STATE_HOME="$WORK/state"

PASS=0; FAIL=0
FAILED=()
APP_PID=""; CLOUD_PID=""
cleanup() {
  [[ -n "$APP_PID" ]] && kill -- "-$APP_PID" 2>/dev/null || true
  [[ -n "$CLOUD_PID" ]] && kill "$CLOUD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "$OUT" "$WORK"

check() { # $1=name $2=status
  if [[ "$2" == "0" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS+1));
  else printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); fi
}
step() { printf '\n== %s ==\n' "$1"; }
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
json_ok() { python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$1" 2>/dev/null; }

BIN="$WORK/bin"
mkdir -p "$BIN"
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(cat VERSION 2>/dev/null || echo dev)" \
  -o "$BIN/vorynex" ./cmd/vorynex) || { echo "build failed"; exit 1; }
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BIN/vorynex-cloud" ./cmd/vorynex-cloud) || exit 1
V="$BIN/vorynex"

# --- fixtures ---------------------------------------------------------------
cat > "$WORK/osv.json" <<'JSON'
{"id":"GHSA-test-0001","aliases":["CVE-2020-0001"],
 "summary":"prototype pollution in lodash",
 "severity":[{"type":"CVSS_V3","score":"7.4"}],
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]}
JSON
cat > "$WORK/package-lock.json" <<'JSON'
{"name":"demo","lockfileVersion":2,
 "packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.4"}}}
JSON
KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
printf '%s\n' "$KEY" > "$WORK/key.hex"

# --- meta -------------------------------------------------------------------
step "meta"
"$V" version --json >"$OUT/version.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/version.json"
check "version --json emits JSON" $?
"$V" help >"$OUT/help.txt" 2>&1
check "help exits 0" $?
grep -q "preflight" "$OUT/help.txt"
check "help lists every command (preflight)" $?
"$V" no-such-command >/dev/null 2>&1
[[ $? -eq 2 ]]
check "an unknown command exits 2" $?

# --- discovery / capability -------------------------------------------------
step "discovery and capability"
"$V" doctor >"$OUT/doctor.txt" 2>&1
check "doctor exits 0" $?
grep -qi landlock "$OUT/doctor.txt"
check "doctor reports Landlock" $?
"$V" discover --details >"$OUT/discover.txt" 2>&1
check "discover --details exits 0" $?
"$V" connect >"$OUT/connect.txt" 2>&1
check "connect exits 0 with no control plane" $?
grep -qi "nothing enforced\|nothing was enforced" "$OUT/connect.txt"
check "connect says nothing was enforced" $?
"$V" live status >"$OUT/live-status.txt" 2>&1
check "live status exits 0" $?

# --- observe -> policy -> signing ------------------------------------------
step "observe, policy, signing"
"$V" observe -- node -e 'require("fs").readFileSync("/etc/hostname")' >"$OUT/observe.txt" 2>&1
check "observe exits 0" $?
TRACE="$(ls -t "$XDG_STATE_HOME/vorynex/traces"/*.jsonl 2>/dev/null | head -1)"
[[ -s "$TRACE" ]]
check "observe wrote a trace" $?
"$V" policy generate --from "$TRACE" --out "$WORK/policy.yaml" >"$OUT/policy.txt" 2>&1
check "policy generate exits 0" $?
grep -q "filesystem:" "$WORK/policy.yaml"
check "generated policy has a filesystem section" $?
"$V" policy generate --from "$TRACE" --out "$WORK/signed.yaml" --sign-key "$WORK/key.hex" \
  >"$OUT/policy-sign.txt" 2>&1
check "policy generate --sign-key exits 0" $?
[[ -s "$WORK/signed.yaml.sig" ]]
check "a signature file was written" $?
"$V" policy pubkey --key "$WORK/key.hex" >"$OUT/pubkey.txt" 2>&1
check "policy pubkey exits 0" $?
grep -q "^public key  [0-9a-f]\{64\}" "$OUT/pubkey.txt"
check "policy pubkey prints the key" $?
# Scripts pin this, so there is a machine-readable form.
"$V" policy pubkey --key "$WORK/key.hex" --json >"$OUT/pubkey.json" 2>&1
check "policy pubkey --json exits 0" $?
json_ok "$OUT/pubkey.json"
check "policy pubkey --json emits JSON" $?
PUB="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["public_key"])' "$OUT/pubkey.json" 2>/dev/null)"
[[ ${#PUB} -eq 64 ]]
check "the JSON carries a 64-hex public key" $?
"$V" policy verify --policy "$WORK/signed.yaml" --sig "$WORK/signed.yaml.sig" --pubkey "$PUB" \
  >"$OUT/verify.txt" 2>&1
check "policy verify accepts a good signature" $?
printf '# tampered\n' >> "$WORK/signed.yaml"
"$V" policy verify --policy "$WORK/signed.yaml" --sig "$WORK/signed.yaml.sig" --pubkey "$PUB" \
  >"$OUT/verify-bad.txt" 2>&1
[[ $? -ne 0 ]]
check "policy verify rejects a tampered policy" $?

# --- exec / protect / status ------------------------------------------------
step "exec, protect, status"
"$V" exec --policy "$WORK/policy.yaml" -- /usr/bin/env true >"$OUT/exec.txt" 2>&1
check "exec runs a command under a policy" $?
"$V" protect --from "$TRACE" --out "$WORK/protect.yaml" -- /usr/bin/env true \
  >"$OUT/protect-from.txt" 2>&1
check "protect --from <events> runs the workload" $?
[[ -s "$WORK/protect.yaml" ]]
check "protect --from wrote a policy" $?
"$V" protect --from-desired >"$OUT/protect-desired.txt" 2>&1
[[ $? -ne 0 ]]
check "protect --from-desired fails when nothing is staged" $?
"$V" protect --off >"$OUT/protect-off.txt" 2>&1
check "protect --off exits 0" $?
"$V" status --json >"$OUT/status.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/status.json"
check "status --json emits JSON" $?

# --- analysis commands ------------------------------------------------------
step "trace, blast radius, cve, shield"
"$V" trace --from "$TRACE" --json >"$OUT/trace.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/trace.json"
check "trace --from --json emits JSON" $?
"$V" blast-radius --policy "$WORK/policy.yaml" --json >"$OUT/blast.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/blast.json"
check "blast-radius --json emits JSON" $?
"$V" live plan --policy "$WORK/policy.yaml" >"$OUT/live-plan.txt" 2>&1
check "live plan exits 0" $?
"$V" cve scan --lockfile "$WORK/package-lock.json" --osv "$WORK/osv.json" --json \
  >"$OUT/cve.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/cve.json"
check "cve scan --json emits JSON" $?
python3 - "$OUT/cve.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
rows = d if isinstance(d, list) else d.get("matches", [])
sys.exit(0 if any("GHSA-test-0001" in json.dumps(r) for r in rows) else 1)
PY
check "cve scan finds the fixture advisory in the lockfile" $?
"$V" shield --lockfile "$WORK/package-lock.json" --osv "$WORK/osv.json" --json \
  >"$OUT/shield.json" 2>&1
[[ $? -eq 0 ]] && json_ok "$OUT/shield.json"
check "shield --json emits JSON" $?

# --- telemetry / rollout / preflight ---------------------------------------
step "telemetry, rollout, preflight"
"$V" telemetry status >"$OUT/telemetry-status.txt" 2>&1
check "telemetry status exits 0" $?
"$V" rollout status >"$OUT/rollout.txt" 2>&1
check "rollout status exits 0 with nothing staged" $?
"$V" preflight --json >"$OUT/preflight.json" 2>&1
json_ok "$OUT/preflight.json"
check "preflight --json emits JSON (exit may be non-zero)" $?

# --- enrollment (needs the control plane) ----------------------------------
step "connect --endpoint (enrollment)"
PORT_CLOUD="$(free_port)"
TOKEN="features-token"
"$BIN/vorynex-cloud" --addr "127.0.0.1:$PORT_CLOUD" --token "$TOKEN" \
  --store "$WORK/cloud.jsonl" --dashboard "$ROOT/cloud/dashboard" >"$OUT/cloud.txt" 2>&1 &
CLOUD_PID=$!
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT_CLOUD/" >/dev/null 2>&1 && break; sleep 0.2; done
"$V" connect --endpoint "http://127.0.0.1:$PORT_CLOUD" --token "$TOKEN" >"$OUT/connect-enroll.txt" 2>&1
check "connect --endpoint enrolls" $?
grep -qi "enrolled" "$OUT/connect-enroll.txt"
check "connect reports the enrollment" $?
HOSTS="$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT_CLOUD/v1/hosts")"
python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if len(d if isinstance(d,list) else d.get('hosts',[]))>=1 else 1)" <<< "$HOSTS" 2>/dev/null
check "the control plane lists the enrolled host" $?
"$V" rollout pull --endpoint "http://127.0.0.1:$PORT_CLOUD" --token "$TOKEN" >"$OUT/rollout-pull.txt" 2>&1
check "rollout pull exits 0" $?
kill "$CLOUD_PID" 2>/dev/null; wait "$CLOUD_PID" 2>/dev/null; CLOUD_PID=""

# ---------------------------------------------------------------------------
echo
echo "=================================================="
printf 'features: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -gt 0 ]] && printf 'failed: %s\n' "$(IFS=', '; echo "${FAILED[*]}")"
echo "evidence: $OUT"
{ echo "passed=$PASS failed=$FAIL"; [[ "$FAIL" -gt 0 ]] && printf 'failed_steps=%s\n' "$(IFS=', '; echo "${FAILED[*]}")"; } > "$OUT/result.txt"
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
