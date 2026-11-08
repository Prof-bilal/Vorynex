#!/usr/bin/env bash
# End-to-end acceptance test: the journey a new operator actually takes.
#
#   build → install → capability report → observe a workload → generate a policy
#   → run the workload under it → attack it (and prove the attack lands without
#   enforcement) → roll back a failing workload → turn protection off → push
#   telemetry into the control plane
#
# Needs no root and no Docker. Where a host capability is missing (no Landlock,
# no strace) the affected steps are SKIPPED loudly and the run fails unless
# E2E_ALLOW_SKIP=1, because a green run that silently tested nothing is worse
# than a red one.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /tmp/vorynex-e2e.XXXXXX)"
PREFIX="$WORK/prefix"
export XDG_STATE_HOME="$WORK/state"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${E2E_OUT:-$ROOT/tests/e2e/evidence/$STAMP}"

PASS=0; FAIL=0; SKIP=0
FAILED_NAMES=()
OPTIONAL_SKIPPED=()
APP_PID=""; CLOUD_PID=""
PORT_APP=0; PORT_CLOUD=0
# The workload lives somewhere stable, not under /tmp: the policy generator
# treats /tmp (like /usr, /lib, /proc, /dev) as runtime-provided scratch and
# never grants it, so an application there could never be protected. This
# mirrors a real deployment.
APPDIR="${VORYNEX_E2E_APPDIR:-$HOME/.local/share/vorynex-e2e/app}"

cleanup() {
  # Supervisors spawn the workload, so kill the whole process group: killing the
  # `vorynex run` pid alone would leave the application behind.
  for pid in "$APP_PID" "$CLOUD_PID"; do
    [[ -n "$pid" ]] && kill -- "-$pid" 2>/dev/null || true
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  [[ "${E2E_KEEP:-0}" == "1" ]] || rm -rf "$(dirname "$APPDIR")"
}
trap cleanup EXIT

mkdir -p "$OUT" "$WORK"

check() { # $1=name $2=condition-ok(0/1)
  if [[ "$2" == "0" ]]; then
    printf '  PASS  %s\n' "$1"; PASS=$((PASS+1))
  else
    printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); FAILED_NAMES+=("$1")
  fi
}
ok() { return 0; }
bad() { return 1; }
skip() { printf '  SKIP  %s (%s)\n' "$1" "$2"; SKIP=$((SKIP+1)); }
# A capability the host may simply not have (Docker). Skipping it does not
# weaken the run the way skipping enforcement would, so it is counted apart.
skip_optional() { printf '  SKIP  %s (%s)\n' "$1" "$2"; OPTIONAL_SKIPPED+=("$1"); }
step() { printf '\n== %s ==\n' "$1"; }
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}
wait_http() { # $1=url, $2=tries
  for _ in $(seq 1 "${2:-60}"); do
    curl -sf "$1" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}
json() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1],{'d':d}))" "$1" 2>/dev/null; }

echo "Vorynex end-to-end acceptance"
echo "work=$WORK  evidence=$OUT"

# ---------------------------------------------------------------------------
step "1. build with a stamped version"
VERSION_EXPECTED="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.0.0-dev)"
BIN="$WORK/bin"
mkdir -p "$BIN"
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION_EXPECTED -X main.commit=e2e -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o "$BIN/vorynex" ./cmd/vorynex) >"$OUT/build-agent.log" 2>&1
check "agent builds" $?
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION_EXPECTED" \
  -o "$BIN/vorynex-cloud" ./cmd/vorynex-cloud) >"$OUT/build-cloud.log" 2>&1
check "control plane builds" $?

VJSON="$("$BIN/vorynex" version --json 2>/dev/null)"
[[ "$(echo "$VJSON" | json 'd["version"]')" == "$VERSION_EXPECTED" ]]
check "version is stamped from VERSION ($VERSION_EXPECTED)" $?
[[ "$(echo "$VJSON" | json 'd["commit"]')" == "e2e" ]]
check "commit is stamped" $?
"$BIN/vorynex" help >/dev/null 2>&1
check "help exits 0" $?
"$BIN/vorynex" not-a-command >/dev/null 2>&1
[[ $? -eq 2 ]]
check "unknown command exits 2 (not 0)" $?

# ---------------------------------------------------------------------------
step "2. install into a private prefix (the installer a user runs)"
PREFIX="$PREFIX" "$ROOT/install.sh" --prefix "$PREFIX" --no-cloud >"$OUT/install.log" 2>&1
check "install.sh exits 0" $?
[[ -x "$PREFIX/bin/vorynex" ]]
check "agent installed to prefix/bin" $?
[[ -f "$PREFIX/etc/vorynex/agent.env" ]]
check "workload config written" $?
[[ -f "$PREFIX/etc/vorynex/cloud-token.env" ]]
check "cloud token generated" $?
[[ "$(stat -c '%a' "$PREFIX/etc/vorynex/cloud-token.env" 2>/dev/null)" == "600" ]]
check "token file is 0600" $?
"$PREFIX/bin/vorynex" version >/dev/null 2>&1
check "installed binary runs" $?
# idempotent: a second install must not fail and must not clobber config
BEFORE="$(sha256sum "$PREFIX/etc/vorynex/cloud-token.env" | cut -d' ' -f1)"
PREFIX="$PREFIX" "$ROOT/install.sh" --prefix "$PREFIX" --no-cloud >"$OUT/install-2.log" 2>&1
check "install.sh is idempotent" $?
[[ "$BEFORE" == "$(sha256sum "$PREFIX/etc/vorynex/cloud-token.env" | cut -d' ' -f1)" ]]
check "re-install does not rotate the admin token" $?
VORYNEX="$PREFIX/bin/vorynex"

# ---------------------------------------------------------------------------
step "2b. preflight refuses an install that is not configured yet"
# A fresh install points at an example workload that does not exist. The gate
# must say so rather than let someone point users at this host.
PRE="$OUT/preflight-unconfigured.log"
"$VORYNEX" preflight --env-file "$PREFIX/etc/vorynex/agent.env" \
  --cloud-env "$PREFIX/etc/vorynex/cloud.env" \
  --token-file "$PREFIX/etc/vorynex/cloud-token.env" >"$PRE" 2>&1
PRE_RC=$?
[[ "$PRE_RC" -ne 0 ]]
check "preflight fails on an unconfigured host (exit $PRE_RC)" $?
# It fails fast on the first problem it finds, which here is the policy.
grep -q "FAIL" "$PRE"
check "preflight reports a failure" $?
grep -q "policy" "$PRE"
check "it names the missing policy" $?
grep -q "fix:" "$PRE"
check "every failure comes with a fix" $?

# With a policy in place it must get past that and name the real blocker: the
# example workload in agent.env does not exist on this host.
cat > "$PREFIX/etc/vorynex/policy.yaml" <<'YAML'
version: 1
filesystem:
  read: ["/srv/example"]
network: {}
env: {}
limits: {}
YAML
"$VORYNEX" preflight --env-file "$PREFIX/etc/vorynex/agent.env" >"$OUT/preflight-workload.log" 2>&1
PRE_RC=$?
[[ "$PRE_RC" -ne 0 ]]
check "preflight still fails while the workload is missing (exit $PRE_RC)" $?
grep -q "workload" "$OUT/preflight-workload.log"
check "it names the workload as the problem" $?

# Unit checks. A network-facing unit must not run as root, and a token file on
# disk proves nothing if the unit never passes it to the process — the exact bug
# this check was written after.
UNITS="$WORK/units"; mkdir -p "$UNITS"
cat > "$UNITS/vorynex-cloud.service" <<'UNIT'
[Service]
User=root
ExecStart=/usr/local/bin/vorynex-cloud --addr 127.0.0.1:8787
UNIT
"$VORYNEX" preflight --unit-dir "$UNITS" >"$OUT/preflight-units-bad.log" 2>&1
PRE_RC=$?
[[ "$PRE_RC" -ne 0 ]]
check "preflight fails when the control-plane unit runs as root" $?
grep -q "cloud-user" "$OUT/preflight-units-bad.log"
check "it names the control-plane user as the problem" $?
grep -q "cloud-token-wired" "$OUT/preflight-units-bad.log"
check "it notices the unit never passes --token" $?
cat > "$UNITS/vorynex-cloud.service" <<'UNIT'
[Service]
User=vorynex
Group=vorynex
ExecStart=/usr/local/bin/vorynex-cloud --token ${VORYNEX_CLOUD_TOKEN}
UNIT
"$VORYNEX" preflight --unit-dir "$UNITS" >"$OUT/preflight-units-ok.log" 2>&1
grep -q "runs as vorynex" "$OUT/preflight-units-ok.log"
check "it accepts a non-root unit" $?
grep -q "passes --token" "$OUT/preflight-units-ok.log"
check "it confirms the token reaches the process" $?

# ---------------------------------------------------------------------------
step "2c. install from the release tarball (the artifact a user downloads)"
(cd "$ROOT" && PLATFORMS=linux/amd64 timeout 300 make release) >"$OUT/release.log" 2>&1
check "make release exits 0" $?
TARBALL="$(ls "$ROOT"/dist/vorynex_*_linux_amd64.tar.gz 2>/dev/null | head -1)"
[[ -n "$TARBALL" ]]
check "a linux/amd64 tarball was produced" $?
(cd "$ROOT/dist" && sha256sum -c checksums.txt >/dev/null 2>&1 || sha256sum -c <(grep linux_amd64 checksums.txt) >/dev/null 2>&1)
check "checksums verify" $?
tar -tzf "$TARBALL" > "$OUT/tarball-list.txt" 2>/dev/null
check "tarball listing is readable" $?
# Note: `tar | grep -q` would fail under `set -o pipefail`, because grep exits on
# the first match and SIGPIPEs tar. Read the listing from the file instead.
grep -q 'packaging/systemd/vorynex-agent.service' "$OUT/tarball-list.txt"
check "tarball ships the systemd unit" $?
grep -q 'cloud/dashboard/index.html' "$OUT/tarball-list.txt"
check "tarball ships the dashboard" $?
TARPREFIX="$WORK/tar-prefix"
"$ROOT/install.sh" --from "$TARBALL" --prefix "$TARPREFIX" --no-cloud >"$OUT/install-tarball.log" 2>&1
check "install from tarball exits 0" $?
[[ -x "$TARPREFIX/bin/vorynex" ]]
check "tarball install produced a binary" $?
TARVER="$("$TARPREFIX/bin/vorynex" version --json 2>/dev/null | json 'd["version"]')"
[[ "$TARVER" == "$VERSION_EXPECTED" ]]
check "tarball binary reports the release version ($TARVER)" $?
[[ -f "$TARPREFIX/share/vorynex/live.bpf.o" ]]
if [[ -f "$ROOT/engine/enforce/live/bpf/live.bpf.o" ]]; then
  check "tier 1 object installed alongside the agent" $?
else
  skip_optional "tier 1 object" "not built on this host (clang unavailable)"
fi

# ---------------------------------------------------------------------------
step "3. capability report (honest about this host)"
"$VORYNEX" doctor >"$OUT/doctor.log" 2>&1
check "doctor exits 0" $?
grep -qi "landlock" "$OUT/doctor.log"
check "doctor reports Landlock" $?
ABI="$("$VORYNEX" status --json 2>/dev/null | json 'd["capabilities"]["landlock_abi"]')"
ENFORCE_OK=1
if [[ "${ABI:-0}" -ge 1 ]]; then ENFORCE_OK=0; fi
if [[ "$ENFORCE_OK" != "0" ]]; then
  if [[ "${E2E_ALLOW_SKIP:-0}" == "1" ]]; then
    skip "landlock unavailable (ABI=${ABI:-0}) — enforcement steps" "E2E_ALLOW_SKIP=1"
  else
    check "host can enforce (Landlock ABI >= 1)" 1
    echo "  (set E2E_ALLOW_SKIP=1 to accept a host without Landlock)"
  fi
fi
"$VORYNEX" discover --details >"$OUT/discover.log" 2>&1
check "discover exits 0" $?

# ---------------------------------------------------------------------------
step "4. observe a workload with no enforcement (two sessions)"
APP_DIR="$APPDIR"
mkdir -p "$APP_DIR"
cp -r "$ROOT/tests/proof/targets/vulnerable-node/." "$APP_DIR/"
echo "  workload: $APP_DIR (stable path; /tmp is never granted)"
# strace-based observe records a command that exits on its own, so this stands in
# for the application's startup path: it reads the files the server reads.
OBSERVE_JS='const fs=require("fs"),p=require("path");const d=process.argv[1];
for(const f of fs.readdirSync(d))fs.readFileSync(p.join(d,f));'
for i in 1 2; do
  "$VORYNEX" observe -- node -e "$OBSERVE_JS" "$APP_DIR" >"$OUT/observe-$i.log" 2>&1
  check "observe session $i exits 0" $?
done
TRACES=($(ls -t "$XDG_STATE_HOME/vorynex/traces"/*.jsonl 2>/dev/null | head -2))
[[ "${#TRACES[@]}" -eq 2 && -s "${TRACES[0]}" && -s "${TRACES[1]}" ]]
check "two event traces were recorded" $?
grep -q 'read' "${TRACES[0]}" 2>/dev/null
check "trace contains file-read events" $?

# ---------------------------------------------------------------------------
step "5. generate a policy from the observation"
POLICY="$WORK/policy.yaml"
"$VORYNEX" policy generate --from "${TRACES[0]}" --from "${TRACES[1]}" \
  --min-sessions 2 --out "$POLICY" >"$OUT/policy.log" 2>&1
check "policy generate exits 0" $?
[[ -s "$POLICY" ]]
check "policy file written" $?
grep -q "filesystem:" "$POLICY" 2>/dev/null
check "policy has a filesystem section" $?
# The policy must actually grant the workload's own tree, or the first protected
# launch cannot even read its entry point. (A capability observed once is not
# promoted, which is why this observes two sessions.)
grep -q "$APP_DIR" "$POLICY" 2>/dev/null
check "policy grants the application's own directory" $?
"$VORYNEX" blast-radius --policy "$POLICY" >"$OUT/blast.log" 2>&1
check "generated policy is loadable (blast-radius)" $?
"$VORYNEX" live plan --policy "$POLICY" >"$OUT/liveplan.log" 2>&1
check "generated policy has a tier-1 plan" $?

# Now that a policy exists, the installed agent can be pointed at the workload
# and the same gate must pass. This is the pair that makes preflight meaningful:
# it failed before configuration and passes after.
cat > "$PREFIX/etc/vorynex/agent.env" <<EOF
VORYNEX_NAME=e2e
VORYNEX_POLICY=$POLICY
VORYNEX_HEALTH=http://127.0.0.1:3000/health
VORYNEX_COMMAND=$(command -v node) $APP_DIR/server.js
EOF
"$VORYNEX" preflight --env-file "$PREFIX/etc/vorynex/agent.env" \
  --cloud-env "$PREFIX/etc/vorynex/cloud.env" \
  --token-file "$PREFIX/etc/vorynex/cloud-token.env" --json >"$OUT/preflight.json" 2>&1
PRE_RC=$?
[[ "$PRE_RC" -eq 0 ]]
check "preflight passes once the workload and policy are configured" $?
python3 -c "
import json,sys
d=json.load(open('$OUT/preflight.json'))
sys.exit(0 if d['failed']==0 and d['verdict']=='ready to deploy' else 1)" 2>/dev/null
check "preflight --json reports zero failures and a verdict" $?

# ---------------------------------------------------------------------------
step "6. control — the attack must land when nothing enforces"
MARKER="$WORK/attack-marker"
PORT_APP="$(free_port)"
rm -f "$MARKER"
( cd "$APP_DIR" && PORT="$PORT_APP" NODE_ENV=test node server.js >"$OUT/app-control.log" 2>&1 ) &
APP_PID=$!
wait_http "http://127.0.0.1:$PORT_APP/health" 60
check "workload starts unprotected" $?
ATTACK="/api/ping?host=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "127.0.0.1;touch $MARKER")"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_APP$ATTACK")"
[[ -f "$MARKER" ]]
CONTROL_LANDED=$?
check "exec injection lands unprotected (http $CODE)" $CONTROL_LANDED
if [[ "$CONTROL_LANDED" != "0" ]]; then
  echo "  the attack does not work here; the protected result below would be meaningless" >&2
fi
kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null; APP_PID=""

# ---------------------------------------------------------------------------
step "7. protected — run the same workload under the generated policy"
rm -f "$MARKER"
PORT_APP="$(free_port)"
( PORT="$PORT_APP" NODE_ENV=test "$VORYNEX" run --policy "$POLICY" \
    --health "http://127.0.0.1:$PORT_APP/health" \
    --health-interval 500ms --health-timeout 20s --health-consecutive 2 \
    -- node "$APP_DIR/server.js" >"$OUT/run-protected.log" 2>&1 ) &
APP_PID=$!
wait_http "http://127.0.0.1:$PORT_APP/health" 60
check "supervisor reports the workload healthy" $?
MODE="$("$VORYNEX" status --json 2>/dev/null | json 'd["mode"]')"
[[ "$MODE" == "protect" ]]
check "status reports mode=protect (got '$MODE')" $?
DIGEST="$("$VORYNEX" status --json 2>/dev/null | json 'd.get("policy",{}).get("sha256","")')"
[[ -n "$DIGEST" ]]
check "status records the active policy digest" $?
# the same attack, byte for byte
CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_APP$ATTACK")"
[[ ! -f "$MARKER" ]]
check "exec injection is contained (http $CODE, no marker)" $?
# benign work must keep working after a blocked attack
BODY="$(curl -s "http://127.0.0.1:$PORT_APP/api/echo?x=1")"
echo "$BODY" | grep -q '"ok":true'
check "benign request still served after a blocked attack" $?
READ="$(curl -s "http://127.0.0.1:$PORT_APP/api/read?file=server.js")"
echo "$READ" | grep -q createServer
check "allowed file read still works (policy grants the app tree)" $?
kill -- "-$APP_PID" 2>/dev/null || kill "$APP_PID" 2>/dev/null || true
wait "$APP_PID" 2>/dev/null || true
APP_PID=""

# ---------------------------------------------------------------------------
step "8. rollback — a workload that never becomes healthy must revert"
MODE_BEFORE="$("$VORYNEX" status --json 2>/dev/null | json 'd["mode"]')"
( "$VORYNEX" run --policy "$POLICY" --health "http://127.0.0.1:1/never" \
    --health-interval 200ms --health-timeout 2s --health-consecutive 1 \
    -- node "$APP_DIR/server.js" >"$OUT/run-rollback.log" 2>&1 ) &
RB_PID=$!
RB_CODE=0; wait "$RB_PID" || RB_CODE=$?
[[ "$RB_CODE" -ne 0 ]]
check "run exits non-zero when the workload is never healthy" $?
MODE_AFTER="$("$VORYNEX" status --json 2>/dev/null | json 'd["mode"]')"
[[ "$MODE_AFTER" != "protect" ]]
check "mode rolled back to '$MODE_AFTER' (was '$MODE_BEFORE')" $?
grep -qi "roll" "$OUT/run-rollback.log"
check "rollback is reported to the operator" $?

# ---------------------------------------------------------------------------
step "9. reversible — protect --off returns the recorded posture to observe"
# Establish protect again first: a healthy supervised run records mode=protect.
PORT_APP="$(free_port)"
( PORT="$PORT_APP" NODE_ENV=test "$VORYNEX" run --policy "$POLICY" \
    --health "http://127.0.0.1:$PORT_APP/health" \
    --health-interval 500ms --health-timeout 20s --health-consecutive 2 \
    -- node "$APP_DIR/server.js" >"$OUT/run-off.log" 2>&1 ) &
APP_PID=$!
wait_http "http://127.0.0.1:$PORT_APP/health" 60
check "protected run becomes healthy again" $?
MODE="$("$VORYNEX" status --json 2>/dev/null | json 'd["mode"]')"
[[ "$MODE" == "protect" ]]
check "mode is protect before turning it off (got '$MODE')" $?
"$VORYNEX" protect --off >"$OUT/protect-off.log" 2>&1
check "protect --off exits 0" $?
MODE="$("$VORYNEX" status --json 2>/dev/null | json 'd["mode"]')"
[[ "$MODE" != "protect" ]]
check "recorded posture is no longer protect (got '$MODE')" $?
# The running workload keeps the boundary it was launched with; the change
# applies to the next launch. The CLI says so, and that is worth asserting.
grep -qi "restart the workload" "$OUT/protect-off.log"
check "protect --off warns the running workload keeps its boundary" $?
kill -- "-$APP_PID" 2>/dev/null || kill "$APP_PID" 2>/dev/null || true
wait "$APP_PID" 2>/dev/null || true
APP_PID=""
"$VORYNEX" status --json >"$OUT/status.json" 2>&1
python3 -c "import json;json.load(open('$OUT/status.json'))" 2>/dev/null
check "status --json is valid JSON" $?

# ---------------------------------------------------------------------------
step "10. control plane — auth, dashboard, ingestion"
PORT_CLOUD="$(free_port)"
TOKEN="e2e-token-$RANDOM"
STORE="$WORK/cloud-events.jsonl"
( "$BIN/vorynex-cloud" --addr "127.0.0.1:$PORT_CLOUD" --token "$TOKEN" \
    --store "$STORE" --dashboard "$ROOT/cloud/dashboard" >"$OUT/cloud.log" 2>&1 ) &
CLOUD_PID=$!
wait_http "http://127.0.0.1:$PORT_CLOUD/" 60
check "control plane serves the dashboard" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_CLOUD/v1/hosts")"
[[ "$CODE" == "401" ]]
check "unauthenticated API call is rejected (401, got $CODE)" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT_CLOUD/v1/hosts")"
[[ "$CODE" == "200" ]]
check "authenticated API call succeeds (200, got $CODE)" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong-token" "http://127.0.0.1:$PORT_CLOUD/v1/hosts")"
[[ "$CODE" == "401" ]]
check "a wrong token is rejected" $?
DASH="$(curl -s "http://127.0.0.1:$PORT_CLOUD/")"
grep -qi "<html\|<!doctype" <<< "$DASH"
check "dashboard HTML is served" $?

"$VORYNEX" telemetry export --endpoint "http://127.0.0.1:$PORT_CLOUD" --token "$TOKEN" --once \
  >"$OUT/telemetry.log" 2>&1
check "agent exports telemetry to the control plane" $?
HOSTS="$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT_CLOUD/v1/hosts")"
COUNT="$(echo "$HOSTS" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("hosts",[])))' 2>/dev/null)"
[[ "${COUNT:-0}" -ge 1 ]]
check "control plane has the host after ingestion (count=${COUNT:-0})" $?
kill "$CLOUD_PID" 2>/dev/null; wait "$CLOUD_PID" 2>/dev/null; CLOUD_PID=""

# ---------------------------------------------------------------------------
step "11. container image (optional: needs a Docker daemon)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if timeout 600 docker build -f "$ROOT/cloud/Dockerfile" -t vorynex-cloud:e2e \
       --build-arg "VERSION=$VERSION_EXPECTED" "$ROOT" >"$OUT/docker-build.log" 2>&1; then
    check "control-plane image builds" 0
  else
    check "control-plane image builds" 1
  fi
  CV="$(timeout 60 docker run --rm vorynex-cloud:e2e --version 2>/dev/null | head -1)"
  [[ "$CV" == "vorynex-cloud $VERSION_EXPECTED" ]]
  check "image runs --version and exits (got '$CV')" $?
  docker rm -f vorynex-cp-e2e >/dev/null 2>&1
  if timeout 60 docker run -d --name vorynex-cp-e2e -e VORYNEX_CLOUD_TOKEN=img-token \
       -p 127.0.0.1:8798:8787 vorynex-cloud:e2e >/dev/null 2>&1; then
    for _ in $(seq 1 40); do
      curl -sf http://127.0.0.1:8798/ >/dev/null 2>&1 && break
      sleep 0.25
    done
    CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8798/v1/hosts)"
    [[ "$CODE" == "401" ]]
    check "containerised control plane requires the token (401, got $CODE)" $?
    CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer img-token' http://127.0.0.1:8798/v1/hosts)"
    [[ "$CODE" == "200" ]]
    check "containerised control plane serves authenticated requests" $?
    DASH="$(curl -s http://127.0.0.1:8798/)"
    grep -qi "<html\|<!doctype" <<< "$DASH"
    check "containerised control plane serves the dashboard" $?
    CLOGS="$(docker logs vorynex-cp-e2e 2>&1)"
    grep -qi "listening" <<< "$CLOGS"
    check "container logs show it listening" $?
    docker rm -f vorynex-cp-e2e >/dev/null 2>&1
  else
    check "containerised control plane starts" 1
  fi
else
  skip_optional "container image" "no usable Docker daemon on this host"
fi

# ---------------------------------------------------------------------------
step "12. teardown"
"$ROOT/install.sh" --prefix "$PREFIX" --uninstall >"$OUT/uninstall.log" 2>&1
check "uninstall exits 0" $?
[[ ! -x "$PREFIX/bin/vorynex" ]]
check "binary removed by uninstall" $?
[[ -f "$PREFIX/etc/vorynex/cloud-token.env" ]]
check "config kept by uninstall (documented)" $?

# ---------------------------------------------------------------------------
echo
echo "=================================================="
printf 'e2e: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
if [[ "${#OPTIONAL_SKIPPED[@]}" -gt 0 ]]; then
  printf 'optional (not available on this host): %s\n' "$(IFS=', '; echo "${OPTIONAL_SKIPPED[*]}")"
fi
if [[ "$FAIL" -gt 0 ]]; then
  printf 'failed: %s\n' "$(IFS=', '; echo "${FAILED_NAMES[*]}")"
fi
echo "evidence: $OUT"
{
  echo "passed=$PASS failed=$FAIL skipped=$SKIP"
  [[ "${#OPTIONAL_SKIPPED[@]}" -gt 0 ]] && printf 'optional_skipped=%s\n' "$(IFS=', '; echo "${OPTIONAL_SKIPPED[*]}")"
  [[ "$FAIL" -gt 0 ]] && printf 'failed_steps=%s\n' "$(IFS=', '; echo "${FAILED_NAMES[*]}")"
} > "$OUT/result.txt"

if [[ "$FAIL" -gt 0 ]]; then exit 1; fi
exit 0
