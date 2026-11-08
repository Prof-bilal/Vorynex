#!/usr/bin/env bash
# P3 — containment proof against a real third-party application.
#
# Target: snoopysecurity/dvws-node (GPL-3.0) — a maintained Node app with real
# sinks: an authenticated `exec()` at /api/v2/sysinfo/:command and an
# unauthenticated XML-RPC fetch at /xmlrpc.
#
# Arms: bare (control), OWASP CRS (request layer), Vorynex Tier 1 (live attach
# to the running container's cgroup — the app is never restarted).
#
# Needs Docker and ~2.5 GB of images. Not part of `make proof` (which is the
# hermetic CI arm); run it explicitly with `make proof-real`.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DVWS_REPO="${DVWS_REPO:-https://github.com/snoopysecurity/dvws-node.git}"
APP_PORT="${APP_PORT:-3280}"

WORK="$(mktemp -d /tmp/vorynex-proof-real.XXXXXX)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${PROOF_OUT:-$ROOT/tests/proof/evidence-real/$STAMP}"
DVWS="${DVWS_DIR:-$WORK/dvws-node}"

APP_PID=""; WAF_PID=""; PROXY_PID=""
cleanup() {
  [[ -n "$WAF_PID" ]] && kill "$WAF_PID" 2>/dev/null || true
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  if [[ "${KEEP:-0}" != "1" && -f "$DVWS/docker-compose.yml" ]]; then
    (cd "$DVWS" && docker compose -f docker-compose.yml -f docker-compose.proof.yml down -v >/dev/null 2>&1)
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$OUT"
echo "== P3: real application (DVWS-node) =="

# --- target ------------------------------------------------------------------
if [[ ! -d "$DVWS" ]]; then
  git clone --depth 1 "$DVWS_REPO" "$DVWS" >/dev/null 2>&1 || { echo "clone failed"; exit 1; }
fi
cp "$HERE/docker-compose.proof.yml" "$DVWS/" || exit 1
cp "$HERE/collector.js" "$DVWS/" || exit 1
mkdir -p "$DVWS/shared"
: > "$DVWS/shared/hits.log"

echo "-- starting the stack (builds the app image on first run) --"
(cd "$DVWS" && docker compose -f docker-compose.yml -f docker-compose.proof.yml up -d --build) || exit 1

for _ in $(seq 1 120); do
  curl -sf "http://127.0.0.1:$APP_PORT/api/v1/info" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$APP_PORT/api/v1/info" >/dev/null 2>&1 || {
  echo "the application did not come up on :$APP_PORT" >&2; exit 1; }
echo "-- app healthy on 127.0.0.1:$APP_PORT --"

COLLECTOR_IP=""
for _ in $(seq 1 20); do
  COLLECTOR_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$(docker ps --filter name=collector --format '{{.Names}}' | head -1)" 2>/dev/null)"
  [[ -n "$COLLECTOR_IP" ]] && break
  sleep 0.5
done
echo "-- collector at ${COLLECTOR_IP:-unknown}:3290 --"
if [[ ! "$COLLECTOR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "the collector container is not running; SSRF cannot be measured. Logs:" >&2
  docker logs "$(docker ps -a --filter name=collector --format '{{.Names}}' | head -1)" 2>&1 | tail -10 >&2
  exit 1
fi

# Tier 1 needs root. Prefer passwordless sudo, otherwise use an askpass helper so
# the harness can still run unprivileged (node/go stay on the user's PATH).
SUDO=""
if sudo -n true 2>/dev/null; then
  SUDO="sudo"
elif [[ -n "${PROOF_SUDO_PASSWORD:-}" ]]; then
  ASKPASS="$WORK/askpass.sh"
  printf '#!/bin/sh\nprintf "%%s\\n" "$PROOF_SUDO_PASSWORD"\n' > "$ASKPASS"
  chmod 700 "$ASKPASS"
  export SUDO_ASKPASS="$ASKPASS"
  SUDO="sudo -A"
fi

export SHARED="$DVWS/shared"
export COLLECTOR_URL="http://collector:3290/probe"
# Must match the decoy set in docker-compose.proof.yml.
export SSTI_CANARY="SSTI-CANARY-NOT-REAL-7f3a"

reset_effects() { rm -f "$DVWS/shared/rce-marker"; : > "$DVWS/shared/hits.log"; }

# --- arm A: bare -------------------------------------------------------------
echo
echo "== arm A — bare (attacks must land) =="
reset_effects
node "$HERE/attacker-real.js" "http://127.0.0.1:$APP_PORT" "$OUT/arm-a.jsonl" | tee "$OUT/arm-a.log"

# --- arm B: OWASP CRS --------------------------------------------------------
echo
echo "== arm B — OWASP CRS (request layer) =="
WAF_BIN="$WORK/proof-waf"
(cd "$ROOT/tests/proof/waf" && go build -o "$WAF_BIN" .) || exit 1
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}
PORT_W="$(free_port)"
# A real deployment configures body processors. Without them a WAF blocks a
# JSON or XML request with a body-parsing error, which measures the WAF's
# configuration, not its detection. Recorded as a separate arm.
EXTRA_CONF="$WORK/crs-extra.conf"
cat > "$EXTRA_CONF" <<'CONF'
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:900004,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(text|application)/xml" "id:900005,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
CONF

run_waf_arm() { # $1=label, $2=paranoia, $3=extra-config ("" for stock)
  local label=$1 pl=$2 extra=$3
  echo "-- CRS $label (paranoia $pl) --"
  reset_effects
  # shellcheck disable=SC2086
  "$WAF_BIN" --listen "127.0.0.1:$PORT_W" --upstream "http://127.0.0.1:$APP_PORT" \
    --mode blocking --paranoia "$pl" ${extra:+--extra "$extra"} \
    --audit "$OUT/waf-$label-audit.jsonl" >"$WORK/waf-$label.log" 2>&1 &
  WAF_PID=$!
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$PORT_W/api/v1/info" >/dev/null 2>&1 && break
    sleep 0.1
  done
  node "$HERE/attacker-real.js" "http://127.0.0.1:$PORT_W" "$OUT/arm-b-$label.jsonl" | tee "$OUT/arm-b-$label.log"
  kill "$WAF_PID" 2>/dev/null || true; wait "$WAF_PID" 2>/dev/null || true; WAF_PID=""
}

run_waf_arm "pl1-stock" 1 ""
run_waf_arm "pl2-stock" 2 ""
run_waf_arm "pl1-tuned" 1 "$EXTRA_CONF"

# --- arm C: Vorynex Tier 1 (live attach) -------------------------------------
echo
echo "== arm C — Vorynex Tier 1 (live attach to the running container) =="
if [[ -n "$SUDO" ]]; then
  VORYNEX="$WORK/vorynex"
  (cd "$ROOT" && go build -o "$VORYNEX" ./cmd/vorynex) || exit 1
  # The Tier 1 object is gitignored and built locally, so a fresh checkout does
  # not have it. Build it here rather than assuming — otherwise the attach fails
  # and the arm silently reports nothing.
  if [[ ! -f "$ROOT/engine/enforce/live/bpf/live.bpf.o" ]]; then
    echo "-- building the tier 1 BPF object --"
    (cd "$ROOT" && make bpf) >"$OUT/bpf.log" 2>&1 \
      || echo "warning: could not build live.bpf.o (clang missing?) — see $OUT/bpf.log" >&2
  fi
  WEB_CID="$(docker ps --filter name=web --format '{{.Names}}' | head -1)"
  WEB_PID="$(docker inspect -f '{{.State.Pid}}' "$WEB_CID")"
  CGROUP=""; CGROUP_PATH=""
  for _ in $(seq 1 20); do
    CGROUP_PATH="$(grep -o '0::.*' "/proc/$WEB_PID/cgroup" 2>/dev/null | cut -d: -f3)"
    if [[ -n "$CGROUP_PATH" ]]; then
      CGROUP="$(stat -c '%i' "/sys/fs/cgroup$CGROUP_PATH" 2>/dev/null)"
      [[ -n "$CGROUP" ]] && break
    fi
    sleep 0.5
  done
  # Never arm nothing and then report a result: an unarmed "containment" column
  # is worse than no column.
  if [[ -z "$CGROUP" ]]; then
    echo "-- ERROR: could not resolve the container cgroup; arm C not run --" >&2
    : > "$OUT/arm-c.jsonl"
  else
  echo "-- container pid $WEB_PID cgroup $CGROUP_PATH (id $CGROUP) --"
  # The inode must be resolved through the container's mount namespace: the
  # image's /bin/sh is an overlay file (a different inode from the host's), and
  # the hook matches the inode the container actually executes.
  SHELL_IN_CONTAINER="/proc/$WEB_PID/root/bin/sh"
  reset_effects
  # shellcheck disable=SC2086
  $SUDO "$VORYNEX" live attach \
    --object "$ROOT/engine/enforce/live/bpf/live.bpf.o" \
    --cgroup "$CGROUP" \
    --deny-exec "$SHELL_IN_CONTAINER" \
    --block-connect "$COLLECTOR_IP:3290" \
    --seconds 40 >"$OUT/tier1.log" 2>&1 &
  APP_PID=$!
  sleep 4
  cat "$OUT/tier1.log"

  # Assert every hook is actually in place by reading the attach's own log. An
  # attach that armed nothing (empty cgroup), or that armed and then returned
  # early because a later flag failed (running the deferred Close), leaves the
  # workload unprotected — and that looks exactly like a containment failure.
  armed_ok=1
  for want in "armed for cgroup" "deny exec" "block connect to"; do
    grep -q "$want" "$OUT/tier1.log" || { echo "-- MISSING from tier1.log: $want --" >&2; armed_ok=0; }
  done
  kill -0 "$APP_PID" 2>/dev/null || { echo "-- the attach exited before the attacks ran --" >&2; armed_ok=0; }

  if [[ "$armed_ok" != "1" ]]; then
    echo "-- ERROR: tier 1 did not arm fully; arm C is not a measurement --" >&2
    : > "$OUT/arm-c.jsonl"
  else
    node "$HERE/attacker-real.js" "http://127.0.0.1:$APP_PORT" "$OUT/arm-c.jsonl" | tee "$OUT/arm-c.log"
  fi
  # Let the attach reach its deadline and detach itself rather than killing it,
  # so the hooks are never left armed on a live workload.
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
  fi
else
  echo "-- SKIPPED: arming Tier 1 needs root. Re-run with passwordless sudo, or" >&2
  echo "   set PROOF_SUDO_PASSWORD, to produce the containment column." >&2
  : > "$OUT/arm-c.jsonl"
fi

# --- verdict -----------------------------------------------------------------
python3 - "$OUT" <<'PY' | tee "$OUT/evidence.md"
import json, pathlib, sys

out = pathlib.Path(sys.argv[1])
def load(name):
    p = out / name
    if not p.exists(): return {}
    return {r["scenario"]: r for r in (json.loads(l) for l in p.read_text().splitlines() if l.strip())}

a = load("arm-a.jsonl")
b1, b2 = load("arm-b-pl1-stock.jsonl"), load("arm-b-pl2-stock.jsonl")
bt = load("arm-b-pl1-tuned.jsonl")
c = load("arm-c.jsonl")

def waf_state(e):
    if not e: return "n/a"
    if e.get("waf") == "blocked" or e.get("status") == 403: return "blocked"
    return "landed" if e.get("landed") else "passed"

rows, attacks, landed, contained, void = [], 0, 0, 0, 0
for name, e in a.items():
    attack = not name.startswith("benign_")
    row = {"scenario": name, "kind": "attack" if attack else "benign",
           "bare": bool(e.get("landed")),
           "crs_pl1": waf_state(b1.get(name)), "crs_pl2": waf_state(b2.get(name)),
           "crs_tuned": waf_state(bt.get(name)),
           "vorynex": (bool(c.get(name, {}).get("landed")) if c else None)}
    if attack:
        attacks += 1
        if row["bare"]: landed += 1
        else: void += 1
        if c and not row["vorynex"]: contained += 1
    rows.append(row)

login_ok = all(r["bare"] for r in rows if r["scenario"].startswith("benign_"))
lines = ["# P3 — real application (DVWS-node)", "",
         f"Attacks {attacks}: landed bare {landed}, VOID {void}. Controls on bare: {'ok' if login_ok else 'BROKEN'}.",
         (f"Vorynex Tier 1 contained {contained}/{attacks}."
          if c else "Vorynex Tier 1: not armed (no containment claim)."),
         "",
         "'stock' is CRS with no body processors; 'tuned' adds the JSON/XML body",
         "processors a real deployment configures.",
         "",
         "| Scenario | Bare | CRS PL1 stock | CRS PL2 stock | CRS PL1 tuned | Vorynex Tier 1 |",
         "|---|---|---|---|---|---|"]
for r in rows:
    v = "n/a" if r["vorynex"] is None else ("landed" if r["vorynex"] else "blocked")
    lines.append(f"| {r['scenario']} | {'landed' if r['bare'] else 'blocked'} | {r['crs_pl1']} | "
                 f"{r['crs_pl2']} | {r['crs_tuned']} | {v} |")
(out / "summary.json").write_text(json.dumps(rows, indent=2) + "\n")
print("\n".join(lines))
PY

echo
echo "evidence: $OUT"
