#!/usr/bin/env bash
# What does a tight policy cost?
#
# Containment without a false-positive number is meaningless: a policy that
# denies everything scores 100%. This runs the *same* application under two
# policies and reports both sides of the trade:
#
#   no-exec    the policy the generator produces for a web service (no shell)
#   allow-sh   the same, plus process.exec.allow: ["/bin/sh"], because the app
#              has a legitimate feature that spawns a command
#
# For each: how many legitimate operations the sandbox denied (FP), and whether
# the command-injection attack is still contained.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/vorynex-benign.XXXXXX)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${PROOF_OUT:-$ROOT/tests/proof/evidence-benign/$STAMP}"

APP_DIR="$WORK/app"
SCRATCH="$WORK/scratch"
MARKER="$WORK/injection-marker"
STOLEN="$SCRATCH/in-grant-stolen.js"
APP_PID=""
cleanup() { [[ -n "$APP_PID" ]] && kill "$APP_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$OUT" "$APP_DIR" "$SCRATCH"
cp -r "$HERE/../targets/vulnerable-node/." "$APP_DIR/"

echo "== false positives vs containment =="
(cd "$ROOT" && go build -o "$WORK/vorynex" ./cmd/vorynex) || exit 1

write_policy() { # $1=path, $2=extra process.exec block ("" for none)
  cat > "$1" <<EOF
filesystem:
  read:
    - "$APP_DIR"
  write:
    - "$SCRATCH"
network:
  allow: []
env:
  allow:
    - "PATH"
    - "NODE_ENV"
    - "PORT"
    - "HOST"
    - "HOME"
    - "TMPDIR"
limits:
  memory_mb: 512
  timeout_s: 60
$2
EOF
}

run_variant() { # $1=label, $2=policy, $3=human description
  local label=$1 policy=$2 desc=$3
  echo
  echo "-- $label: $desc --"
  rm -f "$MARKER" "$STOLEN"
  free_port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
  PORT="$free_port" NODE_ENV=test "$WORK/vorynex" exec --policy "$policy" -- \
    node "$APP_DIR/server.js" >"$WORK/app-$label.log" 2>&1 &
  APP_PID=$!
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$free_port/health" >/dev/null 2>&1 && break
    sleep 0.1
  done
  if ! curl -sf "http://127.0.0.1:$free_port/health" >/dev/null 2>&1; then
    echo "  the workload did not start under this policy (that is itself a false positive)"
    echo "{\"label\":\"$label\",\"started\":false}" >> "$OUT/rows.jsonl"
    kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null; APP_PID=""
    return
  fi

  SCRATCH="$SCRATCH" node "$HERE/benign.js" "http://127.0.0.1:$free_port" "$OUT/benign-$label.json" \
    | tee "$OUT/benign-$label.log"

  # The same injection the proof harness uses, byte for byte. Its effect (a write
  # outside the granted tree) is contained whatever the exec policy says.
  local payload
  payload="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "127.0.0.1; touch $MARKER")"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$free_port/api/ping?host=$payload")"
  if [[ -f "$MARKER" ]]; then
    echo "  injection (write outside the grants): LANDED"
  else
    echo "  injection (write outside the grants): contained"
  fi

  # An injection that acts *within* the granted powers: read a file the policy
  # grants and write into the directory it grants. This is what an exec grant
  # actually costs — with no shell it cannot happen, with a shell it can.
  local payload2 in_grant="no"
  payload2="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' \
    "127.0.0.1; cp $APP_DIR/server.js $STOLEN")"
  curl -s -o "$OUT/in-grant-$label.body" "http://127.0.0.1:$free_port/api/ping?host=$payload2"
  if [[ -f "$STOLEN" ]]; then
    in_grant="yes"
    echo "  injection (acting within the grants): LANDED — copied the app's own file into the writable dir"
  else
    echo "  injection (acting within the grants): contained"
  fi
  rm -f "$STOLEN"

  "$WORK/vorynex" blast-radius --policy "$policy" >"$OUT/blast-$label.log" 2>&1
  python3 - "$OUT/benign-$label.json" "$label" "$desc" "$([[ -f "$MARKER" ]] && echo yes || echo no)" \
    "$code" "$in_grant" >> "$OUT/rows.jsonl" <<'PY'
import json, sys
benign, label, desc, landed, code, in_grant = sys.argv[1:7]
b = json.load(open(benign))
print(json.dumps({
    "label": label, "description": desc, "started": True,
    "legit_ops": b["total_ops"], "legit_failed": b["failed_ops"],
    "sandbox_denials": b["sandbox_denials"], "fp_rate_pct": b["fp_rate"],
    "injection_landed": landed == "yes", "injection_http": code,
    "in_grant_landed": in_grant == "yes",
    "ops": [{"name": o["name"], "count": o["count"], "denied": o["denied"],
             "failures": o["failures"]} for o in b["ops"]],
}))
PY
  kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null; APP_PID=""
}

write_policy "$WORK/policy-no-exec.yaml" ""
write_policy "$WORK/policy-allow-sh.yaml" "process:
  exec:
    allow:
      - \"/bin/sh\""

run_variant "no-exec"  "$WORK/policy-no-exec.yaml"  "the generated policy: no shell allowed"
run_variant "allow-sh" "$WORK/policy-allow-sh.yaml" "plus /bin/sh, because the app has a feature that spawns a command"

python3 - "$OUT" <<'PY' | tee "$OUT/summary.md"
import json, pathlib, sys

out = pathlib.Path(sys.argv[1])
rows = [json.loads(l) for l in (out / "rows.jsonl").read_text().splitlines() if l.strip()]
lines = ["# False positives vs containment", "",
         "Same application, two policies, measured in one run. `FP` counts legitimate",
         "operations the sandbox denied (EACCES/EPERM) — an app failing for its own",
         "reasons is not counted.", "",
         "| Policy | Legit ops ok | Denied (FP) | FP rate | Injection outside grants | Injection inside grants |",
         "|---|---|---|---|---|---|"]
for r in rows:
    if not r.get("started"):
        lines.append(f"| {r['label']} | — | — | — | the workload could not start under this policy | — |")
        continue
    ok = r["legit_ops"] - r["legit_failed"]
    lines.append(
        f"| {r['label']} | {ok}/{r['legit_ops']} | {r['sandbox_denials']} | "
        f"{r['fp_rate_pct']}% | {'**LANDED**' if r['injection_landed'] else 'contained'} | "
        f"{'**LANDED**' if r.get('in_grant_landed') else 'contained'} |")
lines += ["", "Per-operation detail:"]
for r in rows:
    if not r.get("started"):
        continue
    for o in r["ops"]:
        flag = "denied" if o["denied"] else ("failed" if o["failures"] else "ok")
        lines.append(f"  {r['label']:9} {o['name']:18} {o['count'] - o['failures']}/{o['count']}  {flag}")
(out / "summary.json").write_text(json.dumps(rows, indent=2) + "\n")
print("\n".join(lines))
PY

echo
echo "evidence: $OUT"
