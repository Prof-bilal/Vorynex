#!/usr/bin/env bash
# P4 — what does enforcement cost?
#
# Three arms serving the same endpoint, measured in interleaved rounds so that
# drift (thermal, scheduler, page cache) affects all of them equally:
#
#   bare     the workload alone
#   vorynex  the same workload under `vorynex exec` (Tier 0, Landlock)
#   crs      the workload behind the OWASP CRS proxy — enforcement in the
#            request path — with the proxy's own CPU counted in
#
# Latency is measured open-loop at a fixed rate (see loadgen.js) so a stall
# cannot be hidden by the generator waiting for it. CPU and RSS come from /proc
# of every process that arm adds.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/vorynex-bench.XXXXXX)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${PROOF_OUT:-$ROOT/tests/proof/evidence-bench/$STAMP}"

ROUNDS="${ROUNDS:-5}"
RATE="${RATE:-200}"
SECONDS_PER_ARM="${SECONDS_PER_ARM:-6}"
APP_PORT="${APP_PORT:-3310}"
WAF_PORT="${WAF_PORT:-3311}"
CLK_TCK="$(getconf CLK_TCK)"

APP_PID=""; WAF_PID=""
cleanup() {
  [[ -n "$APP_PID" ]] && kill "$APP_PID" 2>/dev/null || true
  [[ -n "$WAF_PID" ]] && kill "$WAF_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$OUT"
echo "== P4: enforcement overhead =="
echo "rounds=$ROUNDS rate=${RATE}rps duration=${SECONDS_PER_ARM}s per arm"

(cd "$HERE/../waf" && go build -o "$WORK/waf" .) || exit 1
(cd "$ROOT" && go build -o "$WORK/vorynex" ./cmd/vorynex) || exit 1

APP_DIR="$WORK/app"
mkdir -p "$APP_DIR" "$WORK/out"
cp -r "$HERE/../targets/vulnerable-node/." "$APP_DIR/"
POLICY="$WORK/protect.yaml"
sed -e "s|__APP__|$APP_DIR|g" -e "s|__OUT__|$WORK/out|g" \
  "$HERE/../policy/protect.yaml.template" > "$POLICY"

wait_healthy() { # $1=port
  for _ in $(seq 1 200); do
    curl -sf "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
    sleep 0.05
  done
  return 1
}

cpu_jiffies() { awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || echo 0; }
rss_kb() { awk '/VmRSS/ { print $2 }' "/proc/$1/status" 2>/dev/null || echo 0; }
peak_kb() { awk '/VmHWM/ { print $2 }' "/proc/$1/status" 2>/dev/null || echo 0; }
sum_of() { # $1 = function, rest = pids
  local fn=$1; shift
  local total=0
  for p in "$@"; do total=$(( total + $("$fn" "$p") )); done
  echo "$total"
}

STARTUP_MS=""
start_bare() { # $1=port — sets STARTUP_MS and APP_PID
  PORT=$1 NODE_ENV=test node "$APP_DIR/server.js" >"$WORK/app-$1.log" 2>&1 &
  APP_PID=$!
  local t0; t0=$(date +%s%N)
  wait_healthy "$1" || { echo "workload failed to start" >&2; cat "$WORK/app-$1.log" >&2; exit 1; }
  STARTUP_MS=$(( ($(date +%s%N) - t0) / 1000000 ))
}

start_protected() { # $1=port — `vorynex exec` replaces itself with node, same pid
  PORT=$1 NODE_ENV=test "$WORK/vorynex" exec --policy "$POLICY" -- node "$APP_DIR/server.js" \
    >"$WORK/app-$1.log" 2>&1 &
  APP_PID=$!
  local t0; t0=$(date +%s%N)
  wait_healthy "$1" || { echo "protected workload failed to start" >&2; cat "$WORK/app-$1.log" >&2; exit 1; }
  STARTUP_MS=$(( ($(date +%s%N) - t0) / 1000000 ))
}

stop_app() { [[ -n "$APP_PID" ]] && kill "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null; APP_PID=""; }
stop_waf() { [[ -n "$WAF_PID" ]] && kill "$WAF_PID" 2>/dev/null; wait "$WAF_PID" 2>/dev/null; WAF_PID=""; }

measure() { # $1=label $2=url, then every pid the arm adds
  local label=$1 url=$2; shift 2
  local c0 c1
  c0="$(sum_of cpu_jiffies "$@")"
  node "$HERE/loadgen.js" --url "$url" --rate "$RATE" --seconds "$SECONDS_PER_ARM" \
    --out "$OUT/$label-r$ROUND.json" >/dev/null || { echo "loadgen failed for $label" >&2; return 1; }
  c1="$(sum_of cpu_jiffies "$@")"
  python3 - "$OUT/$label-r$ROUND.json" "$label" "$ROUND" "$c0" "$c1" "$CLK_TCK" \
    "$(sum_of rss_kb "$@")" "$(sum_of peak_kb "$@")" >> "$OUT/rows.jsonl" <<'PY'
import json, sys
path, label, rnd, c0, c1, hz, rss, peak = sys.argv[1:9]
d = json.load(open(path))
cpu_ms = max(0, int(c1) - int(c0)) * (1000.0 / float(hz))
d.update({
    "arm": label, "round": int(rnd),
    "cpu_ms_total": round(cpu_ms, 1),
    "cpu_ms_per_req": round(cpu_ms / d["ok"], 4) if d["ok"] else None,
    "rss_mb": round(int(rss) / 1024, 1),
    "peak_rss_mb": round(int(peak) / 1024, 1),
})
print(json.dumps(d))
PY
}

echo "-- warmup (JIT, page cache; not reported) --"
ROUND=0
start_bare "$APP_PORT"; measure "warmup" "http://127.0.0.1:$APP_PORT"; stop_app

for ROUND in $(seq 1 "$ROUNDS"); do
  echo "-- round $ROUND/$ROUNDS --"

  start_bare "$APP_PORT"; STARTUP_BARE="$STARTUP_MS"
  measure "bare" "http://127.0.0.1:$APP_PORT" "$APP_PID"
  # A second bare measurement, adjacent and identical. Its spread is the noise
  # floor: a vorynex delta smaller than this is not a result.
  measure "bare2" "http://127.0.0.1:$APP_PORT" "$APP_PID"
  stop_app

  start_protected "$APP_PORT"; STARTUP_VORYNEX="$STARTUP_MS"
  measure "vorynex" "http://127.0.0.1:$APP_PORT" "$APP_PID"
  stop_app

  start_bare "$APP_PORT"; STARTUP_CRS="$STARTUP_MS"
  "$WORK/waf" --listen "127.0.0.1:$WAF_PORT" --upstream "http://127.0.0.1:$APP_PORT" \
    --mode blocking --paranoia 1 >"$WORK/waf.log" 2>&1 &
  WAF_PID=$!
  wait_healthy "$WAF_PORT" || { echo "waf failed to start" >&2; cat "$WORK/waf.log" >&2; }
  STARTUP_CRS=$(( STARTUP_CRS + STARTUP_MS ))
  measure "crs" "http://127.0.0.1:$WAF_PORT" "$APP_PID" "$WAF_PID"
  stop_waf
  stop_app

  printf '{"arm":"startup","round":%s,"bare_ms":%s,"vorynex_ms":%s,"crs_ms":%s}\n' \
    "$ROUND" "$STARTUP_BARE" "$STARTUP_VORYNEX" "$STARTUP_CRS" >> "$OUT/rows.jsonl"
done

python3 - "$OUT" "$RATE" "$SECONDS_PER_ARM" <<'PY' | tee "$OUT/summary.md"
import json, pathlib, statistics as st, sys

out = pathlib.Path(sys.argv[1]); rate = sys.argv[2]; dur = sys.argv[3]
rows = [json.loads(l) for l in (out / "rows.jsonl").read_text().splitlines() if l.strip()]
arms = ["bare", "bare2", "vorynex", "crs"]
data = {a: [r for r in rows if r.get("arm") == a] for a in arms}
starts = {a: [r[f"{a}_ms"] for r in rows
              if r.get("arm") == "startup" and f"{a}_ms" in r] for a in arms}
rounds = len(data["bare"])

def med(xs):
    return round(st.median(xs), 2) if xs else None

def spread(d, q):
    xs = [x["latency_ms"][q] for x in d]
    if not xs:
        return "n/a"
    return f"{med(xs)} [{round(min(xs), 2)}–{round(max(xs), 2)}]"

lines = [f"# P4 — enforcement overhead (open-loop {rate} rps, {dur}s per arm, {rounds} rounds)", "",
         "Medians across rounds; latency cells show the median with the round range.",
         "`vorynex` is Tier 0 (Landlock) — enforcement applied at spawn, out of the",
         "request path. `crs` is the OWASP CRS proxy — enforcement in the request",
         "path — with the proxy's own CPU and memory counted. `bare2` is the same",
         "measurement as `bare` taken moments later: it is the noise floor.",
         "", "| Arm | p50 ms | p95 ms | p99 ms | achieved rps | CPU ms/req | RSS MB | startup ms |",
         "|---|---|---|---|---|---|---|---|"]
for a in arms:
    d = data[a]
    if not d:
        continue
    lines.append(
        f"| {a} | {spread(d, 'p50')} | {spread(d, 'p95')} | {spread(d, 'p99')} | "
        f"{med([x['achieved_rps'] for x in d])} | "
        f"{med([x['cpu_ms_per_req'] for x in d if x['cpu_ms_per_req'] is not None])} | "
        f"{med([x['rss_mb'] for x in d])} | {med(starts[a]) if starts[a] else '—'} |")

base = data["bare"]
if base:
    def pct(a, q):
        b = med([x['latency_ms'][q] for x in base])
        v = med([x['latency_ms'][q] for x in data[a]])
        if not b or v is None:
            return "n/a"
        return f"{(v - b) / b * 100:+.1f}%"
    lines += ["", "Overhead vs bare (p50 / p95 / p99):",
              f"  vorynex    {pct('vorynex','p50')} / {pct('vorynex','p95')} / {pct('vorynex','p99')}",
              f"  crs        {pct('crs','p50')} / {pct('crs','p95')} / {pct('crs','p99')}",
              f"  noise floor {pct('bare2','p50')} / {pct('bare2','p95')} / {pct('bare2','p99')}  "
              "(bare measured twice, same conditions)"]

    # Medians-of-medians are weak when the noise floor is large. Because the arms
    # are interleaved, each round yields a paired delta for the same conditions.
    def paired(a, q):
        bs = {x["round"]: x["latency_ms"][q] for x in base}
        ds = [x["latency_ms"][q] - bs[x["round"]] for x in data[a] if x["round"] in bs]
        if not ds:
            return "n/a"
        slower = sum(1 for d in ds if d > 0)
        return f"{round(st.median(ds), 3)} ms, slower in {slower}/{len(ds)} rounds"

    lines += ["", "Paired per-round delta vs bare, same round (p50 / p95 / p99):",
              f"  vorynex    {paired('vorynex','p50')} | {paired('vorynex','p95')} | {paired('vorynex','p99')}",
              f"  crs        {paired('crs','p50')} | {paired('crs','p95')} | {paired('crs','p99')}",
              "",
              "A delta that is not consistently one-signed is not a measured cost:",
              "the workload's own run-to-run variance is larger than it."]

bad = [f"{a}: errors={sum(x['errors'] for x in d)}, timeouts={sum(x['timeouts'] for x in d)}, "
       f"dropped={sum(x['dropped'] for x in d)}"
       for a, d in data.items() if d and any(x["errors"] or x["timeouts"] or x["dropped"] for x in d)]
lines += ["", "Load integrity: " + ("all scheduled requests completed"
          if not bad else "PROBLEMS — " + "; ".join(bad)),
          "Numbers are only meaningful if no arm dropped load; a dropped request is",
          "a latency the generator never measured."]
(out / "summary.json").write_text(json.dumps({"rows": rows}, indent=2) + "\n")
print("\n".join(lines))
PY

echo
echo "evidence: $OUT"
