# PERFORMANCE.md — what enforcement costs

Measured, not asserted. Produced by `make bench`; raw rows and per-round JSON in
`tests/proof/evidence-bench/<stamp>/` (gitignored).

## What is being compared

The same endpoint (`/api/echo?x=1` on the proof target) served three ways, in
**interleaved rounds** so drift — thermal, scheduler, page cache — hits every arm
equally:

| Arm | Enforcement | Where it sits |
|---|---|---|
| `bare` | none | — |
| `vorynex` | Tier 0 (Landlock) | applied at **spawn**; not in the request path |
| `crs` | OWASP Coraza + CRS 4.0 | **in the request path**, proxying every request |

`bare2` is the same measurement as `bare` taken moments later. It exists to
supply a noise floor: on a shared machine, two identical measurements differ, and
a delta smaller than that difference is not a result.

The proxy's own CPU and memory are counted in the `crs` arm. Nothing is excluded
to favour anyone.

## Method notes

- **Open-loop, fixed rate** (`RATE=200` rps, 6 s per arm, 7 rounds). A
  closed-loop generator ("32 workers looping") stops issuing requests while a
  response is stalled, which hides the tail latency a request-path defence
  introduces — coordinated omission. Here each request is scheduled on a clock,
  so a stall shows up as a large latency rather than as an absence of samples.
  `dropped` counts a schedule the target could not keep up with; any arm with
  drops or errors is reported as a problem instead of a number.
- **Paired per-round deltas**, not only medians-of-medians: each round yields a
  vorynex-minus-bare and crs-minus-bare delta under identical conditions. If a
  delta is not consistently one-signed, it is noise, not cost.
- CPU from `/proc/<pid>/stat` jiffies over the measurement window; RSS/VmHWM from
  `/proc/<pid>/status`. For `crs`, the workload and the proxy are summed.
- Startup is spawn → first successful `/health`, median of 7 rounds.

## Results (one machine, loopback, 200 rps)

| Arm | p50 ms | p95 ms | p99 ms | CPU ms/req | RSS MB | startup ms |
|---|---|---|---|---|---|---|
| `bare` | 0.60 | 0.92 | 1.67 | 0.38 | 71.6 | 86 |
| `vorynex` (Tier 0) | 0.59 | 1.04 | 1.58 | 0.37 | 71.6 | 88 |
| `crs` (in path) | 2.09 | 3.60 | 5.59 | 2.31 | 132.7 | 176 |

Paired per-round delta vs bare, same round:

```
vorynex    p50 -0.024 ms (slower in 3/7 rounds)
           p95 +0.057 ms (slower in 4/7)
           p99   -0.09 ms (slower in 2/7)
crs        p50 +1.511 ms (slower in 7/7)
           p95 +2.679 ms (slower in 7/7)
           p99  +4.27 ms (slower in 7/7)
noise floor (bare vs bare): slower in 5/7, 4/7, 2/7 — i.e. coin flips
```

## How to read it

1. **Tier 0's cost is below the noise floor of this measurement.** Its deltas
   are mixed-sign and about as often "faster" as "slower", exactly like two bare
   runs compared to each other. At this load the sandbox is not a measurable
   cost: Landlock is a check applied when a path is resolved, not a per-request
   stage, and an already-open loopback connection never touches it.
2. **The request-path filter costs 2.5–3.5× latency and ~6× CPU**, consistently,
   in 7 of 7 rounds at every percentile — including +1.85× memory and +2× startup
   (it must load ~600 rules before it can serve anything).
3. **This is the architectural difference, quantified.** Vorynex's enforcement
   does not grow with request rate; the proxy's does.

## Limits (do not overstate this)

- **Tier 0 only.** Tier 1 (eBPF-LSM) *is* per-operation — it hooks exec, file
  open and connect — so it is the arm most likely to show overhead, and it is
  **not** measured here. Any claim of "no overhead" is a claim about Tier 0.
- One machine, shared with other workloads; loopback; no TLS; a trivial endpoint
  (`/api/echo`) that does no meaningful application work. A CPU-heavy workload
  would dilute both overheads; an I/O-heavy one would change the picture.
- 200 rps at a fixed rate. **No saturation ceiling** was measured, so no
  "handles N rps" claim is made for any arm.
- 7 rounds. Enough to make a sign-consistent cost obvious (CRS), not enough to
  bound a small one (Tier 0) tighter than "smaller than run-to-run noise".
- Startup figures are for a Node workload with the page cache warm.

## Reproduce

```bash
make bench                            # default: 7 rounds, 200 rps, 6 s per arm
ROUNDS=15 RATE=500 make bench         # tighter / higher rate
```
