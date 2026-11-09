# Competitive policy engineering

## Provenance: read this first

- **REA was not used for this.** REA (MCP tools `mcp__rea__*`) analyses *shipped artifacts*: binaries, bundles, APKs, web pages, runtimes. Its own guidance says to skip it for ordinary source-repository analysis. Nothing here required disassembling a binary, and I did not run any REA tool.
- **No upstream repository was cloned or read in this session, and no web fetch was made.** The system descriptions below are from general knowledge of public documentation and may be out of date. No file or function references to those projects are given because I did not verify any. Treat every row as "documented, unverified" until someone reads the source. The one-line lessons are my recommendations.
- Aikido Zen was not investigated. Its marketing claims are not evidence.

## Comparison (documented, unverified)

| System | Problem it solves | Enforcement | Learning | False-positive handling | Lesson for Vorynex |
|---|---|---|---|---|---|
| AppArmor | Per-program MAC profiles | LSM path rules | complain mode logs; `aa-genprof`/`aa-logprof` turn logged accesses into proposed rules *a human accepts per rule* | complain-before-enforce; interactive review | Proposals are per-rule and reviewed. Vorynex already refuses to auto-promote shells/secrets. Add per-rule review output to `verify`. |
| Security Profiles Operator | Record and distribute seccomp/AppArmor profiles on Kubernetes | seccomp / AppArmor / SELinux via the node | Recording a workload's syscalls into a profile | Profile bound to workloads, rolled out as objects | A recording is a candidate, not proof of safety. Separate record from approve from bind. |
| Tetragon | eBPF observability + enforcement | eBPF/LSM; actions like override return or SIGKILL | Policies are hand-written | Staged by running tracing-only first | Distinguish *kill after the fact* from *deny before*; Vorynex's Tier 0 denies synchronously. Tetragon's per-binary matching is finer than Landlock; Tier 1 is the equivalent here. Integrating it is a build-vs-buy question not settled here. |
| Falco | Runtime detection | none (alerts) | Rule exceptions | Exceptions suppress *alerts* | Exceptions in a detector are not kernel allow rules; do not copy the idea into an enforcer. Useful only for the ancestry vocabulary. |
| Cilium | Network policy/identity | eBPF datapath | Hubble flow visibility | Audit mode for policy verdicts | Recommend egress from observed flows only with review: an attacker's destination observed during recording must not enter an allowlist. |
| Argo Rollouts / SRE canarying | Safe release | n/a | n/a | metric analysis, auto-abort | Adapt as: new policy is a release; required workflows are the analysis; failure aborts to the last verified policy. |

## Recommendations (mine)

1. Candidate vs approved vs active stay distinct states (built as `verify`; promotion is manual).
2. Never learn from an untrusted window: observation can only propose, and a human or a defined test must justify each grant.
3. Prefer fixing the application call over widening the policy (ping: shell -> argv exec).
4. Do not add a dependency on any of these for v1.
