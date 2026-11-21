# Competitive policy engineering

## Provenance

- **REA was not used.** It analyses shipped artifacts (binaries, bundles, pages); its own guidance says to skip it for source-repository analysis. These are open-source repositories, so ordinary read-only inspection was the right tool.
- **Source was read, narrowly.** Shallow read-only clones (2026-11-09) of AppArmor `d223f07`, Security Profiles Operator `e5ecbf1`, Tetragon `d86c942` and Falco `2be5618`. Only the specific files cited in "Verified" below were read. Everything in "Documented, not verified" is from general knowledge and may be out of date.
- **Not investigated:** Cilium/Hubble, Aikido Zen (marketing claims are not evidence), Argo Rollouts, Google SRE material.

## Verified in source

| Claim | Evidence |
|---|---|
| AppArmor ships learning tools: `aa-genprof`, `aa-logprof`, `aa-complain`, `aa-enforce`, `aa-cleanprof`, `aa-autodep` | `utils/` in apparmor `d223f07` |
| `aa-genprof` puts the program in complain mode before learning | `utils/aa-genprof:130` `apparmor.complain(program)` |
| Learned exec accesses are decided *per binary by a human* with inherit/profile/child/unconfined choices (`CMD_ix`, `CMD_px`, `CMD_cx`, `CMD_ux`, `CMD_DENY`) | `utils/apparmor/aa.py` `ask_exec` (:740), choice list (:827); `ask_the_questions` (:1037), `do_logprof_pass` (:1501) |
| SPO records profiles for seccomp, SELinux and AppArmor, via audit logs or a BPF recorder | `api/profilerecording/v1/profilerecording_types.go:55-73` |
| SPO separates recording, profile objects and binding (`profilebinding`, `seccompprofile`, `apparmorprofile`, `selinuxprofile`, `profilerecording` API groups; `bpfrecorder`, `profilerecorder` daemons) | `api/`, `internal/pkg/daemon/` |
| Tetragon has `sigkill` and `override` actions | `pkg/selectors/kernel.go:69-70` |
| **Tetragon's own docs say SIGKILL does not always stop the operation** (e.g. a `write()` still completes); only `Override` prevents it, so they advise combining both | `docs/content/en/docs/concepts/enforcement/_index.md:29-35` |
| Falco exceptions are compiled into the *detection condition*; they suppress alerts and enforce nothing | `userspace/engine/rule_loader_compiler.cpp:101-106` |

## Documented, not verified

Cilium policy audit mode and Hubble verdicts; Tetragon policy staging by running tracing-only first; SPO profile merging; Argo Rollouts analysis/abort semantics; any Aikido Zen behavior.

## Comparison (see the two tables above for what is verified)

| System | Problem it solves | Enforcement | Learning | False-positive handling | Lesson for Vorynex |
|---|---|---|---|---|---|
| AppArmor | Per-program MAC profiles | LSM path rules | complain mode logs; `aa-genprof`/`aa-logprof` turn logged accesses into proposed rules *a human accepts per rule* (verified) | complain-before-enforce; interactive review | **Adopted:** exec observed during learning is a per-binary human decision. Vorynex now matches this: only the workload binary auto-promotes; all other execs are `review` items (`engine/profiler`). |
| Security Profiles Operator | Record and distribute seccomp/AppArmor profiles on Kubernetes | seccomp / AppArmor / SELinux via the node | Recording a workload's syscalls into a profile | Profile bound to workloads, rolled out as objects | A recording is a candidate, not proof of safety. Separate record from approve from bind. |
| Tetragon | eBPF observability + enforcement | eBPF/LSM; actions like override return or SIGKILL | Policies are hand-written | Staged by running tracing-only first | **Verified:** its own docs say SIGKILL alone does not guarantee the operation is prevented. This is the same distinction Vorynex draws (Tier 0 denies in `execve`; kill-after-the-fact is not prevention). Tetragon's per-binary matching is finer than Landlock; Tier 1 is the equivalent here. Integrating it is a build-vs-buy question not settled here. |
| Falco | Runtime detection | none (alerts) | Rule exceptions | Exceptions suppress *alerts* (verified: compiled into the detection condition) | Exceptions in a detector are not kernel allow rules; do not copy the idea into an enforcer. Useful only for the ancestry vocabulary. |
| Cilium | Network policy/identity | eBPF datapath | Hubble flow visibility | Audit mode for policy verdicts | Recommend egress from observed flows only with review: an attacker's destination observed during recording must not enter an allowlist. |
| Argo Rollouts / SRE canarying | Safe release | n/a | n/a | metric analysis, auto-abort | Adapt as: new policy is a release; required workflows are the analysis; failure aborts to the last verified policy. |

## Recommendations (mine)

1. Candidate vs approved vs active stay distinct states (built as `verify`; promotion is manual).
2. Never learn from an untrusted window: observation can only propose, and a human or a defined test must justify each grant.
3. Prefer fixing the application call over widening the policy (ping: shell -> argv exec).
4. Do not add a dependency on any of these for v1.
