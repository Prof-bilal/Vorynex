# False-positive root cause: the ping feature

Reproduced 2026-11-08 on this host (Linux 7.2.8, Landlock enabled, Go 1.27.3, node 26.12.0).

## Reproduction

```
$ make fp
| no-exec  | 120/140 | 20 | 14.29% | contained | contained |
| allow-sh | 140/140 |  0 |  0%    | contained | **LANDED** |
  no-exec   legit_exec         0/20  denied
```

This matches the reported 120/140. Evidence: `tests/proof/evidence-benign/<stamp>/`.

## Answers

| Question | Finding | Source |
|---|---|---|
| Which process handles ping? | The Node server itself (the workload process). | `tests/proof/targets/vulnerable-node/server.js:49-58` |
| How is it spawned? | `child_process.exec("ping -c 1 " + host)`. `exec` always runs `/bin/sh -c`. | same |
| Does it need a shell? | **No.** `ping` needs no shell; the shell is incidental, and is also what makes the feature an injection hole (that target is intentionally vulnerable). | |
| Which policy denies it? | The generated policy has no `process.exec.allow`, so only the launched binary's directory is executable. | `engine/enforce/spawntime/spawntime_linux.go` `execDirs` |
| Enforcement boundary | Landlock `LANDLOCK_ACCESS_FS_EXECUTE`, checked inside `execve` for `/bin/sh`. | `spawntime_linux.go` (`addPathRule(..., read\|accExecute)`) |
| Synchronous? | Yes. `execve` returns `EACCES` to the caller before the program starts. | observed: `sh DENIED EACCES` |
| Meaningful error to the app? | Node surfaces `EACCES`, but this app collapses every error to `code:1, stderr:""`, so the operator sees an anonymous failure. The new fixture passes `error: "EACCES"` through. | `server.js:56`, `benign.js` denial heuristic |
| Does the event trace identify it? | **Not verified.** `spawntime_linux.go` contains no audit/journal/event emission, so as far as the code shows, Tier 0 denials are invisible to telemetry; the only evidence is the app's own errno. | grep for audit/event/journal: no hits |
| Would loosening the policy let an attacker do the same? | Yes. `allow-sh` makes the injection `ping ...; cp server.js $SCRATCH/x` land (`in-grant LANDED`). | `make fp` |

## The previous explanation was incomplete

"The default policy denies shell execution" is true but not the root cause. Two deeper facts:

1. **The feature never needed a shell**, so denying it was correct for the code as written. Fix the code, not the policy.
2. **Tier 0 cannot grant exec per file.** Landlock's execute right attaches to a directory subtree. A narrow-looking rule `exec.allow: [/usr/bin/ping]` really grants all 3,867 executables in `/usr/bin`, including `sh` and `cp`:

```
allow ["/usr/bin/ping"]  ->  sh OK, cp OK          (broad: attacker has a shell)
allow ["<private>/ping"] ->  sh EACCES, cp EACCES, ping OK
```

So the "obvious" exception reproduces the exact `allow-sh` exposure while looking narrow, and the engine accepted it silently. That silent widening, not the shell denial, is the defect this work fixes.

## Conclusion

Root cause: an application feature implemented through a shell, combined with a backend whose only exec primitive is directory-granular, so no narrow exception was expressible. The false positive was an accurate denial of a risky call pattern; the dangerous part was the lack of any way to say "just ping" safely.
