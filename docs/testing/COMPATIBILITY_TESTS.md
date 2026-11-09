# Compatibility tests

`vorynex verify --policy P --corpus C --base URL -- <cmd>` runs the workload under P and drives C.
Corpus: `tests/proof/targets/safe-api/corpus.json` (9 features, 168 requests; `${SCRATCH}` is expanded from the environment).

Each workflow: `feature`, `required`, `count`, request, `expect_status`, `expect_body` (regexp). A failure is a *sandbox denial* only if the body matches `EACCES|EPERM|Permission denied`; other failures are "verification incomplete" because they cannot be attributed to the policy. A feature with no required workflow is "insufficient coverage". Either state yields DO NOT ENFORCE. Exit code 2 means do not enforce.

Unit tests: `engine/verify/verify_test.go` (health never overrides a failing workflow; uncovered feature blocks; all-pass).
Not covered: see roadmap item 4.

Corpus fields added: `concurrency` (parallel workers). `--lifecycle` adds `graceful-shutdown` (SIGTERM must exit 0 within 5s) and `cold-restart` (restart under the same policy, healthy, every workflow passes again). `--trace` appends the syscalls refused with EACCES/EPERM.
