# CI_RUNNER.md — the real-application arm on every push

`make proof-real` (P3) runs DVWS-node in Docker: bare, behind OWASP CRS, and under
Vorynex Tier 1 armed on the running container. It needs **Docker**, **~2.5 GB of
images** and **root** for the Tier 1 column.

On a GitHub-hosted runner that is ~10 minutes and a large pull per run. On a
machine you own it is a few minutes and free. This is how to wire it in.

## 1. Register a runner

On the host that will run it (it needs Docker and sudo):

```bash
./scripts/ci-runner-setup.sh
```

The script obtains a registration token with `gh`, downloads the current runner,
configures it with the label `vorynex`, and installs it as a systemd service. It
does not run as root itself — it uses sudo only for the service.

Requirements: `gh` authenticated with admin on the repo, `docker`, `curl`, `tar`.

## 2. Point CI at it

```bash
# the runner's labels, as a JSON array (the workflow defaults to ubuntu-latest)
gh variable set PROOF_REAL_RUNNER '["self-hosted","linux","x64","vorynex"]'

# run P3 on every push to main, not only on demand
gh variable set PROOF_REAL_ON_PUSH true
```

Both are repository variables, not secrets — they are not sensitive.

## 3. Prove it

```bash
gh workflow run ci.yml
gh run watch
```

The `proof-real` job prints its result table into the run summary and uploads the
evidence bundle (`arm-a.jsonl`, `arm-b-*.jsonl`, `arm-c.jsonl`, `tier1.log`).

## Behaviour without a runner

`PROOF_REAL_ON_PUSH` unset means the job is **skipped**, not queued. A job that
waits forever for a runner nobody registered reads as a broken pipeline on every
push; the skip is deliberate.

`workflow_dispatch` always runs it — on the self-hosted runner when the variable
is set, otherwise on `ubuntu-latest` (slower, but it works).

## Security

A self-hosted runner executes code from this repository. Keep it attached to a
private repository or trusted branches only, and never allow it to pick up pull
requests from forks. `pwn-request` is the standard name for what happens
otherwise.

## Uninstall

```bash
cd ~/actions-runner-vorynex
sudo ./svc.sh stop && sudo ./svc.sh uninstall
./config.sh remove
gh variable unset PROOF_REAL_ON_PUSH
```
