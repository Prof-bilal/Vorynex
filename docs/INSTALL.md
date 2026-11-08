# INSTALL.md — install, verify, and protect

Vorynex applies a **local** runtime boundary to a workload. Enforcement is at
spawn (Tier 0, Landlock) or attached live to a running cgroup (Tier 1, eBPF-LSM).
Nothing is in the request path, and the control plane is optional.

## Requirements

| Need | For | Check |
|---|---|---|
| Linux, kernel ≥ 5.13 with `CONFIG_SECURITY_LANDLOCK` | Tier 0 | `vorynex doctor` |
| kernel ≥ 6.7 (Landlock ABI ≥ 4) | Tier 0 also denies outbound TCP | `vorynex status --json` → `capabilities.landlock_abi` |
| kernel with BPF-LSM (≥ 5.7, `lsm=...,bpf`) **and root** | Tier 1 live attach | `vorynex live status` |
| `strace` | `observe` (learning) | `command -v strace` |
| Docker (optional) | the control-plane image | `docker info` |
| `clang` (optional) | building the Tier 1 BPF object | `make bpf` |

Vorynex never pretends to enforce at a tier the host cannot: `doctor` reports
what is available and `status` reports which tier it is actually using.

## Install

Build a release and install it (works today, no published artifacts required):

```bash
make release                              # dist/*.tar.gz + checksums.txt
sudo ./install.sh                          # builds from the checkout instead
# or install a specific tarball into a prefix:
./install.sh --from dist/vorynex_0.1.0_linux_amd64.tar.gz --prefix "$HOME/vorynex" --no-cloud
```

`install.sh` is idempotent and never overwrites configuration you already have.
Options: `--prefix DIR`, `--from TARBALL`, `--no-cloud`, `--enable` (enable the
cloud service), `--uninstall`.

Verify what you downloaded before installing it:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### For maintainers: publishing a release

There are no published releases yet, so no download URL exists. When you decide
to publish one, the artifacts `make release` produces are exactly what the
install path above consumes:

```bash
git tag "v$(cat VERSION)"
git push origin "v$(cat VERSION)"
gh release create "v$(cat VERSION)" dist/*.tar.gz dist/checksums.txt \
  --title "v$(cat VERSION)" --notes-file docs/RELEASE_NOTES.md   # or --generate-notes
```

After that, `https://github.com/Prof-bilal/Vorynex/releases/latest/download/<tarball>`
is a valid URL and the curl-and-install form works:

```bash
V="$(curl -fsSL https://api.github.com/repos/Prof-bilal/Vorynex/releases/latest \
     | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"])')"
curl -fLO "https://github.com/Prof-bilal/Vorynex/releases/download/$V/vorynex_${V#v}_linux_amd64.tar.gz"
curl -fLO "https://github.com/Prof-bilal/Vorynex/releases/download/$V/checksums.txt"
sha256sum -c checksums.txt --ignore-missing
tar -xzf "vorynex_${V#v}_linux_amd64.tar.gz" && sudo "./vorynex_${V#v}_linux_amd64/install.sh"
```

### What it puts where

| Path | What |
|---|---|
| `/usr/local/bin/vorynex`, `vorynex-cloud` | binaries (version-stamped) |
| `/etc/vorynex/agent.env` | the workload the host protects (you edit this) |
| `/etc/vorynex/cloud.env`, `cloud-token.env` | control-plane settings; admin token is generated 0600 |
| `/var/lib/vorynex` | local state: mode, policy digest, journal |
| `/usr/share/vorynex/dashboard`, `live.bpf.o` | dashboard assets; Tier 1 object |
| `/etc/systemd/system/vorynex-agent.service`, `vorynex-cloud.service` | units (installed, **not enabled**) |

## Protect a workload

```bash
vorynex doctor                 # what this host can enforce
vorynex discover --details      # what is running here
vorynex connect                 # find the app, learn it, report — never protect
```

`connect` never starts enforcing. Learning is explicit:

```bash
# 1. record two sessions with no enforcement (a capability seen once is not
#    promoted, so one session is not enough)
vorynex observe -- node /srv/app/server.js     # Ctrl-C when the app is up
vorynex observe -- node /srv/app/server.js

# 2. turn the observations into a reviewable policy
vorynex policy generate --from ~/.local/state/vorynex/traces/A.jsonl \
                        --from ~/.local/state/vorynex/traces/B.jsonl \
                        --min-sessions 2 --out /etc/vorynex/policy.yaml

# 3. read it before you trust it
cat /etc/vorynex/policy.yaml
vorynex blast-radius --policy /etc/vorynex/policy.yaml

# 4. supervise the workload under it; roll back if it never becomes healthy
vorynex run --policy /etc/vorynex/policy.yaml \
            --health http://127.0.0.1:3000/health -- node /srv/app/server.js
```

Then point the service at the same thing and start it:

```bash
sudoedit /etc/vorynex/agent.env     # VORYNEX_POLICY, VORYNEX_HEALTH, VORYNEX_COMMAND
sudo systemctl enable --now vorynex-agent
vorynex status                      # mode, active policy digest, capabilities
```

### Two things that surprise people

- **Your application must live on a stable path.** `/tmp`, `/usr`, `/lib`,
  `/proc` and `/dev` are treated as runtime-provided scratch and are **never**
  granted: an app under `/tmp` can be observed but never protected. Put it in
  `/srv`, `/opt`, `/var/lib` or `$HOME`.
- **`protect --off` does not restart your workload.** It restores the recorded
  posture (the previous mode is what comes back, not a literal "off"); a running
  process keeps the boundary it was launched with, and the next launch uses the
  restored posture. The CLI says so.

## Control plane (optional)

```bash
vorynex-cloud --addr 127.0.0.1:8787 --token "$(openssl rand -hex 32)" \
              --store /var/lib/vorynex/cloud-events.jsonl
```

Or as a container:

```bash
docker build -f cloud/Dockerfile -t vorynex-cloud .
docker run -d -p 127.0.0.1:8787:8787 \
  -e VORYNEX_CLOUD_TOKEN=$(openssl rand -hex 32) \
  -v vorynex-data:/var/lib/vorynex vorynex-cloud
```

Without `--token` the API is **unauthenticated**; `install.sh` generates one for
you. Agents enrol with the admin token once and then use a per-host token.

## Verify the install

```bash
make e2e        # the whole journey, asserted: install (checkout + tarball),
                # observe, policy, protect, attack contained, rollback, off,
                # control-plane ingestion, container image
make preflight  # the deployment gate, against this host's real config
make proof      # containment vs a request-layer WAF on a controlled target
make proof-real # the same against a real third-party app (Docker, needs root)
make bench      # enforcement overhead, interleaved and paired
```

`make e2e` needs no root. It skips the container step when no Docker daemon is
available, and fails (rather than skipping) when the host cannot enforce — a
green run that tested nothing is worse than a red one. `E2E_ALLOW_SKIP=1`
downgrades that, `E2E_KEEP=1` leaves the scratch workload behind.

## Verify readiness before you ship

`vorynex preflight` reads the real configuration and refuses to bless a host that
would fail in front of users. It writes nothing, and exits non-zero on any
failure:

```bash
sudo vorynex preflight --behind-proxy   # this host, as configured
vorynex preflight --json                # machine-readable, for CI or a deploy gate
```

Every failure names the command that fixes it. What it checks:

| Group | Checks |
|---|---|
| **host** | Landlock ABI ≥ 1 (Tier 0 can enforce at all), ABI ≥ 4 (TCP denial works), `strace` present for `observe`, Tier 1 availability (warning) |
| **agent** | `agent.env` present; the policy **loads**; the workload exists and is executable; the workload's directory is **grantable** and covered by a read grant |
| **cloud** | admin token set — a *failure*, not a warning, once the address is beyond loopback; token file not world-readable; TLS configured or a proxy acknowledged; state store writable |
| **release** | version is not a dev placeholder; working tree committed; a tag exists for this version |

The two agent checks that matter most are the ones that otherwise surface as a
puzzling rollback on the first launch: an application under `/tmp` (or `/usr`,
`/lib`, `/proc`, `/dev`) can never be granted, and a policy generated from a
single observation session will not grant the application its own entry point.

```text
AGENT
  FAIL  grantable   /tmp/app is runtime scratch (/tmp, /usr, /lib, /proc, /dev):
                    it can be observed but never granted, so it can never be protected
        fix: move the application to a stable path such as /srv, /opt, /var/lib or $HOME

CLOUD
  FAIL  token       no admin token, and the API is reachable beyond loopback: anyone
                    who can reach it can read and write fleet state
  FAIL  tls         plaintext on a non-loopback address, with no proxy acknowledged
```

## Uninstall

```bash
sudo ./install.sh --uninstall     # removes binaries + units
```

It deliberately **keeps** `/etc/vorynex` (your policy and tokens) and
`/var/lib/vorynex` (the journal). Remove those by hand when you mean it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `run` rolls back immediately, logs `EACCES` on your entry file | the policy does not grant the app tree: let it see two observe sessions, or add the path to `filesystem.read` |
| `observe` fails: `strace not found` | install `strace` |
| `live attach` says Tier 1 unavailable | needs root and a kernel with BPF-LSM: `vorynex live status` lists the reasons |
| No outbound TCP at all | Landlock ABI ≥ 4 denies connect unless the policy allows it — expected, and it is why Tier 1 is the better fit for an app that needs its database |
| `doctor` reports ABI < 4 | the kernel is older; filesystem/exec containment works, network denial does not |
