#!/usr/bin/env bash
# Register this host as a self-hosted GitHub Actions runner for this repository,
# so `proof-real` (the real-application arm) stops being a manual step.
#
# Why a self-hosted runner: that job needs Docker, ~2.5 GB of images and root for
# the Tier 1 column. On GitHub's hosted runners it costs ~10 minutes per run;
# on a machine you own it is a few minutes and free.
#
# Run this as the user that should own the runner (NOT root):
#   ./scripts/ci-runner-setup.sh
# It uses sudo only to install the background service.
#
# Requires: gh (authenticated with admin on the repo), curl, tar, docker, sudo.
set -euo pipefail

REPO="${REPO:-Prof-bilal/Vorynex}"
LABELS="${LABELS:-self-hosted,linux,x64,vorynex}"
NAME="${NAME:-$(hostname)-vorynex}"
DIR="${RUNNER_DIR:-$HOME/actions-runner-vorynex}"

say() { printf '\n== %s ==\n' "$1"; }

say "preflight"
command -v gh >/dev/null || { echo "gh is required (https://cli.github.com)" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required: the job starts containers" >&2; exit 1; }
[[ "$EUID" -ne 0 ]] || { echo "run this as the runner's user, not root (it uses sudo itself)" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "run 'gh auth login' first" >&2; exit 1; }
sudo -n true 2>/dev/null || echo "note: sudo will prompt for a password to install the service"
echo "repo   $REPO"
echo "labels $LABELS"
echo "dir    $DIR"

say "registration token"
TOKEN="$(gh api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token)"
[[ -n "$TOKEN" ]] || { echo "could not obtain a registration token (need admin on $REPO)" >&2; exit 1; }
echo "obtained (expires in ~1 hour)"

say "download the runner"
VERSION="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; esac
TARBALL="actions-runner-linux-${ARCH}-${VERSION}.tar.gz"
mkdir -p "$DIR"
if [[ ! -f "$DIR/$TARBALL" ]]; then
  curl -fsSL -o "$DIR/$TARBALL" \
    "https://github.com/actions/runner/releases/download/v${VERSION}/${TARBALL}"
fi
tar -xzf "$DIR/$TARBALL" -C "$DIR"
echo "runner $VERSION ($ARCH) in $DIR"

say "configure"
cd "$DIR"
./config.sh --url "https://github.com/$REPO" --token "$TOKEN" \
  --name "$NAME" --labels "$LABELS" --unattended --replace

say "install as a service"
sudo ./svc.sh install "$(id -un)"
sudo ./svc.sh start
sudo ./svc.sh status || true

cat <<EOF

Runner registered. Tell CI to use it (and to run the real-application arm on
every push to main):

  gh variable set PROOF_REAL_RUNNER '["self-hosted","linux","x64","vorynex"]'
  gh variable set PROOF_REAL_ON_PUSH true
  gh workflow run ci.yml          # prove it now

Check it is online:  gh api repos/$REPO/actions/runners --jq '.runners[] | {name,status,busy}'

Security note: a self-hosted runner executes code from this repository. Keep it
attached to a private repo or to trusted branches only — never let it pick up
pull requests from forks.

To remove it:  cd $DIR && sudo ./svc.sh stop && sudo ./svc.sh uninstall && ./config.sh remove
EOF
