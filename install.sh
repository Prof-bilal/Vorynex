#!/usr/bin/env bash
# Vorynex installer.
#
# Installs the agent (and optionally the cloud control plane), the Tier 1 BPF
# object if it was built, the systemd units, and a state directory — from either
# a release tarball or a git checkout.
#
#   sudo ./install.sh                 # install agent + cloud + units
#   sudo ./install.sh --no-cloud      # agent only
#   sudo ./install.sh --prefix /opt/vorynex
#   sudo ./install.sh --from dist/vorynex_0.1.0_linux_amd64.tar.gz
#   sudo ./install.sh --uninstall
#
# It is idempotent: running it twice changes nothing the second time. It never
# enables or starts a service unless you pass --enable.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
# Overridable so a non-root prefix is self-contained and testable end to end.
SYSCONF="${SYSCONF:-}"
STATE="${STATE:-}"
SHARE="${SHARE:-}"
WITH_CLOUD=1
ENABLE=0
UNINSTALL=0
FROM=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --no-cloud) WITH_CLOUD=0; shift ;;
    --enable) ENABLE=1; shift ;;
    --from) FROM="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage 2 ;;
  esac
done

BINDIR="$PREFIX/bin"

# A system install uses the FHS locations; any other prefix keeps everything
# under itself, so it can be installed and exercised without root.
if [[ -z "$SYSCONF" || -z "$STATE" || -z "$SHARE" ]]; then
  if [[ "$PREFIX" == "/usr/local" ]]; then
    SYSCONF="${SYSCONF:-/etc/vorynex}"
    STATE="${STATE:-/var/lib/vorynex}"
    SHARE="${SHARE:-/usr/share/vorynex}"
    UNIT_DIR="/etc/systemd/system"
  else
    SYSCONF="${SYSCONF:-$PREFIX/etc/vorynex}"
    STATE="${STATE:-$PREFIX/var/lib/vorynex}"
    SHARE="${SHARE:-$PREFIX/share/vorynex}"
    UNIT_DIR="$PREFIX/etc/systemd/system"
  fi
fi
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"

if [[ "$UNINSTALL" == "1" ]]; then
  echo "== uninstalling =="
  for unit in vorynex-agent vorynex-cloud; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^$unit.service"; then
      systemctl disable --now "$unit" 2>/dev/null || true
    fi
    rm -f "$UNIT_DIR/$unit.service"
  done
  systemctl daemon-reload 2>/dev/null || true
  rm -f "$BINDIR/vorynex" "$BINDIR/vorynex-cloud"
  rm -rf "$SHARE"
  echo "removed binaries and units."
  echo "kept: $SYSCONF (your configuration), $STATE (agent state)."
  echo "      the 'vorynex' system user is left in place; remove it with:"
  echo "      userdel vorynex   (after you are sure nothing else uses it)"
  echo "      remove the config and state by hand if you also want those gone."
  exit 0
fi

if [[ "${EUID}" -ne 0 && "$PREFIX" == "/usr/local" ]]; then
  echo "install.sh: installing to $PREFIX needs root. Re-run with sudo, or pass" >&2
  echo "            --prefix \$HOME/.local (services are then skipped)." >&2
  exit 1
fi

# --- locate the binaries -----------------------------------------------------
SRC=""
if [[ -n "$FROM" ]]; then
  [[ -f "$FROM" ]] || { echo "install.sh: no such file: $FROM" >&2; exit 1; }
  SRC="$(mktemp -d)"
  tar -xzf "$FROM" -C "$SRC"
  # tarballs contain a single top-level directory
  SRC="$(find "$SRC" -maxdepth 1 -mindepth 1 -type d | head -1)"
elif [[ -x "$HERE/vorynex" ]]; then
  SRC="$HERE"
elif [[ -f "$HERE/go.mod" ]] && command -v go >/dev/null 2>&1; then
  SRC="$HERE/build/install"
  mkdir -p "$SRC"
  echo "== building from checkout =="
  VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo 0.0.0-dev)"
  COMMIT="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ( cd "$HERE" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
      -o "$SRC/vorynex" ./cmd/vorynex )
  ( cd "$HERE" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION" \
      -o "$SRC/vorynex-cloud" ./cmd/vorynex-cloud )
  if [[ -f "$HERE/engine/enforce/live/bpf/live.bpf.o" ]]; then
    mkdir -p "$SRC/packaging/bpf"
    cp "$HERE/engine/enforce/live/bpf/live.bpf.o" "$SRC/packaging/bpf/live.bpf.o"
  fi
  mkdir -p "$SRC/cloud"
  cp -r "$HERE/cloud/dashboard" "$SRC/cloud/" 2>/dev/null || true
  mkdir -p "$SRC/packaging/systemd"
  cp "$HERE"/packaging/systemd/*.service "$SRC/packaging/systemd/" 2>/dev/null || true
else
  echo "install.sh: nothing to install. Pass --from <tarball>, or run from a" >&2
  echo "            release directory, or from the git checkout with go installed." >&2
  exit 1
fi

[[ -x "$SRC/vorynex" ]] || { echo "install.sh: $SRC/vorynex missing or not executable" >&2; exit 1; }

# --- install -----------------------------------------------------------------
echo "== installing to $BINDIR =="
install -d "$BINDIR"
install -m 0755 "$SRC/vorynex" "$BINDIR/vorynex"
if [[ "$WITH_CLOUD" == "1" && -x "$SRC/vorynex-cloud" ]]; then
  install -m 0755 "$SRC/vorynex-cloud" "$BINDIR/vorynex-cloud"
fi
echo "  $("$BINDIR/vorynex" version | head -1)"

if [[ -d "$SRC/cloud/dashboard" ]]; then
  install -d "$SHARE/dashboard"
  cp -r "$SRC/cloud/dashboard/." "$SHARE/dashboard/"
  echo "  dashboard -> $SHARE/dashboard"
fi

BPF_DST=""
if [[ -f "$SRC/packaging/bpf/live.bpf.o" ]]; then
  install -d "$SHARE"
  install -m 0644 "$SRC/packaging/bpf/live.bpf.o" "$SHARE/live.bpf.o"
  BPF_DST="$SHARE/live.bpf.o"
  echo "  tier 1 object -> $BPF_DST"
elif [[ -f "$SRC/engine/enforce/live/bpf/live.bpf.o" ]]; then
  install -d "$SHARE"
  install -m 0644 "$SRC/engine/enforce/live/bpf/live.bpf.o" "$SHARE/live.bpf.o"
  BPF_DST="$SHARE/live.bpf.o"
  echo "  tier 1 object -> $BPF_DST"
else
  echo "  tier 1 object: not built (Tier 0 only). Build it with: make bpf"
fi

install -d -m 0700 "$STATE"
install -d -m 0755 "$SYSCONF"

# --- service user ------------------------------------------------------------
# The control plane is network-facing and never needs root, so it gets its own
# system user that owns the state directory. The *agent* is different: the
# workload it supervises inherits the agent's identity, so forcing a user there
# would break applications that rely on their own permissions.
SERVICE_USER="vorynex"
if [[ "$PREFIX" == "/usr/local" ]]; then
  getent group "$SERVICE_USER" >/dev/null 2>&1 || groupadd --system "$SERVICE_USER" 2>/dev/null || true
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_USER" --home-dir "$STATE" \
      --shell /usr/sbin/nologin --comment "Vorynex control plane" "$SERVICE_USER" 2>/dev/null || true
  fi
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    chown "$SERVICE_USER:$SERVICE_USER" "$STATE"
    chmod 0700 "$STATE"
    echo "  service user: $SERVICE_USER (owns $STATE)"
  else
    echo "  warning: could not create the '$SERVICE_USER' user; vorynex-cloud will not start" >&2
  fi
fi

# --- configuration (never overwrite what is already there) -------------------
if [[ ! -f "$SYSCONF/cloud.env" ]]; then
  cat > "$SYSCONF/cloud.env" <<EOF
# Vorynex Cloud control plane. Written by install.sh; edit freely.
VORYNEX_CLOUD_ADDR=127.0.0.1:8787
VORYNEX_CLOUD_STORE=$STATE/cloud-events.jsonl
VORYNEX_CLOUD_TLS_ARGS=
EOF
  echo "  wrote $SYSCONF/cloud.env"
fi
if [[ ! -f "$SYSCONF/cloud-token.env" ]]; then
  TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  cat > "$SYSCONF/cloud-token.env" <<EOF
# Admin token for the cloud API and dashboard. Rotate by editing this file and
# restarting vorynex-cloud. Agents enrol with it once, then use a host token.
VORYNEX_CLOUD_TOKEN=$TOKEN
EOF
  chmod 0600 "$SYSCONF/cloud-token.env"
  echo "  wrote $SYSCONF/cloud-token.env (admin token generated, 0600)"
fi
if [[ ! -f "$SYSCONF/agent.env" ]]; then
  cat > "$SYSCONF/agent.env" <<EOF
# The workload this host protects. Point these at your application, then:
#   systemctl restart vorynex-agent
VORYNEX_NAME=example
VORYNEX_POLICY=$SYSCONF/policy.yaml
VORYNEX_HEALTH=http://127.0.0.1:3000/health
VORYNEX_COMMAND=/usr/bin/node /srv/example/server.js

# The agent — and therefore the workload it supervises — runs as this user. It
# must be the user your application already runs as, or the app will see the
# wrong file ownership and permissions. Left unset, the agent runs as root.
# VORYNEX_RUN_AS=myapp
EOF
  echo "  wrote $SYSCONF/agent.env (edit it, then enable the service)"
fi

# --- systemd -----------------------------------------------------------------
AGENT_USER="$(sed -n 's/^VORYNEX_RUN_AS=//p' "$SYSCONF/agent.env" 2>/dev/null | tail -1 | tr -d '"'"'"' ')"
if [[ -z "$AGENT_USER" ]]; then
  AGENT_USER="root"
fi
AGENT_GROUP="$(id -gn "$AGENT_USER" 2>/dev/null || echo "$AGENT_USER")"

if [[ -d /run/systemd/system && "$PREFIX" == "/usr/local" ]]; then
  for unit in vorynex-agent vorynex-cloud; do
    if [[ "$unit" == "vorynex-cloud" && "$WITH_CLOUD" != "1" ]]; then continue; fi
    src="$SRC/packaging/systemd/$unit.service"
    [[ -f "$src" ]] || src="$HERE/packaging/systemd/$unit.service"
    if [[ -f "$src" ]]; then
      # The agent unit carries the workload identity; the cloud unit's user is
      # created above and written literally.
      sed -e "s|__VORYNEX_AGENT_USER__|$AGENT_USER|g" \
          -e "s|__VORYNEX_AGENT_GROUP__|$AGENT_GROUP|g" "$src" > "$UNIT_DIR/$unit.service"
      chmod 0644 "$UNIT_DIR/$unit.service"
      echo "  installed $UNIT_DIR/$unit.service"
    fi
  done
  if [[ "$AGENT_USER" == "root" ]]; then
    echo "  note: the agent runs as root (VORYNEX_RUN_AS is not set in agent.env)."
    echo "        The workload inherits that identity. Set VORYNEX_RUN_AS=<app user>"
    echo "        to match how your application already runs."
  else
    echo "  agent runs as $AGENT_USER"
  fi
  systemctl daemon-reload
  if [[ "$ENABLE" == "1" ]]; then
    systemctl enable --now vorynex-cloud 2>/dev/null || true
    echo "  enabled vorynex-cloud"
  fi
else
  echo "  systemd not detected (or custom prefix): units not installed"
fi

cat <<EOF

Vorynex is installed.

  vorynex preflight                    # is this host ready to deploy? (exits non-zero if not)
  vorynex doctor                       # what this host can enforce
  vorynex discover --details           # what is running here
  vorynex connect                      # find the app, learn it, report

  $SYSCONF/agent.env                   # point the service at your workload
  $SYSCONF/cloud-token.env             # cloud admin token (0600)

Nothing is enforcing yet. Vorynex never starts in protect mode: run an observe
window, review the generated policy, then use \`vorynex protect\`.

Uninstall with: install.sh --uninstall   (see docs/INSTALL.md)
EOF