#!/bin/sh
# Container entrypoint: turn the environment into flags, then hand over.
#
# This exists instead of an inline `sh -c` for one concrete reason: with
# `ENTRYPOINT ["/bin/sh","-c","..."]`, the first container argument becomes the
# shell's $0 rather than part of "$@", so `docker run <image> --version` would
# silently lose its argument and start the server. As a script, every container
# argument lands in "$@".
set -eu

set -- \
  --addr "${VORYNEX_CLOUD_ADDR:-0.0.0.0:8787}" \
  --store "${VORYNEX_CLOUD_STORE:-/var/lib/vorynex/cloud-events.jsonl}" \
  --dashboard "${VORYNEX_CLOUD_DASHBOARD:-/usr/share/vorynex/dashboard}" \
  "$@"

if [ -n "${VORYNEX_CLOUD_TOKEN:-}" ]; then
  set -- --token "$VORYNEX_CLOUD_TOKEN" "$@"
fi
if [ -n "${VORYNEX_CLOUD_TLS_CERT:-}" ] && [ -n "${VORYNEX_CLOUD_TLS_KEY:-}" ]; then
  set -- --tls-cert "$VORYNEX_CLOUD_TLS_CERT" --tls-key "$VORYNEX_CLOUD_TLS_KEY" "$@"
fi

exec /usr/local/bin/vorynex-cloud "$@"
