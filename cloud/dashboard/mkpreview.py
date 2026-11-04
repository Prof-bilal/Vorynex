#!/usr/bin/env python3
"""Generate a self-contained dashboard preview with sample data.

Inlines styles.css and app.js into index.html and injects a demo dataset so the
dashboard can be opened (or published as an artifact) without the Go server.
Regenerate after changing the dashboard: python3 mkpreview.py
"""
import json
import pathlib
from datetime import datetime, timedelta, timezone

here = pathlib.Path(__file__).parent
html = (here / "index.html").read_text()
css = (here / "styles.css").read_text()
js = (here / "app.js").read_text()

now = datetime.now(timezone.utc)


def ev(seq, action, resource, allowed, reason, age_s, etype="file"):
    ts = (now - timedelta(seconds=age_s)).isoformat().replace("+00:00", "Z")
    return {
        "seq": seq,
        "event": {
            "timestamp": ts,
            "type": etype,
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "reason": reason,
        },
    }


def rec(seq, action, resource, allowed, reason, age_s, etype="file"):
    return {"host_id": "host_4f2a9c…", "record": ev(seq, action, resource, allowed, reason, age_s, etype)}


payments = [
    rec(190, "execve", "/bin/bash", False, "-1 EACCES (Permission denied)", 12),
    rec(189, "connect", "169.254.169.254:80", False, "-1 EACCES (Permission denied)", 34, "network"),
    rec(188, "openat", "/app/.env", False, "-1 EACCES (Permission denied)", 51),
    rec(187, "connect", "api.stripe.com:443", True, "", 70, "network"),
    rec(186, "openat", "/app/server.js", True, "", 96),
    rec(185, "openat", "/app/.next/cache/chunk.mo", False, "-1 ENOENT (No such file or directory)", 120),
    rec(184, "openat", "/app/node_modules/next/package.json", True, "", 141),
]
billing = [
    rec(88, "execve", "/usr/bin/curl", False, "-1 EACCES (Permission denied)", 22),
    rec(87, "connect", "api.resend.com:443", True, "", 60, "network"),
    rec(86, "openat", "/app/config.yaml", True, "", 88),
    rec(85, "openat", "/app/secrets/db.pem", False, "-1 EACCES (Permission denied)", 130),
]

demo = {
    "hosts": [
        {"host_id": "host_4f2a9c…", "hostname": "payments", "mode": "protect", "registered_at": (now - timedelta(days=3)).isoformat()},
        {"host_id": "host_8b1e77…", "hostname": "billing", "mode": "observe", "registered_at": (now - timedelta(days=1)).isoformat()},
    ],
    "events": payments + billing,
}

demo["policy"] = {
    "host_id": "host_4f2a9c…",
    "summary": {
        "version": 1,
        "read": ["/app", "/usr/lib/node_modules", "/etc/ssl/certs"],
        "write": ["/app/uploads"],
        "deny": ["/app/.env", "/app/.env.*", "**/*.pem", "**/credentials*"],
        "exec_allow": ["/usr/bin/node", "/usr/local/bin/node"],
        "exec_deny": ["/bin/bash", "/bin/sh", "/usr/bin/curl", "/usr/bin/wget"],
        "network_allow": ["api.stripe.com", "api.resend.com"],
        "protect_secrets": True,
    },
    "blast_radius": {
        "workload": "host_4f2a9c…",
        "mode": "protect",
        "reachable": [
            {"kind": "network", "target": "api.stripe.com", "via": "network.allow", "confidence": "exact"},
            {"kind": "network", "target": "api.resend.com", "via": "network.allow", "confidence": "exact"},
            {"kind": "path", "target": "/app", "via": "filesystem.read", "confidence": "exact"},
            {"kind": "path", "target": "/app/uploads", "via": "filesystem.write", "confidence": "exact"},
            {"kind": "process", "target": "/usr/bin/node", "via": "process.exec.allow", "confidence": "exact"},
        ],
        "contained": [
            {"class": "shell execution", "reason": "no shell in process.exec.allow"},
            {"class": "secret file reads", "reason": "protect_secrets on"},
            {"class": "cloud metadata", "reason": "not in network.allow"},
            {"class": "arbitrary egress", "reason": "network is allowlisted"},
        ],
    },
}

html = html.replace('<link rel="stylesheet" href="styles.css">', "<style>\n" + css + "\n</style>")
html = html.replace(
    '<script src="app.js"></script>',
    "<script>window.__VORYNEX_DEMO__ = " + json.dumps(demo) + ";</script>\n<script>\n" + js + "\n</script>",
)

(here / "preview.html").write_text(html)
print(f"wrote {(here / 'preview.html')} ({len(html)} bytes)")
