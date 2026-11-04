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

demo["sbom"] = {
    "host_id": "host_4f2a9c…",
    "sbom": {
        "workload": "payments",
        "scanned_at": (now - timedelta(minutes=8)).isoformat(),
        "packages": 412,
        "entries": [
            {"name": "next", "version": "15.0.2", "advisory_id": "GHSA-7gfc-8cq8-jh5f", "aliases": ["CVE-2025-55182"],
             "summary": "Server-side request forgery in server actions", "fixed": "15.0.4", "known_exploited": True,
             "cvss": {"score": 9.8, "severity": "CRITICAL", "version": "3.1"}},
            {"name": "express", "version": "4.18.2", "advisory_id": "GHSA-rv95-896h-c2vc", "aliases": ["CVE-2024-29041"],
             "summary": "Open redirect in malformed URLs", "fixed": "4.19.2", "known_exploited": False,
             "cvss": {"score": 6.1, "severity": "MEDIUM", "version": "3.1"}},
            {"name": "lodash", "version": "4.17.21", "advisory_id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"],
             "summary": "Command injection via template", "fixed": "4.17.21", "known_exploited": False,
             "cvss": {"score": 7.2, "severity": "HIGH", "version": "3.1"}},
            {"name": "body-parser", "version": "1.20.1", "advisory_id": "GHSA-qwcr-r2fm-qrc7", "aliases": ["CVE-2024-45590"],
             "summary": "Denial of service when urlencoding is enabled", "fixed": "1.20.3", "known_exploited": False,
             "cvss": {"score": 7.5, "severity": "HIGH", "version": "3.1"}},
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
