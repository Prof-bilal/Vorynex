# AGENTS.md

Working notes for AI agents in this repository.

## What this is

**Vorynex** — a managed runtime security platform for internet-facing web apps.
It learns what an app needs, enforces a least-privilege runtime boundary, and
contains post-exploitation behaviour. The Go engine lives in `engine/` and
`cmd/`; the Next.js product UI (landing + auth + dashboard) lives in `web/`.

Hard rules: enforcement is **local** and never in the request path; the cloud is
optional. Never claim Vorynex prevents hacking, blocks every zero-day, or
replaces a WAF. Use "contain compromise / reduce blast radius / runtime least
privilege".

## Build and verify

```bash
make build          # go build ./...
make test           # go test ./...
make ci             # vet + build + test
make lab            # Tier 0 security lab (7 scenarios must pass)
make bpf            # build the Tier 1 eBPF object (clang)
make bpf-test       # privileged Tier 1 test (needs root)
cd web && npm run typecheck && npm run build
```

## RepoSpine / CodeAtlas context (code intelligence)

This repo is indexed by **RepoSpine** (`repospine-cli`, binary `atlas`). The
index is local and gitignored.

- **Index:** `.codeatlas/context.db` (386 files, 6,650 symbols at last build).
- **Refresh after edits:** `atlas update --repo "$PWD"` (incremental).
- **Clean rebuild:** `atlas build --repo "$PWD" --tools none` — the `--tools none`
  matters; without it the command blocks on an interactive tool prompt.
- **Search from a shell:** `atlas search "<symbol or phrase>" --repo "$PWD"`
- **MCP server:** registered with Command Code as `atlas` (local scope):
  `cmd mcp add --scope local atlas -- atlas mcp --root "$PWD"`
  Tools appear as `mcp__atlas__*` in new sessions.

Prefer these MCP tools over whole-tree grepping:

| Tool | Use it for |
|---|---|
| `search_symbols` | find a function/type by name (returns target IDs + line refs) |
| `find_relevant_context` | first pass on "how does X work" — ranked, budgeted excerpts |
| `inspect_symbol` | one symbol's declaration, callers, callees, tests |
| `get_dependencies` / `analyze_impact` | who imports what; what a change breaks |
| `read_file_range` | exact code after a search narrows it down |

### Known RepoSpine issue (0.7.0-beta.1)

`atlas doctor` and `atlas context` report the index as permanently **stale**
("261 added") even after a full `atlas build`. The reported set is 100 % non-code
(`.md` 171, `.yaml` 41, `.sh` 14, `.json` 13, `.yml` 10, `.html` 4, `.css` 3;
220 under the `upstream/` submodule), while the index holds the 386 code files
and the manifest claims 499. The counts disagree three ways, so the freshness
check can never pass.

Effect: `atlas context <task>` on the CLI floods its output with the file list
and can truncate the useful context. The **MCP tools are unaffected** — they read
the database directly and return clean packages.

Repro:

```bash
atlas build --repo "$PWD" --tools none
atlas doctor | grep -A1 freshness     # still "stale — 261 added"
```
