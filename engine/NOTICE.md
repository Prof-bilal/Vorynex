# Provenance notice — engine/

The packages under `engine/` are **vendored and adapted** from
[Warden](https://github.com/Prof-bilal/Warden), which is MIT-licensed
(© 2026 Warden contributors). Warden's reusable code lives in `internal/`
packages, which Go does not allow another module to import, so Vorynex vendors
the specific packages it reuses and rewires their import paths.

Vendored from Warden `a7df7c0` (v0.2.0-beta.4-6-ga7df7c0):

| Vorynex package | Warden source | Adaptation |
|---|---|---|
| `engine/audit` | `internal/audit` | state dir `warden/` → `vorynex/` |
| `engine/envfilter` | `internal/envfilter` | unchanged |
| `engine/policy` | `internal/policy` (`policy.go`, `grants.go`) | dropped the Warden-only `agent` concept; `Marshal` moved to `marshal.go` |
| `engine/proxy` | `internal/proxy` | import rewired to `engine/audit` |

The full MIT license text is in [`LICENSE.warden`](LICENSE.warden) and in
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). These packages remain
under the MIT license.

Do not diverge silently: changes that are generally useful should go upstream to
Warden. See [`../docs/OSS_COMMERCIAL_BOUNDARY.md`](../docs/OSS_COMMERCIAL_BOUNDARY.md).
