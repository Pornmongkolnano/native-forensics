# Release aggregate-history receipt — 8 October 2026

Five fresh **Release headless** processes passed the exact aggregate-history
oracle. This measures `CaseWorkStore` paging and subsequent per-record
verification. It does not measure the native GUI or execute a provider.

The observed host was arm64, 16 GiB RAM, eight logical CPUs and macOS 27.0.1.
Root recorded Apple M2 / Swift 6.4 for the serialized optimized build. The
checkout was dirty at `b84b19cdc981f14c559770bb9af2555ecc263ad4`; the complete
input graph below identifies the measured local source rather than implying
that the clean commit alone contains these changes.

## Workload and acceptance

One separate generator created an owned synthetic case containing **120
full-retention records**, each with a known **614,400-byte `H` request**. The
requests total 73,728,000 bytes; serialized records total **74,040,012 bytes**,
with a maximum individual record of **617,001 bytes**. The production **1 MiB
record cap and 50-item page cap remain unchanged**.

Generation reached its retained exact-PID `wait4` exit **0** and was excluded
from all scan distributions. Every scan independently returned the exact
newest-first UUID order in **50 + 50 + 20** pages, then loaded all 120 records
to verify full request bytes, request digests and expected summaries. The source
is a 23-byte synthetic marker; filesystem metadata and advisory responses were
constructed locally. A stored provider label does not represent a provider
request, and the workload invokes no filesystem engine or decoder.

All five scans reached natural exit **0**, with confirmed terminal receipts,
no timeout or lifecycle error, and matching stdout / exact `wait4` PIDs. Their
source, manifest, fixture receipt and all 120 record hashes and named identities
match the retained preflight baseline. Independent readback also checked the
current complete 124-file / three-directory fixture namespace, including the
zero-byte `.case.lock`, with unchanged held/named identities and bytes across
the audit. **A pre-scan operational-lock / complete-directory baseline was not
captured**: historical `.case.lock` or whole-case namespace preservation is not
established by current hashes or timestamps. Intermediate driver validations
were executed against the shared baseline but were not separately snapshotted.

The sampler retained **250 valid exact-root observations**: 51, 49, 50, 50 and
50 samples. Failed RSS reads and observed helpers were both zero. Independent
readback recomputed every peak, process inventory, interval summary and compact
summary from the raw receipts. Requested sampling was 10 ms; actual per-run
median intervals were about **16.16–16.17 ms**, and maxima **16.28–16.73 ms**.
Missing or failed samples are rejected rather than omitted from percentiles.

## Observed distributions

Each distribution has **n = 5**. p50 is the median; p95 uses nearest rank and
therefore equals the maximum. Whole-process time includes startup, setup,
paging, individual verification and final integrity checks.

| Scope | p50 | p95 | Range |
|---|---:|---:|---:|
| Whole scan process, seconds | 0.775269 | 0.784277 | 0.773689–0.784277 |
| History paging, seconds | 0.436786 | 0.446198 | 0.436230–0.446198 |
| Per-record verification, seconds | 0.321004 | 0.321455 | 0.319470–0.321455 |
| Sampled probe / aggregate RSS, MiB | 12.281250 | 12.296875 | 12.281250–12.296875 |
| Kernel `wait4` maximum RSS, MiB | 12.375000 | 12.390625 | 12.375000–12.390625 |

Sampled probe and aggregate RSS coincide because every observed sample contains
only the owned probe; sampled helper RSS is zero. RSS includes paging **and**
later verification, so a paging-only peak is unavailable. Sampling can miss
short-lived processes and peaks between observations. Kernel `wait4` usage
covers the exact probe and its accounted children; its maximum is reported
separately and is not an atomic summed process-tree peak. Python driver/auditor
memory is outside these measurements.

Independent preflight reads warm the fixture before every scan. These are
**warm-preverified fresh processes**; caches were not flushed or verified cold.
The historical Debug receipt uses a different build and measurement recipe and
does not support a Debug-to-Release speedup claim. This experiment also provides
no GUI, Autopsy comparison, physical M5, battery, thermal or new performance
budget acceptance.

## Input and artifact binding

All **111 Package/probe/Core/IPC/SQLite/driver inputs** match before compilation,
after compilation and after measurement. Their live paths, complete inventory
and full SHA-256 values were independently rechecked. The build command was
`swift build -c release --product CaseHistoryWorkloadProbe`; the actual canonical
Release executable is 8,224,904 bytes. The **109 common inputs** also match D's
recorded application graph. This binds shared source scope; it does not make the
standalone probe a GUI measurement or give it the app executable's identity.

| Identity | SHA-256 |
|---|---|
| Measured Release history probe | `bee48989b358e0b03adb153f6c914f2174120211b25aa36c4d023c0a040c3499` |
| Complete 111-input history graph | `dffa457359a22d4dec076ef9191365c1b8d80cf8ce6ba64bf389ce6c0d588e3d` |
| Probe Swift recipe | `363bb65ede849f3310bf0337a59a866a3c78d0fb2d260beb12148882308a2c96` |
| Python measurement recipe | `b75b4616a815644ddc37cceb723364ebbda51fb079c93ffbc818c7268dc0ffcd` |
| Terminal benchmark summary | `028570328022e4e5276b8c43c796f3a70d50a73ecf69d4ef3143df2e32b3adb6` |
| Independent read-only audit | `6610d50e2a8d2d0a3864a1567f73328873bf3d978c0b62feb38b5ff8bd9432b2` |
| D application graph compared | `ca4c4b89129ee79549f28b865018afd58511637d6eea06d7ac2c50e32b707325` |
| D application executable independently read | `234ca5186123c9eab82b3d2015307c94770bc2f607535b0ed89891ba92bd84a6` |

The initial measurement invocation used an invalid legacy executable location
and failed the existing-executable precondition before creating its benchmark
destination or launching a probe. Its error log remains separate from the
successful corrected v2 run; it was not counted as a performance sample.

Raw evidence stays below ignored `local/history-release-d-qahpq7l4.noindex/`:
`build-inputs-before.json`, `build-inputs-after.json`,
`inputs-after-measurement.json`, `measurements-v2/` and
`independent-readonly-audit.json`. Initial and corrected invocation logs remain
under ignored `local/roadmap-development/`. No personal source paths or runtime
records are included in this sanitized note. The broader gates in
[the full roadmap audit](GOAL-COMPLETION.md) remain separate.
