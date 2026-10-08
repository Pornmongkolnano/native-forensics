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

## Separate E Saved Comparisons GUI acceptance

The coordinator subsequently used frozen **E0.7.1/build17** to open the original
D full parent answer and digest-only follow-up answer through distinct accessible
buttons in **Saved Comparisons…**. The valid owned clone retained recorded
evidence but had **no filesystem listing**. A separate zero-evidence negative
clone was refused. The history and each loaded answer appeared in captured
Accessibility readbacks, including historical/unverified-source wording; fresh
PDF-span controls remained disabled. This accepts those two local comparison
answer loads and the case-only comparison entrypoint, separately from the D
headless measurement above. No request was sent to a provider in this run.

The retained executed audit reports unchanged original/negative13 files,
valid no-listing clone4 files and source hash. A subsequent read-only inspection
matched all17 named full file hashes and recorded dev/ino/size/mtime/ctime values.
That static byte/identity check is separate from the coordinator's actual GUI
actions. The audit carries no independent executable field: E bundle binding is
coordinator-observed and cross-referenced with the separate [E PDF](PDF-RUNTIME-CURRENT-2026-10-08.md)
and [E index](INDEX-RUNTIME-CURRENT-2026-10-08.md) receipts, rather than reconstructed
from an AX file. Those runtime receipts identify E main SHA-256
`a3fea4ee264e85148a660f0fec42d3739672f6dc584cabaa0be97a68dfa63b74`.

| Retained local artifact | Bytes | SHA-256 |
|---|---:|---|
| Executed history preservation audit | 743 | `24a82c44f7b0760d4b069cacf97a20d42a613ae817fa6d207eee13c70a7afbf0` |
| Distinct history open buttons AX readback | 3,034 | `43cdb7400a3df07f624db56cea132214813595e2a1cd9296d545f3f0a86bdf45` |
| Full parent loaded AX readback | 8,007 | `57942c5d0c39759546afb18827e36a54bd4dcd43166107ce5e8a0092f3f52f01` |
| Digest-only child loaded AX readback | 5,655 | `f938f8ad9d8dde74ad60bba3688452eca689cb366923747f8439358da1022012` |

Raw artifacts stay in ignored `local/gui-e-history-oo4zf40t.noindex/`; personal
paths and saved question/answer content are not published here. Root then observed normal CUA Cmd-Q and absence of the exact checkout
application process. The post-quit audit reports17 file records spanning four
case namespaces and the source with unchanged full hashes/dev/ino/size/mtime/ctime.
Its396-byte receipt SHA-256 is
`3235dd256df7c6c5013c0d157eea5f25cd4775df431f93efbc58ca97956c24ad`;
the7,316-byte pre-quit AX capture SHA-256 is
`6f01ca10c66a44a37e6f0ebe16ab3814f3c4adcdc03850abe7d4f7a89711af8d`.
This is a normal-input/process-absence observation, without an exact-child
wait4 receipt or a subsequent E reopen acceptance. The stale-index
close attempt remains retained. The recorded screen-capture error
`SCStreamError -3812` recovered after a Finder context switch; this observer
failure is not app-crash/data-loss evidence and does not erase the earlier
frozen-D no-action/entrypoint observations.

**Fresh citation verified=false, new provider request=false and source
reachability not tested offline=true.** No source verification occurs merely
because a historical answer is readable. Changed-source refusal, fresh cited
content after restart and a truly unavailable-source GUI run remain open. This
entrypoint browses `MultiEvidenceComparison` receipts, not single-file
`AnalysisRecord` history; it does not make the original headless120-record case
reachable in the GUI without a genuine selected listing/file.

A new opt-in probe mode can populate a disposable owned case clone using its
normal saved listing and actual selected file, with120 explicitly synthetic
full-request analysis records. It is a **different GUI workload**, without a
provider request. No executed population receipt, GUI50+50+20 paging/detail
receipt, current full-app/helper aggregate RSS distribution or GUI120 memory
acceptance is included in this checkpoint. The later F Native Release log
records281 tests/33 suites PASS6.692s, with terminal0 separately confirmed by
Root and no serialized shell-exit status in the log. The separate opt-in probe
admission gate passed5 methods/one suite in0.701s, including12 malformed-argument
cases. Its initial guessed nonexistent executable path produced16 retained
issues before child launch; a later initial relative-path population invocation
was refused. None is a generated positive GUI120 receipt. Unit history/citation
scopes are not F app-build or actual GUI citation/memory evidence. Preserve the measured D probe/111-input graph and its old fixture
rather than transferring D timings or missing historical lock coverage to E/F.
