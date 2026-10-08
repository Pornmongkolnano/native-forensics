# Matched release document workload — 8 October 2026

The measured 0.7 development bundle completed the same bounded ASCII document
analysis faster and with lower sampled worker RSS than the earlier 0.7 bundle.
All **36 measured slots** passed independent output, provenance, source-integrity,
request-family and physical-exit checks. These results compare two complete
release bundles on this host. Other Core, broker and application changes are
included, so the measurements do not isolate the ASCII decoder change.

This series is separate from the archived 0.6 development Seatbelt and mixed
filesystem/index workloads in [LARGE-WORKLOADS.md](LARGE-WORKLOADS.md). It measures
the bundled document XPC diagnostic, rather than Autopsy, a GUI interaction or
physical M5 hardware.

## Measured artifacts and later rebuild

Both measured bundles report **0.7.0 / build 16**, minimum macOS 14.0 and sealed
`release` source receipts. Their binary hashes distinguish them:

| Signed executable | Earlier 0.7 bundle | Measured later 0.7 bundle |
|---|---|---|
| Main application | `41b5e9a6ffaea993b85046c46ed5557e43274bda2e7b80a1dc250449499d7885` | `88c17a1fd6a057cf4c2b783cf57a0a228da2f1f2c8d8b5e530929f21984e272b` |
| XPC broker | `dce1a12a33ce66081008dbb2a7673307c8a998fa438d1fa6436926750e1b4c73` | `ddc392df8918527be7c8fb02b4cc1df178f92856f972dca643534cf118eefea1` |
| Parser worker | `ec3e442961e4c4a961ad5e54f0de81ed3965347bb965ee2e605886501bc66dd1` | `29a3fb99520500dfc35331bae3257ed961c2c239d61100dd7a14b0b59e017d86` |
| Standalone decoder, not invoked in this series | `99a9ee59b1de3d06d36a3b90c2b7e47463bef7dbbb98b404e6e3d90dcaad3a4c` | `43f8f25ea3b482554869b41d1966db6b70208e601a03d0912025cf4cc53b8fe9` |

The required canonical build/launch verification subsequently rebuilt and signed
the application. That later GUI artifact has main SHA-256
`2f5f43eb673cde5bfc68b8c725de5b3a3a0850d400f10088d16989213e1ecfa5`.
Its four source graphs and decoder/broker/worker bytes remain equal to the
measured later bundle, but its main executable bytes differ. This benchmark is
bound to the retained **`88c17a1f…`** main executable; it does not establish exact
timings for the subsequent **`2f5f43eb…`** GUI artifact. The raw benchmark copies
and receipts were preserved.

The sealed source graphs changed across the measured comparison:

| Product | Changed, added or removed source/build inputs |
|---|---:|
| Main application | 23 |
| XPC broker | 14 |
| Parser worker | 16 |
| Standalone decoder | 16 |

The worker changes include both ASCII decoder files and 14 shared Core inputs.
The source graphs therefore reject an isolated ASCII-only causal claim.

## Workload and verification

Hardware was **Apple M2 / Mac14,2, arm64, 16 GiB RAM, 8 logical CPUs** on
**macOS 27.0.1, build 26A434**. The harness ran six paired rounds for each size,
alternating earlier→later and later→earlier. It rotated the 32/64/128 MiB order
between rounds, giving three pairs in each ordering per size. Each slot launched
a fresh host process and its fresh parser worker. A persistent broker could be
reused; the accepted worker's actual parent broker birth was recorded for each
request.

The three immutable synthetic files share the existing independent recipe:
repeat `NF_RUNTIME_ASCII_ORACLE_20261008\n` to exactly 1 MiB, then repeat that
complete chunk to the selected source size. Every earlier/later pair used the
same file, inode, byte count, timestamps and full source hash:

| Input | Full source SHA-256 |
|---|---|
| 32 MiB | `4d14ca397f4b671663f9cd267f41257e533b5dc01e7af6e8aee66f9409c7d5c4` |
| 64 MiB | `97efca53e7886a7ba60f85a8b4239f492801a8f7fc116a9a6f8d8caa994ca1a5` |
| 128 MiB | `94f69cd404f13a809d67b5a0b873e80641d82d78de4fbde506e112995f310198` |

Every result had one UTF-8 `.document` page, reference `Text document`, exactly
the first **1 MiB** of source text and `isTruncated=true`. The original size-limit
warning and `Text.Encoding=UTF-8` metadata were preserved. Canonical derived-page
SHA-256 was identical in all slots:
`4041c492c18318b210f80c8a22abec47ef9bf4bf17e2dc8236deffc899c2ca56`.

The complete interpretation and provenance matched within every pair, excluding
only each bundle's worker/broker executable SHA and signing CDHash fields. Those
four identity fields were independently checked against that bundle's recorded
signed executables. Contract **2.1.0**, App Sandbox XPC isolation, **12-second**
timeout, **128 MiB** input cap, **1 MiB** text cap and **2 MiB** response cap stayed
equal. Options SHA-256 remained
`b3c2e4c7537017cab4b8431d33ee15c4745c03c54680b55736031c492f75b909`.

All accepted workers had matching start/exit lifecycle receipts plus independently
registered kernel `NOTE_EXIT` observations. All 36 host processes exited normally
with status zero. The physical-observer uptime records when Python polled the
event, rather than an exact kernel exit timestamp.

## Timing results

Each table cell is **p50 / p95**, using nearest rank independently for the six
samples of each variant and size. With `n=6`, p50 is the third sorted sample and
p95 is the maximum. All samples, including initial startup outliers, remain in
the distribution; no successful slot was dropped or retried.

The external host interval starts immediately before its direct launch and ends
at the blocking waiter's natural-exit observation. It includes launch/startup and
excludes subsequent source hashing, JSON parsing and audit work. The application
interval brackets document analysis and cleanup/drain; it is not parser-only CPU
time.

| Input | Earlier host exit, s | Later host exit, s | Earlier analysis/drain, s | Later analysis/drain, s |
|---|---:|---:|---:|---:|
| 32 MiB | 0.850 / 1.401 | 0.326 / 0.806 | 0.836 / 0.847 | 0.313 / 0.327 |
| 64 MiB | 1.463 / 1.489 | 0.451 / 0.467 | 1.448 / 1.475 | 0.437 / 0.454 |
| 128 MiB | 2.756 / 2.814 | 0.709 / 0.725 | 2.740 / 2.797 | 0.693 / 0.709 |

The retained paired host-duration ratios, later/earlier, have nearest-rank p50
values **0.3836, 0.3083 and 0.2570** for 32/64/128 MiB respectively. These are
statistics of individual paired ratios; a ratio of the two variant p50 values is
a different calculation.

## Sampled memory results

Public `libproc` sampled RSS every approximately **20 ms**. Role maxima include
only the current host birth, accepted worker birth and that worker's parent
broker birth. The family maximum sums one valid sample of each of those three
roles in the same sampling pass; sequential kernel queries are not an atomic
measurement. Neither metric is an operating-system true peak or a hard memory
limit. The sum of three independently selected role maxima is not used as the
family metric.

Each cell remains **p50 / p95**, in **MiB** (`1 MiB = 1,048,576 bytes`):

| Input | Earlier worker | Later worker | Earlier family row sum | Later family row sum |
|---|---:|---:|---:|---:|
| 32 MiB | 105.20 / 105.22 | 73.05 / 78.91 | 194.98 / 195.41 | 163.09 / 168.89 |
| 64 MiB | 201.38 / 201.38 | 137.20 / 137.22 | 355.17 / 355.30 | 291.33 / 291.39 |
| 128 MiB | 393.67 / 397.41 | 265.52 / 267.08 | 675.58 / 679.39 | 547.66 / 549.09 |

Computing reduction as `1 - p50(later/earlier)` from the paired worker-RSS
ratios gives **30.6%, 31.9% and 32.6%**. The same calculation for family-row
sums gives **16.4%, 18.0% and 18.9%**, respectively. This transformation of
the ratio statistic is distinct from separately ranking per-pair reductions.
Other process roles do not show a uniform reduction:

| Input | Earlier host | Later host | Earlier broker | Later broker |
|---|---:|---:|---:|---:|
| 32 MiB | 50.64 / 76.27 | 50.14 / 52.14 | 43.41 / 43.42 | 43.58 / 43.59 |
| 64 MiB | 82.19 / 120.48 | 82.28 / 142.58 | 75.42 / 77.39 | 75.58 / 75.59 |
| 128 MiB | 159.05 / 261.64 | 146.25 / 148.97 | 139.47 / 141.44 | 139.58 / 141.55 |

In particular, the later 64 MiB host RSS p95 was higher. Its host maximum need
not occur in the pass containing the family maximum. Broker RSS was broadly
unchanged. The measurements support the listed workload-specific observations,
without establishing lower memory usage in every process or workload.

## Retained evidence and limits

Local evidence is retained below ignored
`local/matched-release-ascii/run-cfc8980e-cea3-47ba-863c-036709b2ef2a/`:

- `summary.json`, SHA-256
  `b8ed085bd0a137ed39e76fbd0555578b0502b98e53ece67d801492fe227e7e65`;
- 36 complete host JSON reports, bounded stderr files and raw driver receipts;
- the unchanged three read-only source files and two immutable measured app
  copies;
- exact per-slot RSS samples, request-family identities, kernel exit receipts,
  paired deltas/ratios and six-sample percentile inputs.

Raw driver snapshots deliberately retain `oracleStatus=pending`: they were
written before semantic assertions. Successful slot and pair decisions are in
the terminal summary. Independent audits rechecked the full input recipe and
hashes, every output/provenance receipt, raw-report digests, request-family RSS
statistics, all paired ratios and percentile calculations. The four harness/tool
hashes remained equal to the recorded values.

The inputs occupy **234,881,024 bytes**. The complete measured artifact, including
its summary, occupies **360,488,238 bytes**, within the **536,870,912-byte**
artifact budget. The source/app/tool identities were checked by the harness at
both boundaries. The later canonical application rebuild is recorded separately
above; it does not replace the retained measured copy.

The operating-system filesystem caches were not flushed. Thermal state, energy
use and ordinary background load were not independently measured. This ASCII
series does not establish performance for Unicode or inferred legacy text, PDF,
Office, filesystem ingestion, extraction, content indexing, GUI rendering or
Autopsy. The separate history-memory diagnostic remains explicitly scoped to
its previously measured DEBUG standalone executable; no release-history result
is inferred from this document workload.
