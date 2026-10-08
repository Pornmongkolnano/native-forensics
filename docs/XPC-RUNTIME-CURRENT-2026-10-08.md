# Current signed document runtime receipt

The latest **current-D** full run requested all 15 runtime scopes: 14 passed,
and forced broker death remained unavailable. Exit **77**, `complete:false`
and `fullSuiteComplete:false` remain qualified results, with no execution or
cleanup failure. D has its own signed identities and fresh measurements;
the C and earlier A/B receipts below remain separate historical observations.

The preceding **current-C** full run requested all 15 runtime scopes: 14 passed,
and forced broker death remained unavailable. It exited **77**, retaining
`complete:false` and `fullSuiteComplete:false`, with no execution or cleanup
failure. Its distinct signed artifact and measurements are recorded below;
earlier A/B results are not reassigned to C.

The earlier repeat-64 staged four-product app completed ten executed runtime
scopes. Its wrapper exited **77** with `complete:false` because macOS denied the test
helper's `task_for_pid` request for broker death. There was no execution failure
or cleanup failure. This is qualified local runtime evidence, not a notarized
distribution claim or a complete physical broker-death test.

A later boundary/failure-recovery subset completed all four requested scopes
with exit **0**, `complete:true` and `fullSuiteComplete:false`. It used a
different signed host artifact while retaining the same source production
broker and parser worker identities. The two receipts are separate artifact
observations; their results do not form a complete full-suite pass.
The host payload itself changed, so the earlier host's repeat-64, large-input
and early-cancellation results cannot be reassigned to the later host.

The ignored raw receipt is
`local/runtime-gates-current-0.7/nf-xpc-runtime-mkn8od9k/summary.json`.
It records ten `oracleStatus:passed` scopes and one unavailable scope. Every
decoded analysis was independently checked against its source byte count/hash,
actual signed worker/broker SHA and CDHash, options digest, and canonical whole
derived-page digest. Current policy remains 128 MiB input, 2 MiB response, 1 MiB
derived text and the default 12-second deadline.

| Earlier repeat-64 source executable | Signed SHA-256 | CDHash |
| --- | --- | --- |
| Host | `88c17a1fd6a057cf4c2b783cf57a0a228da2f1f2c8d8b5e530929f21984e272b` | `3ea130cc481f45eee038dbf99295f53923538536` |
| Broker | `ddc392df8918527be7c8fb02b4cc1df178f92856f972dca643534cf118eefea1` | `f81b690762b56aef1a5a7573149bfe6c07983eab` |
| Parser worker | `29a3fb99520500dfc35331bae3257ed961c2c239d61100dd7a14b0b59e017d86` | `6893a5283407272dc89ac866b26acf948eaef5c8` |

Fixture copies retain matching signing-normalized host/broker payloads, with
their separately recorded actual signed identities. They replace the parser
with an explicitly synthetic worker. They are not production parser coverage.

| Scope | Observed result |
| --- | --- |
| Production sustained 64 | 64 decoded results, 64 distinct accepted worker PIDs, 64 matching physical exit events, one broker birth in one host; 4347.77 ms total, maximum inter-worker gap 47.97 ms |
| Synthetic worker sustained 64 | 64 decoded results, 64 distinct accepted workers and matching physical exits, one broker birth; 2913.88 ms total, maximum gap 30.53 ms |
| Actual production 32/64/128 MiB | Each decoded the exact first 1 MiB of known printable ASCII, marked truncation, retained full source receipt, and paired accepted worker start/exit |
| Near-cap synthetic response | 2,097,148-byte response payload, plus four-byte framing header; derived text 349,416 bytes, within its separate cap |
| Flood | `outputLimit`, with matching accepted-worker physical exit |
| Same-host early cancellation/recovery | First attempt cancelled before trusted startup; independent worker exit observed 28.68 ms after cancellation request; fresh second accepted worker started 1691.80 ms after that observed exit; decoded successfully through the original broker PID/birth/path and matching parent relation |
| Separate-host availability | New host decoded through its authenticated application-service broker; no same-process recovery claim |
| Bad hello | `invalidResponse` before trusted startup; independent kernel observer confirmed the synthetic worker's physical exit |
| Broker death | Unavailable: `KERN_FAILURE` 5 at `task_for_pid`; the worker subsequently timed out and exited, while no broker physical-exit event or verified task-control right was obtained |

Observed RSS comes from approximately 20 ms sampling passes. All three roles
had valid measurements for each large input. These values are observed peaks,
not hard OS memory bounds; family values sum sequential queries in one pass.

| Production input | Host peak MiB | Broker peak MiB | Worker peak MiB | Family sampling-pass peak MiB | Probe duration ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 MiB | 60.89 | 43.50 | 73.00 | 162.78 | 339.53 |
| 64 MiB | 84.70 | 75.58 | 137.22 | 291.19 | 376.76 |
| 128 MiB | 270.44 | 139.61 | 265.52 | 547.56 | 626.27 |

The sampler saw 40 and 32 short-lived worker births during the two sustained
runs; accepted start/physical-exit lifecycle callbacks covered all 64 in each.
No sampled PID/path/BSD query failure was recorded. Preparation's owned
47-byte synthetic canary passed its post-run receipt check, and the listener
was closed in cleanup. The repeat-64 run did **not** invoke the
filesystem/network boundary mode: its held loopback listener and declared
no-fetch options do not establish fresh network-denial evidence. Earlier
boundary observations remain separate evidence in the older runtime report.

The later subset's ignored raw receipts are
`local/runtime-gates-policy-current-0.7/nf-xpc-preparation-r8_bu7d0/preparation.json`
and `local/runtime-gates-policy-current-0.7/nf-xpc-runtime-nbldex8x/summary.json`.
Their SHA-256 values are respectively
`ca484fd57f22939429fdbef2cbc81713bc8cd7999a49de09b5d79594ad9dee3f`
and `1617aeef34ed32f399877b459e6624175ee306330b466c7d68bf538b4f507253`.
Both record exactly the four selected policy/recovery gates, no failure and no
cleanup failure. The source host SHA-256 is
`2f5f43eb673cde5bfc68b8c725de5b3a3a0850d400f10088d16989213e1ecfa5`,
with CDHash `d412999cb3aeca215e579c1004543f38e098b117`. Source broker and
production worker SHA/CDHash match the earlier table; the fixture replaces
that worker and re-signs the owned copies. Matching signing-normalized
host/broker payloads establishes retained code/data bytes, not identical
signed executable bytes. The actual fixture worker SHA-256 is
`5b1e2aa2eab05de16ce980016d0b33cad831252e3b2acbc000556068d61018f1`,
with CDHash `d69775644bc45f67ef6e3ea67f14f40d22bf5930`.
Across the two source host artifacts, the signing-normalized payload changed
from `e27d43e6f7a770c337f7da1bd40781a1cd82165d6baf48b0d8cad751c9134384`
to `81d93ec6b78083116e997d1fceb11266a9755cfd9590df49be40c63812905a53`;
this difference is not explained by re-signing alone.

| Later selected scope | Observed result |
| --- | --- |
| Boundary | One decoded operation inventory, with accepted-worker start and matching physical exit; outside read/writable-open/create denied with `EPERM` at `open`; IPv4 loopback connect and bind denied with `EPERM` at `connect`/`bind`; outside UNIX bind denied with `EPERM` at `bind` |
| Crash recovery in one host | First attempt `invalidResponse`, next attempt decoded the exact normal fixture text; two distinct workers and both independent kernel exit observations; retained original broker birth/path and live parent relationship; 474.81 ms total |
| Malformed-response recovery in one host | First attempt `invalidResponse`, next attempt decoded exact normal fixture text; same ownership and two-worker physical-exit proof; 500.14 ms total |
| Hang/timeout recovery in one host | First attempt `timeout` under the explicit 2 s diagnostic policy, next attempt decoded exact normal fixture text; same ownership and two-worker physical-exit proof; 2410.10 ms total. The shipping default remains 12 s |

All seven accepted workers across these four scopes had matching host
physical-exit events, without overlapping jobs or reused worker PIDs. Each
negative recovery also retained independent kernel observers for its two
workers and the original broker. Both workers' sampled birth/path identities
matched their registered observers, and the broker was revalidated live as
the fresh recovery worker's parent. The first independently observed worker
exit preceded recovery startup by 57.93 ms, 46.42 ms and 185.11 ms respectively.
Broker exit events were also eventually observed, and each public host
process completed successfully;
polling timestamps do not establish kernel exit order between processes
already dead when polled. No task-control right or forced broker-death test
was obtained by this subset.

The 47-byte canary retained identical device/inode, UID, single link, mode
`0600`, length, modification/change timestamps and SHA-256 before/after.
Its outside private directory had mode `0700`, and the compiled UNIX socket
pathname fit the platform path bound. The live 127.0.0.1 listener used 100 ms
accept timeouts, accepted **zero** connections, recorded no listener errors,
and transferred no application data. These denial results require actual
permission errors at their operation stages; missing-file, refused-connection,
socket-creation and long-path failures were not accepted as substitutes.

The worker successfully wrote the fixed one-byte positive control inside a
new owned `0700` child of the actual broker container Data directory. The
host independently checked its UID, regular-file identity, mode `0600`,
single link, byte count and digest, along with all three one-byte fault cookies.
IPv4 socket creation and spawning/reaping the fixture's own `/usr/bin/true`
child also succeeded. The legacy `NSHomeDirectory()` write probe returned
`EPERM`; that path is distinct from the successful compiled container control.
The observed inherited policy permits container writes and this benign system
execution, so it is broader than the development Seatbelt profile.

Every successful subset analysis retained its full input SHA/length and
actual signed fixture/broker identity, unchanged caps/options digest and
canonical whole-page digest. Read-only recomputation passed. One malformed
scope sample recorded `proc_pidpath` return 0 with `ESRCH` for the known owned
host; the other three scopes recorded no owned query failures, and none
omitted query diagnostics. This does not erase the retained broker/worker
birth and kernel-exit observations. The six fixture/compiler-policy input
hashes also matched the recorded source inputs during this audit. These are
local synthetic policy/lifecycle results, not added production-parser format
coverage or validation of later source changes.

The current-C full run's ignored raw receipts are
`local/runtime-gates-current-c-0.7/nf-xpc-preparation-7pa1mglk/preparation.json`
and `local/runtime-gates-current-c-0.7/nf-xpc-runtime-6ygrs8rj/summary.json`.
Their SHA-256 values are respectively
`a2addd8d2eb7d9d9240b5b1665c0ed6f3d18907f3e657b4a9c26da1dd7275f85`
and `e1534c9021cd1b025338b037e584dc11e360a185819634b1858477af75a6f27b`.
Both select `full-runtime-suite`, retain all 15 required gate names, record
14 `oracleStatus:passed` entries and one `unavailable`, and have empty cleanup
failure lists. This is a new C artifact observation rather than a combination
of the older repeat-64 A and four-scope B receipts.

| Current-C source executable | Signed SHA-256 | CDHash |
| --- | --- | --- |
| Host | `cb6e722363f158e3d2850f8b9dcba141ca8fd61d34744204546a8593ea5649fe` | `52b1bdf8bffbd68f6bca08c127e562aecbeed60f` |
| Broker | `a09ec2022a7d17e1196f90e7f25f6bb038d519284909c864225db91171184509` | `718488101901a928581324c2cc8a2a9f739b804a` |
| Production parser worker | `43eed1ed328db726e9f9498d8d81ee0b292c48598915205582ecb6330f327f80` | `89c0f2f074d751da85b120e323891050e76e689c` |

The C production copy retains those signed identities. Each synthetic worker
copy instead retains matching signing-normalized C host/broker payloads,
with its different signed SHA/CDHash recorded and bound to its analyses.
The normalized source digests are
`772ecbe2a9a4cc607872e7509bfe8f696c0ab624bd2ea4aed8597690687a4994`
for the host and
`0dd6470c76bba0b5516edb18639fdaef7a5f50446ac97213908ac2802b6e2e72`
for the broker. Re-signing their resource seals does not establish identical
signed bytes. The normal fixture worker's signed SHA-256 is
`ca1bb8ebe4da2730603c3d0a6dfcdc9eee42973f3693f0615b14dc4bf7b0fb67`,
with CDHash `16ad9197a9f7551226c27b53a34d392abe101a99`. Its policy/lifecycle
results are explicitly synthetic parser execution.

| Current-C scope | Observed result |
| --- | --- |
| Production sustained 64 | 64 exact decoded results, 64 distinct accepted workers and 64 matching physical-exit lifecycle events, one sampled broker birth in one host; probe 4462.20 ms, driver wall 4956.08 ms, maximum inter-worker gap 136.89 ms |
| Fixture sustained 64 | 64 decoded results, 64 distinct accepted workers and 64 matching physical exits, one sampled broker birth; probe 2952.95 ms, driver wall 2986.88 ms, maximum gap 40.27 ms |
| Boundary | All six outside-canary open/read/create and IPv4/UNIX connect/bind operations returned `EPERM` at their actual open/connect/bind stages; positive container write, IPv4 socket creation and own `/usr/bin/true` spawn/reap succeeded |
| Crash and malformed recovery | Each returned `invalidResponse` then exact normal fixture text in the same host, retaining the original broker birth/path/live parent; both workers had independent kernel exit observations |
| Hang recovery | `timeout` under explicit 2 s diagnostic policy, then exact normal fixture text through the same verified broker; both worker exits independently observed; shipping default remains 12 s |
| Production 32/64/128 MiB | Full known source hash/length matched; each returned the exact 1 MiB prefix with truncation disclosure and matching accepted-worker physical exit |
| Near-cap response and flood | Valid synthetic payload 2,097,148 bytes plus four-byte frame header, with 349,416 bytes derived text; over-cap fixture returned `outputLimit` and physically exited |
| Same-host early cancellation/recovery | First attempt `cancelled` before trusted startup; independent exit observed 21.79 ms after cancellation request, 1682.24 ms before fresh accepted recovery startup; original broker parent retained and second result decoded |
| Separate-host availability | Later invocation decoded through its independently authenticated application-service broker; no same-process recovery claim |
| Bad hello | `invalidResponse` without trusted `started`; independent kernel observer confirmed the rejected worker's exit |
| Broker death | `task-for-pid` helper receipt reported `unavailable`, kernel status 5 (`KERN_FAILURE`); no termination trigger/receipt or control-right proof; fixture eventually timed out and physically exited, while no broker exit event was observed |

All 138 successful C analyses passed independent recomputation of full source
SHA/length, actual signed worker/broker SHA/CDHash, fixed caps/options digest
and canonical whole-page digest. Across all scopes, 143 accepted-worker
starts had 143 matching physical-exit callbacks. Each sustained run covered
all 64 through the public client's registered physical-exit lifecycle;
the approximately 20 ms external sampler caught only 45 production and
38 fixture worker births. Those sampling counts are not 64 independent
external kernel observers. The recovery negatives separately retained
independent observers for both exact workers, matching their birth/path/parent
identities to the original broker, revalidated live during recovery.

The C canary retained its complete 47-byte receipt, including identity,
timestamps, UID, mode `0600`, single link and digest. Its private outside
directory and the compiled broker-container control directory had mode
`0700`; the outside UNIX path fit the platform bound. The live loopback
listener accepted zero connections, recorded zero errors and transferred
no application data. All four one-byte N/C/M/H control/cookie receipts
matched their contents and regular-file ownership/identity checks.
The legacy home-directory write again returned `EPERM`; it is distinct from
the successful inherited-container positive control. These observations
support the tested canary/network operations and the broader inherited
container-write/benign-execution policy, without a universal no-write/no-exec
claim.

All 15 C scopes recorded zero owned/known PID query failures, zero omitted
query diagnostics and zero failed role RSS samples. Large-input RSS remains
an observation rather than an OS cap; family peaks sum sequential queries
within sampling passes and can miss short-lived peaks.

| Current-C production input | Host peak MiB | Broker peak MiB | Worker peak MiB | Family sampling-pass peak MiB | Driver duration ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 MiB | 51.03 | 43.58 | 73.13 | 163.28 | 371.71 |
| 64 MiB | 82.28 | 75.58 | 137.30 | 291.42 | 453.40 |
| 128 MiB | 231.83 | 139.67 | 265.59 | 547.88 | 775.23 |

The unavailable broker-death entry's outer intervention phase label says
`verified-kernel-task-right`; that generic label does not establish acquired
rights. Its authoritative helper receipt reports status `unavailable` and
kernel status 5, with no termination request or result. No private API,
privilege, entitlement change or numeric PID-signal fallback was used.
The runtime oracle suite's 30 pure Python tests passed before the C run; its bounded
partial-line handling does not turn broker death into a pass. Current-C
coverage remains local signed runtime evidence for production text and
synthetic policy/lifecycle scopes. Later Core-D source changes have no
optimized D bundle/runtime proof in this receipt and require fresh gates.
After preserving C's raw receipt, the test-only phase label was corrected for
future runs: `task-control-helper-replied` initially, `verified-kernel-task-right`
only after an armed reply passes exact identity/CDHash validation, and
`task-control-unavailable` for refusal. This label correction changes no rights,
signals, statuses or runtime behavior and does not rerun or relabel C's receipt.

The latest D full runtime receipts are
`local/runtime-gates-current-d-0.7/nf-xpc-preparation-_twucr2e/preparation.json`
and `local/runtime-gates-current-d-0.7/nf-xpc-runtime-yckmd63l/summary.json`.
Their SHA-256 values are respectively
`0c4ce12b7e2d1163b7625c35488c10b8873f52bec00319db84165ca95c23c48c`
and `2339c040b1742891da4d3de3fd8857afe4383ecddfc14695b789a0423dffa479`.
Both select the full suite and retain the exact 15-gate inventory, 14 passes,
one unavailable gate, both completion flags false, and empty cleanup lists.
The source host/broker/worker SHA values also cross-match
`local/roadmap-development/current-d-independent-product-hashes.json`;
that independent four-product inventory has SHA-256
`199fc3884b13b5563d091e31e1bc9f0bbe64f2172c615b289f73c56080a09502`.
The runtime suite does not execute the inventory's separate development CLI.

| Current-D source executable | Signed SHA-256 | CDHash |
| --- | --- | --- |
| Host | `234ca5186123c9eab82b3d2015307c94770bc2f607535b0ed89891ba92bd84a6` | `2de2d3b5c27b6d218a206f79fbf1e76ef1ad3f86` |
| Broker | `15b38557ca90ac3ac51880df91d2f44094cb450e508e034a87373e6d82b34c1b` | `bb3b6675d31c71b6807e5f078be96541f971a6a2` |
| Production parser worker | `a8e02b8288c45d08d0f4a44823a375ea1327b51b021e36484b0e828c76e0e51b` | `32a2aceee244de89277905986f5a4677bca4aaef` |

All three source payloads differ from C. The D source host/broker normalized
digests are respectively
`a5e303ba19263d1f8e8203e0846590e482e26c655682041ff04b50dd0023c263`
and `91c85e02e9dedf4d3c860636850d0c5131f36036069a8a2fb5af39eb9e545d04`.
Every re-signed synthetic copy retains those normalized host/broker payloads;
its actual signed identities are separately bound to its decoded analyses.
The normal fixture worker SHA-256 is
`ea9608fa143c45d85fe9344958e9b40843ef0b18a5d68fe29b5c2cff6f3499d6`,
with CDHash `080830df2d39becceb19ee4c8cc50eefc9b933d9`. This remains
synthetic worker policy/lifecycle evidence rather than production format
coverage from that binary.

| Current-D scope | Observed result |
| --- | --- |
| Production sustained 64 | 64 exact decoded results, 64 distinct accepted workers and 64 paired physical-exit lifecycle events, one sampled broker birth; probe 4152.96 ms, driver wall 4677.84 ms, maximum inter-worker gap 56.60 ms |
| Fixture sustained 64 | 64 decoded results, 64 distinct accepted workers and 64 paired physical exits, one sampled broker birth; probe 2842.70 ms, driver wall 2865.98 ms, maximum gap 47.96 ms |
| Crash/malformed/hang recovery | Exact first errors `invalidResponse`/`invalidResponse`/`timeout`, followed by normal decoded text in the same respective host; both workers independently observed exiting, with original broker birth/path revalidated as their live parent; hang uses explicit 2 s diagnostic policy |
| Early cancellation/recovery | First attempt cancelled before trusted startup; exact worker independently observed exiting 26.25 ms after cancellation request and 1693.45 ms before fresh accepted recovery; original broker parent retained; second result decoded |
| Boundary controls | Six actual-stage `EPERM` denials; inherited-container one-byte write, IPv4 socket creation and own `/usr/bin/true` child succeeded; legacy home-directory write denied, with no universal container-write/exec restriction inferred |
| Input/response caps | Exact 1 MiB truncated prefixes for known full 32/64/128 MiB sources; valid 2,097,148-byte synthetic response payload and 349,416-byte derived text; flood returned `outputLimit` with physical worker exit |
| Separate-host availability and bad hello | Later independent host decoded; malformed hello failed before accepted startup and its worker independently exited |
| Forced broker death | Correct phase `task-control-unavailable`, authoritative `task-for-pid` receipt code 5; no control-right proof, termination trigger or result, and no broker exit event; worker eventually timed out and independently exited |

All 138 successful D analyses independently recomputed their source,
options/whole-page digests and exact signed worker/broker provenance. All
143 accepted-worker starts paired with physical-exit callbacks. The sampler
observed only 39 production and 32 fixture sustained-worker births; the 64
per-run exit proofs are public-client lifecycle observations, not 64 separate
external samplers. The raw Main, driver and final-summary reports match.
No rights, entitlements, privilege, private API or PID-signal fallback made
the unavailable broker-death gate pass.

The D canary retained its complete 47-byte before/after receipt, including
identity, UID, mode `0600`, single link, timestamps and digest. Both private
control directories retained mode `0700`; all N/C/M/H one-byte files passed
ownership/identity/hash checks. The live loopback listener accepted zero
connections, recorded zero errors and transferred no application data.
All six filesystem/network denial records reported `EPERM` at the actual
open/connect/bind stage, with no missing-file, long-path or refused-connection
substitution.

D records **five host-only** `proc_pidpath` return-0/`ESRCH` diagnostics, one
each in malformed recovery, production sustained 64, production 64 MiB,
bad hello and broker death. Their cause is not proved by these untimestamped
query receipts. They establish neither a restart nor missing broker/worker
exit proof. There are no saved broker/worker query failures, omitted query
diagnostics or failed role RSS samples. This differs from C's zero-query-failure
receipt and must not be replaced by C's result.

| Current-D production input | Host peak MiB | Broker peak MiB | Worker peak MiB | Family sampling-pass peak MiB | Driver duration ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 MiB | 52.86 | 43.64 | 73.09 | 163.17 | 420.90 |
| 64 MiB | 82.30 | 75.64 | 139.69 | 293.91 | 521.31 |
| 128 MiB | 230.89 | 141.61 | 265.53 | 547.70 | 871.55 |

These D memory values remain sampled, sequential-query observations rather
than hard limits or a matched performance comparison with A/B/C. The raw
qualified D result remains exit 77 with both completion flags false, even
though all available policy/lifecycle scopes passed. It is local signed
artifact evidence and does not establish notarization, forced broker death
or production PDF/image/Office format coverage beyond the recorded corpus.

Preserve the earlier pre-snapshot v3 receipt at
`local/runtime-gates-pre-snapshot-0.7/nf-xpc-runtime-er9el0zf/summary.json` with
`complete:false`. It failed the comparison of brokers across two different
application hosts. The later same-host diagnostic remedies that test scope;
it does not rewrite the failed receipt or prove that the earlier broker crashed.

A read-only API review found that a task-name right can expose the kernel audit
token but cannot authorize `task_terminate`. Installed `libproc.h` labels its
audit-token signal/terminate interfaces private. [Apple DTS likewise states
that these interfaces have no public compatibility guarantee](https://developer.apple.com/forums/thread/837541).
No private-API, privilege, entitlement, or numeric PID-signal fallback was used.
Physical broker death remains an external unavailable gate under the supported
public-API requirement.
