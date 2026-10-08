# Deterministic local document runtime gates

`run_document_runtime_gates.py` uses already-built, signed app bundles. It
invokes their actual `Contents/MacOS/NativeForensics --document-xpc-probe`
entry point without opening the desktop UI. It does not compile, sign, alter
production entitlements, contact a provider, or add a parser diagnostic RPC.
Preparation of these sources is not proof that the gates have run. Keep the
resulting ignored local JSON reports separate from release package validation.

Prepare four signed app variants from one production build: the production
parser; the normal synthetic worker; the same fixture with
`NF_TEST_HELLO_DELAY_MS=1500`; and the fixture with
`NF_TEST_HELLO_DELAY_MS=500` plus `NF_TEST_BAD_HELLO_VERSION=1`. Replace only
each owned test copy's worker, keep the production broker/client payload, and
sign worker → broker → parent with the exact production policy. The inherited
worker has exactly the two true Boolean sandbox/inherit entitlements. The
broker has exactly the true Boolean sandbox entitlement. Never ship a fixture.

Use the worker compile command in [README.md](README.md), adding these
definitions as individual argv entries. Its outside-canary path and live
loopback port remain compile-time constants owned by the preparation harness.
The preparation wrapper creates a fresh private short directory under
`/private/tmp` for its outside canary and UNIX socket pathname, plus a new
owned private child of the broker's existing sandbox container Data directory.
It pins their directory descriptors and verifies their identities and file
receipts before/after the tests. The UNIX pathname must fit `sun_path[104]`.
A live 127.0.0.1 listener accepts and immediately closes connections without
reading or sending application data, using 100 ms accept timeouts. Any accepted
connection or listener error fails preparation; it cannot support a denial.
These are fixed compiler definitions, never paths accepted by shipping IPC.

For one coordinated preparation-and-run invocation, after the root permits the
isolated compiler window, use:

```sh
python3 Tests/Runtime/prepare_and_run_document_runtime_gates.py \
  --production-app /ABSOLUTE/CURRENT/GATE16/NativeForensics.app \
  --output-parent local/runtime-gates --repeat 64
```

The wrapper serially compiles and signs only owned test copies, holds its
synthetic canary and live listener throughout the gates, and closes/removes
preparation resources in `finally`. It preserves the original hardened-runtime
option and parent identifier/entitlements; extra unhandled signing flags cause
refusal. Default signing is local ad-hoc with timestamps disabled. An explicit
`--sign-identity` can select the coordinator's existing test identity. Changing
fixture signing authority does not establish a final release package pass.
`--retain-apps` retains the runtime copies for inspection, while preparation
copies, canary, helper and listener are still removed/closed. Logs and
`preparation.json` remain in the private local preparation directory; that
receipt points to the separate runtime `summary.json`.
To execute only the four newly added policy/failure recovery scopes against an
already validated production artifact, add `--only-policy-recovery --repeat 2`.
Both receipts record the selected scope and required gate names; `complete`
then describes that selection and `fullSuiteComplete` remains false. This
subset does not supersede retained sustained/cap/cancellation/death receipts.

The isolated fixture compiler inputs are the synthetic worker Objective-C
source, `Sources/NFDecoderIPC/NFDecoderIPC.m` and its public header, Foundation,
Security and `libbsm`. Every variant uses `-fobjc-arc -fblocks -std=gnu11 -arch
arm64 -mmacosx-version-min=14.0`, fixed canary and inherited-control-directory
C strings, and the live integer port. The broker container Data directory
must already exist and belong to the current UID; preparation creates only
its exclusive private test child, and refuses symlinked/canonical-path changes.
Normal has no extra macro; early uses `NF_TEST_HELLO_DELAY_MS=1500`; bad hello
uses delay 500 and `NF_TEST_BAD_HELLO_VERSION=1`. Signing uses the exact current
`script/specs/document_worker_entitlements.plist` and
`script/specs/document_xpc_entitlements.plist`, worker → broker → parent.
Their source hashes and actual signed executable receipts are recorded. No
Swift source or SwiftPM product is rebuilt by this test wrapper.

The optional owned broker-death helper is a separate unsandboxed test program:

```sh
xcrun clang -fobjc-arc -std=gnu11 -arch arm64 -mmacosx-version-min=14.0 \
  Tests/Runtime/NFBrokerDeathProbe.m \
  -framework Foundation -framework Security -lbsm \
  -o OWNED_HELPER
```

Run only after the root coordinator releases the serialized compiler and
performance windows:

```sh
python3 Tests/Runtime/run_document_runtime_gates.py \
  --production-app PREPARED_PRODUCTION.app \
  --fixture-app PREPARED_FIXTURE.app \
  --early-app PREPARED_DELAYED_FIXTURE.app \
  --bad-hello-app PREPARED_BAD_HELLO_FIXTURE.app \
  --death-helper OWNED_HELPER \
  --output-parent local/runtime-gates --repeat 64
```

The wrapper creates one canonical UID-owned private `nf-xpc-runtime-UUID`
directory and signed app copies. It owns every input, marker and host/helper
child. It keeps reports and removes generated inputs and app copies in
`finally`; `--retain-apps` retains copies for diagnosis. Source app bundles
are untouched. It never signals a cached broker or parser PID. A persistent
broker may remain idle under launchd after the host exits; removal of an owned
app copy is file cleanup, not a claim that the broker process was reaped.

| Gate | Oracle and termination evidence |
| --- | --- |
| Boundary | Accepted fixture returns the complete operation inventory; outside read/open/create, IPv4 connect/bind and outside UNIX bind each require actual `EPERM`/`EACCES` at the recorded open/read/connect/bind stage. Missing files, socket creation failure, refused connection and long UNIX paths cannot count as those denials. Owned inherited-container write and own `/usr/bin/true` spawn/reap are positive controls, with independent file receipt and live-listener checks in preparation |
| Crash/malformed/hang recovery | Each runs two sequential attempts in one actual host/client through one retained broker. Fixed one-byte `ONCE` cookies make the first worker crash, return invalid JSON, or hang; errors must be `invalidResponse`, `invalidResponse`, and `timeout` respectively, followed by exact normal text from a fresh worker. Hang uses an explicit 2 s diagnostic timeout; shipping default remains 12 s. Both accepted workers require physical-exit events and independent kernel observers; their parent is the original exact broker birth/path, rechecked live at the recovery worker observation. Production client terminal success follows owned reap |
| Production and fixture sustained jobs | 2...64 sequential analyses in one host/client; exact success count; every accepted fresh worker has one matching physical exit; no overlap or reused parser PID; only one observed broker birth identity; inter-worker gaps recorded |
| Production 32/64/128 MiB | Exactly known ASCII bytes; unchanged SHA/size/inode/mtime/ctime; schema 2 receipt binds actual signed parser and broker; exact 1 MiB text prefix and truncation flag; current 128 MiB input, 2 MiB response and 12 s policy retained |
| Valid near-cap response | Fixture warning gives framed response payload byte count within six bytes of 2 MiB; four-byte length header is separate; control-character text fits the independent 1 MiB cap; options and whole derived-page digests independently recomputed |
| Flood | Deliberately declared 2 MiB + 1 frame fails with `outputLimit`; accepted worker physically exits |
| Early cancellation and recovery in one host | External read-only kqueue observes the exact owned worker birth before valid hello; registered observer is rechecked against UID/path/parent/start timestamp; only then create the absent single-byte marker; `cancel-early-recover` reports `cancelRequested`, first attempt `cancelled` without trusted `started`, then awaits public-client cleanup before the second attempt; independent kernel event proves first-worker exit before the fresh accepted worker; exact original broker PID/birth/path retained |
| Availability from another host | A later host invocation decodes successfully through its independently authenticated application-service broker; this may be a new broker and is not same-process slot recovery |
| Bad hello | External worker birth/exit observation plus actual broker handshake refusal; no document bytes reach a trusted parser; public client fails before `started` |
| Broker death | Exact signed broker has retained task control right, matching kernel audit token, UID, fixed executable, designated requirement, CDHash and minimal CFBoolean entitlement; terminate that task object while the fixture job is accepted; independent broker and worker kqueues must report physical exit; host returns a bounded transport failure |

The worker-birth observer uses SDK-visible `proc_pidpath`, `proc_pidinfo`
`PROC_PIDTBSDINFO` diagnostic metadata and public `EVFILT_PROC/NOTE_EXIT`.
The installed libproc header labels its interfaces private; these local
diagnostic queries are not claimed as a supported App Store API contract.
It does not treat a missing PID,
Security guest disappearance, or NSXPC invalidation as physical-exit evidence.
The broker-death helper first prints an `armed` receipt and retains the verified
Mach task right. Only stdin byte `T` triggers `task_terminate(right)`; EOF or its
30 s trigger deadline releases the right without termination. The send right
addresses the kernel object across PID reuse. If `task_for_pid` is denied, the
gate is **unavailable**, exits 77 overall, and neither changes policy nor falls
back to a PID signal. It does not add `get-task-allow` or request privilege.

The broker-death fixture consumes `NF_TEST_HANG`, and the coordinator waits a
bounded settling period after arming. The final accepted `started` event must
precede the recorded termination trigger, using verified shared macOS
`mach_absolute_time` uptime epochs. The fixture stalls after complete body/hash
receipt. The shipping
contract does not expose a separate parser-body acknowledgement, so this gate
reports accepted decode ownership and the fixture's specified stall behavior.

The exact failed observer-registration branch remains covered by
`DocumentWorkerWireTests.unverifiedRegistrationNeverTreatsSyntheticExitAsProof`
and the owned-process exec/physical-exit test. The malformed-hello runtime gate
proves actual early broker cleanup; it must not be relabelled as a forced
runtime failure of the host's registered observer. No `@testable` observer
bypass is linked into a shipping app.

RSS uses public `PROC_PIDTASKINFO`, sampled every approximately 20 ms and
filtered to exact executable paths in the unique owned app copy. Reports show
per-role and simultaneous-family observed peaks, sample counts, worker/broker
birth identities, input sizes and elapsed time. Short-lived peaks can fall
between samples. Birth identity is checked again after each PID-based RSS
query. Missing observations are `null`, with valid/failed counts per role;
incomplete family sampling passes have a separately labelled known-byte sum.
Family values sum sequential kernel queries in one pass. Required large-input
and near-cap RSS gates are unavailable if any role has no valid observation.
These measurements are not an OS memory cap: App Sandbox
does not impose the derived-output limit on the parser's working set. No
invented RSS ceiling or reduced document limit turns a failure into a pass.
This wrapper closes/reaps its own runtime resources, but does not measure
persistent host/broker descriptor growth; sustained success is not an FD-leak
oracle. Failed copy/input creation is tracked before the operation and all
owned partial artifacts are cleaned in `finally`. Final completion is saved
only after cleanup, with cleanup failures forcing `complete=false`.

Every completed driver invocation writes a bounded `NAME.driver.json` before
semantic assertions and retains that gate in `summary.json` even if an oracle
fails. Raw receipts have `oracleStatus=pending`; the final summary records the
pass/failure. A zero exact-owned broker birth count leaves the same-broker
criterion **unproven**, while multiple actual births fail with their observed
count. Neither missing RSS nor missing path coverage is labelled a restart.
Bounded known-host and exact-owned-path query failures include return values
and errno; PID-inventory errors fail explicitly. No unowned broker path is
accepted to fill a sampling gap. A fresh run with those receipts is necessary
when an older failed run discarded its sampler data.

Re-signing a fixture changes signed executable/resource-seal bytes. The
wrapper retains actual signed SHA/CDHash for every app and compares a separate
`signatureNormalizedPayloadSHA256`: remove only the EOF code-signature blob,
zero its allocation length and normalize `__LINKEDIT` allocation-dependent VM
and file sizes. Every other code/data/load-command/link-edit byte remains in
the digest. Matching this value establishes the retained executable payload,
not byte-identical signed binaries or a final release source-graph receipt.

Boundary evidence must describe actual policy. Existing fixture observations
permit IPv4 socket creation and `/usr/bin/true` execution; outside filesystem
operations and loopback connect/bind were denied. The legacy home-directory
write probe is not proof about every inherited container path. App Sandbox
container writes and execution remain broader than the development Seatbelt
profile; do not claim a universal no-write/no-exec policy.
The boundary gate now executes those operations, but this source change alone
is not fresh runtime evidence. The older current repeat-64 receipt did not
invoke boundary mode. Its ten passed scopes and unavailable broker-death gate
remain qualified as recorded. Broker kernel exit observers in the new recovery
scopes remain registered through both jobs; the host's later exit may end its
application-service broker. Polling timestamps show observation time and do
not establish kernel exit order between two already-dead processes.
