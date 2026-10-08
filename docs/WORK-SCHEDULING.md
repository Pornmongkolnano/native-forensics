# Application work admission and energy policy

One `ForensicWorkScheduler.shared` admits one heavy forensic workflow across all
workbench windows. Per-window `isBusy` alone does not bound multiple independent
windows. The scheduler queue accepts at most 32 waiting workflows and contains
only typed work kinds, UUIDs, monotonic enqueue times and continuations. Full
queues and application termination return explicit errors before new work starts.

The single active workflow is an overlap bound, **not a measured RSS ceiling**.
The 0.6 frozen [full-pipeline workload](LARGE-WORKLOADS.md) measured sequential
work on one M2/16 GiB host: warm p50/p95 18.117/18.986 seconds and sampled owned
aggregate RSS p95 91.08 MiB for its particular corpus. It did not fill all
production aggregate caps, measure the new XPC backend, or compare concurrent
whole pipelines. Helper-only 1/2/4 results cannot select a whole-app parallelism
policy. No two-worker preference or M5/battery-life claim follows from those
measurements.

## Ownership and cancellation

`acquire(kind)` is FIFO. Canceling a queued task removes it and throws before its
operation starts. A cancellation racing with admission releases an unused slot.
An active owner's cancellation cannot release the slot: the owner must finish
its helper termination, owned scratch cleanup and publication drainage first.
`release()` is idempotent and returns true only for the matching active permit's
first release. Closing one window cancels its own task; only application
termination closes the shared scheduler and rejects all queued owners.

Prefer `withPermit(kind) { admission in ... }` around the complete owner
workflow. This awaits release on return and throw, without a post-operation
cancellation check that could mislabel an already committed result. Existing
store checks remain responsible for truthful cancellation/publication status.
The operation must await all of its owned children before returning.

`scheduler.run(kind) { admission in ... }` runs an entire non-UI workflow in an
owned detached task at the sampled requested priority. `permit.run { ... }`
does the same for one heavy stage while the owner retains the admission through
later writers and final cleanup. Both forward cancellation and await the worker;
neither substitutes cancellation for drainage. Task-local ownership rejects a
nested acquisition on the same scheduler instead of deadlocking. Acquire once
at an outer user-workflow boundary, rather than inside every nested hash,
extraction or decoder call.

For an explicitly begun atomic publisher, `permit.runToCompletion { ... }`
checks parent cancellation immediately before worker construction, with no
intervening suspension, then awaits the publisher without forwarding later
parent cancellation. Its worker receives the same requested priority and task
locals. The owner retains the permit through any subsequent cleanup and reports
the actual publication outcome. This API is only for atomic commit boundaries;
inspection, decoding, extraction and other cancellable work retain ordinary
`run` semantics.

Wait for previous superseded owner tasks **before acquiring** the next permit.
Waiting for a prior queued job while holding the only admission would deadlock.
Saved historical reads/searches may use their own bounded tasks; they must not
silently spawn a new live engine/APFS/decoder workflow outside admission.

## Password-bearing APFS operations

`acquireImmediately(.apfsRead)` never queues and never bypasses existing queued
work. Freeze case/evidence/result/entry identity, obtain the immediate permit,
revalidate those identities, then copy SecureField text into single-use
`APFSPassphrase` data. Transfer the permit to the APFS owner only if that owner
accepts the operation; otherwise release it. The accepting owner releases after
live read/export, provenance/cache publication and mount/scratch drainage.

An async caller can retain its captures while suspended even if the scheduler
does not store credentials itself. Therefore do not obtain password Data first,
then call the FIFO acquisition API. The existing SecureField can retain its
user-entered text while another window is working; no additional password-bearing
job is queued. Never serialize the credentials into scheduling receipts.

## Public power and thermal inputs

`WorkEnergyMonitor` samples public `ProcessInfo` thermal/Low Power Mode values and
IOKit's current providing power-source type. It reads thermal state before
registering for its notification, as [Foundation requires](https://developer.apple.com/documentation/foundation/processinfo/thermalstatedidchangenotification).
Power-state notifications concern Low Power Mode; periodic IOKit polling also
observes AC/battery transitions. The polling interval is 30 seconds with a
5-second tolerance; main-run-loop scheduling can add delay. Unknown readings
are shown as unavailable and choose the conservative requested priority.

The explicit settings are **Automatic** and **Conserve energy**. Automatic
requests user-initiated priority only for external power, nominal thermals and
Low Power Mode disabled. Battery, unknown power/thermals, Low Power Mode and
fair/serious/critical thermals request utility priority. Conserve energy always
requests utility priority. Every policy retains one active heavy workflow and
all existing input/output/coverage limits.

Context changes apply only when the next workflow is admitted. They do not
signal, cancel or alter the active owner's deadline, source verification,
cleanup, or atomic save. Task priority is a request: Swift awaiting tasks and
the operating system can raise effective priority. No measured CPU QoS,
temperature improvement or energy savings is claimed from the policy alone.

`ForensicWorkExecutionContext.requestedTaskPriority` is read before creating an
inner detached task, which does not inherit task locals. `BlockingWork.run`
selects a fixed utility or user-initiated dispatch queue before suspension.
Unscheduled CLI/development callers preserve the previous user-initiated default.
Tests observe the actual queue marker from inside dispatched work, rather than
equating `Task.currentPriority` with a non-escalating kernel QoS value.

## Integration boundaries

The scheduler implementation and tests are additive. Integration must wrap the
whole owner task at the following entry points, with the permit held through
the final writer and any stale-selection/closing cleanup:

- `WorkspaceStore.inspectImage` and `WorkspaceFilesystemStore` analysis/extraction.
- `FilesystemDocumentPreviewStore` and transactional `FilesystemBatchExportStore`.
- Content-index rebuild/update, timeline analysis/export and integrity audit.
- Recovery/optical inspect, preview and export/report owners.
- Single-file/two-file assistant local preparation and fresh citation reads.
- APFS live inspect/preview/export via immediate, credential-free admission.

Per-store source integration and actual multi-window runtime evidence are
separate gates. New scheduler tests do not certify every listed store has been
wired. Case publication receipts, partial coverage, and source hashes remain
owned by the existing services and are not replaced by a scheduling receipt.

## GUI timing evidence

Search algorithm timing, main-actor handler receipt and actual table presentation
are distinct measurements. For a synthetic GUI trial, record a fresh local
`NSEvent.timestamp`, handler receipt, generation scheduling, worker start/end,
guarded row publication and cancellation/supersession outcome without logging
queries, filenames or source data. Bound diagnostic trial storage to 256 records.

An independent ScreenCaptureKit display stream can pixel-match the actual
expected query, row/count and pagination state. Accept complete screen frames
and read [`SCStreamFrameInfo.displayTime`](https://developer.apple.com/documentation/screencapturekit/scstreamframeinfo/displaytime),
which Apple defines as the time WindowServer displays the frame. The installed
SDK defines that value as Mach absolute ticks; convert with `mach_timebase_info`
and validate calibration against [`NSEvent.timestamp`](https://developer.apple.com/documentation/appkit/nsevent/timestamp)
(seconds since system startup) and [`CACurrentMediaTime`](https://developer.apple.com/documentation/quartzcore/cacurrentmediatime()).
Never subtract raw ticks, nanoseconds, wall-clock dates and seconds directly.

Keep the preceding nonmatching/first matching frame times, expected output
identity, ROI hashes, capture gaps and input mode. A first matching captured
frame bounds the earliest presentation from above unless all intervening frames
are demonstrably captured. It is WindowServer presentation evidence, not panel
photon latency. Controlled paste/key events can establish an input event; an
accessibility value assignment may only establish binding-receipt time.
`NSApplication.currentEvent` is the last dequeued event and may be stale.

`CADisplayLink` ticks, SwiftUI body/onChange, view drawing/layout,
`setNeedsDisplay` and transaction completion do not prove a particular table
state reached the display. CUA screenshot/AX correctness is useful visual
confirmation; its tool roundtrip is not an app latency sample. Runtime capture
and matched p50/p95 GUI measurements remain required.

## Validation status

The added independent tests cover FIFO multi-window ownership, queued/head
cancellation, active drain before release, throwing release, bounded queue,
application close, immediate credential admission, nested rejection, exact
power/thermal decision cases and requested-priority propagation. They have not
been compiled/run by the scheduler agent; the root owns serialized SwiftPM
verification and final bundle/runtime measurements. No source limits, hash
checks, expected bytes or partial-status semantics were reduced.
