# Bounded UI interaction timing

`NF_UI_TIMING=1` opts a local diagnostic launch into `UIInteractionTiming.shared`.
Normal launches allocate no trace and collect no trial receipts. This instrumentation
measures binding receipt through row publication. The controlled filesystem search
field can also attach a qualified native input receipt. Neither receipt alone
measures when a SwiftUI frame becomes visible.

## Call-site contract

`begin()` returns an optional numeric trial ID and records `bindingReceived`.
Keep that ID with the search generation; never substitute the current generation's
ID inside an old callback. Record `scheduled`, `workerStarted`, `workerFinished`,
then `rowsPublished`. A synchronous clear or unrestricted result may instead move
directly from `bindingReceived` to `rowsPublished`. Finish `published` only after
that publication. Finish `cancelled`, `superseded`, or `failed` before publication
when the corresponding generation ends without publishing.

Every stage accepts a finite, nonnegative uptime timestamp at least as large as
the preceding timestamp for that trial. A duplicate, a skipped worker stage,
backward time, unknown or evicted ID, or attempted terminal rewrite is rejected.
The immutable snapshot contains at most 256 trials, each with at most eight stage
samples. The implementation currently has five possible stages. IDs are never
recycled; oldest receipts are evicted when capacity is reached. Rejection and
eviction counters saturate rather than overflow. An active trial may be evicted;
its later callbacks are rejected and cannot modify a newer trial.

`snapshot()` returns value copies under the same lock used for mutations. Worker
callbacks record directly without scheduling an extra MainActor task. Trace
locking and allocation contribute some measurement overhead. Retained receipts
contain numeric IDs, uptime values, fixed stage/outcome names, and optional numeric
event metadata. They contain no query text, paths, hashes, raw key codes, document
content, or credentials. The recorder performs no logging, capture, input
monitoring, or automated upload.

`writeRequestedReport()` is an explicit local shutdown diagnostic. It returns
`nil` unless timing is enabled and `NF_UI_TIMING_OUTPUT` is provided. That output
must be an absolute canonical path to a fresh `.nativeforensics-ui-timing-*.json`
file inside an existing directory owned by the current UID with exact `0700`
permissions. The identifier permits only ASCII letters, digits, dash and underscore;
the whole filename is limited to 128 bytes. Directory components are opened with
no-follow descriptors, and the final output is created exclusively with `0600`
permissions. The bounded snapshot is encoded once, limited to 1 MiB, then flushed
and verified using the created descriptor. Existing files and symlinks cannot be
overwritten. Policy and write failures return `false` without logging the path.
Normal launches and launches without an explicit output destination perform no
write. Call this API after app-owned workers drain. A directory-flush failure may
leave the complete new diagnostic and returns uncertainty; it is not a case record.

`UIInteractionTrial.bindingToPublicationSeconds` is present only for a published
trial, and excludes time spent after `rowsPublished`. Cancelled and superseded
trials are not successful latency samples. `completedUptimeSeconds` is the terminal
receipt time, which may follow publication by a small bookkeeping interval. The
computed duration is available from a snapshot but is not a separately encoded
field; derive it from its recorded stage times when exporting JSON.

The synthetic report tests create fresh UUID directories under the repository's
ignored `local/` directory, with ownership and exact `0700` permissions checked
through independent no-follow directory descriptors. This avoids the macOS
temporary-directory alias: Foundation may report `/var` after path resolution,
while the production no-follow component gate rejects that symlink. The positive
test independently reopens the created report with `O_RDONLY | O_NOFOLLOW`, checks
the regular-file type, current UID and exact `0600` permissions with `fstat`, and
decodes the receipt through that descriptor. Production path policy is unchanged.

## Clock and input boundaries

The wrapper uses [CACurrentMediaTime](https://developer.apple.com/documentation/quartzcore/cacurrentmediatime()),
which converts `mach_absolute_time` to seconds. Default trials begin at binding
receipt. An independently controlled input observer may explicitly supply
`inputEventUptimeSeconds` after checking event freshness, trial association and
clock alignment; the model can only validate the numeric range and ordering.
[NSEvent.timestamp](https://developer.apple.com/documentation/appkit/nsevent/timestamp)
is startup-relative seconds. Do not infer a fresh input from
[NSApplication.currentEvent](https://developer.apple.com/documentation/appkit/nsapplication/currentevent),
which reports the last event retrieved from the event queue. Accessibility value
assignment may have no matching NSEvent. Input dispatch mode must be recorded by
the external test receipt before claiming input-to-publication latency.

The controlled filesystem search field observes its own field editor only when
timing is enabled. It preserves superclass event handling and the existing search
binding and scheduling. After that dispatch returns, it attaches a one-use numeric
receipt only when one owned control notification changed exactly one search trial.
The actual NSEvent and CGEvent timestamps must agree, with the dispatch sample
inside a contemporaneous Mach/CA clock bracket. Focus/owner mismatch, stale or
future events, paste, marked text, nested/multiple notifications and programmatic
changes do not qualify. Sleep or wake invalidates qualification and records a
rejection. Accepted and rejected associations remain bounded numeric diagnostics;
query characters and key codes are not recorded.

## Separate display gate

Actual presentation requires a separate content-correlated capture receipt.
[ScreenCaptureKit displayTime](https://developer.apple.com/documentation/screencapturekit/scstreamframeinfo/displaytime)
reports when WindowServer displays the captured frame; its attached value is Mach
absolute ticks, requiring timebase conversion before comparison with seconds.
Accept complete frame buffers and match the actual expected query and table pixels,
not only a separately painted marker. Retain the last nonmatching and first
matching frame timestamps, content proof, capture interval and observed gaps.
Missing intermediate frames make the first matching captured presentation an upper
bound on the earliest matching presentation. WindowServer timestamps do not measure
physical display photons.

The core ScreenCaptureKit APIs and frame metadata exist from macOS 12.3 and fit the
app's macOS 14 minimum. The current [Apple capture sample](https://developer.apple.com/documentation/screencapturekit/capturing-screen-content-in-macos)
also includes newer features and requires macOS 15; do not adopt its newer additions
without availability checks. A display-link tick, SwiftUI body evaluation,
AppKit drawing callback, or Core Animation transaction completion does not identify
the requested table state as presented. CUA screenshot and accessibility checks
confirm sampled visible state; tool roundtrip duration is not app latency.

## Standalone owned-window capture helper

`Tests/Runtime/GUIFrameCapture.swift` is outside SwiftPM targets. It is prepared
for a separately authorized compile and runtime gate; preparing or compiling it
does not establish that any frame was captured. For example, from this repository:

```sh
capture_root=$(mktemp -d "$PWD/local/gui-capture-private.XXXXXX")
xcrun swiftc -parse-as-library -swift-version 6 -target arm64-apple-macosx14.0 \
  "$PWD/Tests/Runtime/GUIFrameCapture.swift" -o "$capture_root/gui-frame-capture"
"$capture_root/gui-frame-capture" --pid PID \
  --app-bundle /absolute/NativeForensics.app --synthetic-only --list-owned
```

The list command requires an already running, owned synthetic app. It emits
only that app's window IDs and geometry, display IDs and geometry, and numeric
process-birth metadata. Replace `PID` with the app process observed by the root
runtime harness. Capture requires exact selected IDs and a fresh output leaf:

```sh
"$capture_root/gui-frame-capture" --pid PID \
  --app-bundle /absolute/NativeForensics.app --synthetic-only \
  --window-id WINDOW_ID --display-id DISPLAY_ID --output "$capture_root/frames" \
  --seconds 10 --max-frames 512 --max-pixels 4000000 --max-bytes 134217728
```

`CGPreflightScreenCaptureAccess()` runs before content enumeration. If existing
permission is absent, the helper prints a generic `BLOCKED` receipt and exits
`77`; it never requests permission, opens System Settings or changes TCC grants.
Arguments, identity and output-path failures exit `64`; other unclassified API
failures exit `69`. A completed capture exits `0`; bounded or failed capture
returns a partial receipt and exits `2`. READY is emitted only after the stream
starts and the original process identity has been checked again.

The helper requires a nonnil immutable `NSRunningApplication.launchDate` and
an owned PID birth from public `proc_pidinfo(PROC_PIDTBSDINFO)`. It compares both
at asynchronous selection/start/stop boundaries and checks the kernel birth
around each frame write. PID equality alone cannot substitute for these checks.
The receipt includes numeric launch/birth values. Root must separately correlate
the executable and source graph with the running app and the synthetic query.

The output must be beneath this source repository's ignored `local/`. Its
existing immediate parent must belong to the current UID and have exact `0700`
permissions. The helper never changes existing parent permissions. It opens
all ancestors without following symlinks, creates one fresh `0700` leaf,
retains pinned parent/directory descriptors and checks the fresh leaf's named
identity relative to its pinned parent. Each capture output is an exclusive
regular `0600` file with one link, verified through
both its descriptor and its name before and after a complete, flushed write.
File and directory flush failures fail the receipt; no existing output is
overwritten. Failures can leave newly owned diagnostic fragments for inspection.

Defaults bound capture to 10 seconds, 512 complete frames, four million pixels
per frame and 128 MiB total output including a reserved 1 MiB summary. The
maximum accepted duration is 60 seconds. Only the exact selected window is
included, with audio and cursor capture disabled. Each complete-frame PNG has
raw Mach display ticks, converted uptime seconds, callback receipt time,
observed gaps and raw-pixel/PNG hashes. The root still needs actual query/table
pixel matching, visible synthetic-state verification and a last-nonmatch /
first-match pair before reporting binding-receipt-to-display timing. Capture,
encoding, birth checks and file flushes add measurement overhead.

## Observed large-listing cohort C

The local M2 run used the optimized release main executable with SHA-256
`cb6e722363f158e3d2850f8b9dcba141ca8fd61d34744204546a8593ea5649fe`.
This pins cohort C; subsequent source/cache changes require a new measurement.
The warm synthetic FAT32 case had 49,994 listed entries. Its selected image
contained 286,720,000 bytes, with independently checked file SHA-256
`9b0829b7cdd4fcff7a1c91c9e20eab53a887d0f651104d03acde1d885c2a6551`.

Each of five separate captures started before one actual nonhuman CUA BackSpace
after the helper's READY receipt. Removing the trailing `X` from `PDFALPHAX` or
`PDFBETAX` produced one allocated result, respectively `/PDFALPHA.PDF` at 742 bytes
or `/PDFBETA.PDF` at 741 bytes. A fresh report written at normal app quit contained
five unique native event associations, trial IDs 3/5/7/9/11 with input sequences
2/4/6/8/10. The event and Quartz clocks agreed exactly; each CA dispatch sample
was inside its actual Mach bracket. Captures retained one process birth, launch,
window and display identity throughout.

An independent readback hashed every one of 755 captured PNGs and reconstructed
all seven fixed regions for 46 distinct PNG hashes. Cached OCR was checked against
the saved text files, and the full matching and preceding images were visually
inspected. A frame qualified only when its query, filename, path, allocated state,
byte size, `1 of 49,994` count and `Entries 1–1 of 1` footer all matched in that same
frame. Every earlier recorded frame failed that complete semantic check.

| Trial | Query | Last nonmatch → first match frame | Event → rows published (ms) | Event → captured display upper bound (ms) |
| --- | --- | --- | ---: | ---: |
| 3 | PDFALPHA | 72 → 73 | 218.747 | 272.818 |
| 5 | PDFBETA | 107 → 108 | 214.663 | 276.858 |
| 7 | PDFALPHA | 92 → 93 | 220.280 | 268.601 |
| 9 | PDFBETA | 72 → 73 | 226.567 | 289.286 |
| 11 | PDFALPHA | 79 → 80 | 214.368 | 276.608 |

For this small mixed cohort (three Alpha, two Beta), captured-display upper-bound
p50 was **276.608 ms** and p95 was **286.800 ms**, using Hyndman–Fan type 7 linear
interpolation. These are five observed event-to-first-matching-captured-frame
upper bounds, with no per-query five-sample percentile claim.

The transition pairs were about 33.333 ms apart; the maximum complete-frame gaps
over the full captures were 216.665–249.998 ms. Requested eight-second captures
had start/stop receipt spans of 8.197–8.549 seconds after stop/drain overhead.
Frame, pixel and byte caps all passed. Capture, PNG encoding and file flush work
were present during this measurement. The result concerns captured WindowServer
presentation, not physical display photons or human/hardware input latency. It
does not establish general-query, cold-start, M5, cancellation/RSS or Autopsy
performance, and does not measure the later cache changes.

The fresh final semantic report SHA-256 is
`50226b7dc52fecda42d7c6bbe2a79d817a05e4b0e79ec1648473ce93b2c94dd5`;
the independent source-image/crop/clock audit SHA-256 is
`fb40664ad2134719c7812afeef03ccd4115f035a294be36a1c558857204feff8`.
Detailed synthetic receipts and images remain in ignored local diagnostics.

## Separate historical binding-only cohort

The earlier ten-entry synthetic run used main executable SHA-256
`41b5e9a6ffaea993b85046c46ed5557e43274bda2e7b80a1dc250449499d7885`.
Only two of six capture attempts contained a matching input/result transaction;
four missed the input after capture ended and remain unmatched. The two valid
binding-to-captured-display upper bounds were 216.555 ms for BETA and 224.696 ms
for ALPHA. That run had no qualified native input timestamp and no five-sample
p50/p95. Keep its n=2 evidence separate from cohort C's different workload and
event-based n=5 result; it is not a before/after performance comparison.
