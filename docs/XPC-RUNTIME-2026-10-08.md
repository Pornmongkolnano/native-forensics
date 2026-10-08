# Actual broker and parser-worker runtime observations

These are **local signed debug-bundle diagnostics** on Apple M2/macOS 27.0.1, not the final release/source-graph/notarization receipt. The actual app executable's local diagnostic entry resolved its embedded XPC service. Input fixtures were synthetic; no coursework image, case, provider request or original Autopsy installation was used. Raw reports and test bundles are under ignored `local/.xpc-runtime-broker/`.

## Production parsers

The production broker and production fresh parser worker decoded exact UTF-8 English/Thai text. Two requests in one host process both completed, each with a distinct parser PID and a registered physical-exit observation before completion. The observed total was about 201 ms with a 2-second per-job deadline. The earlier self-exiting service needed about 10.11 seconds for two requests under its normal 12-second deadline, with a roughly 10-second gap between processes; the 2-second variant timed out. These observations justified retaining the broker and replacing only each parser process. They are not a matched performance or full-pipeline speedup measurement.

Seven independent production input checks subsequently passed:

| Input | Observed result |
|---|---|
| Valid PNG with a misleading `.dat` name | Image decoded; physical parser exit confirmed |
| Valid JPEG | Image decoded; physical parser exit confirmed |
| Known text PDF | Exact independently specified text marker |
| Locked RC4-128 PDF | Explicit `LOCKED_PDF`, no decoded text |
| Malformed PDF | Explicit `MALFORMED_PDF` |
| Known DOCX with a misleading `.bin` name | Exact independently specified body marker |
| NUL/binary input | Explicit unsupported content |

Every input retained the same full SHA-256, size, inode, modification and change times. Each result had matching started/exited parser identity. The PNG had exposed a false cleanup failure in the previous Security guest-absence observation; the physical kernel observer resolved it. The locked PDF is a real encrypted fixture, not an injected `isLocked` flag. Its legacy algorithm is a test input, not an encryption recommendation or proof of every encrypted PDF profile.

## Policy and terminal behavior

An independent Objective-C **test worker** replaced only the worker in an owned copy of the debug app. The broker executable remained the exact production bytes. The copy was signed worker → broker → app with the production policy: sandbox-only broker, sandbox-inheriting worker. A live owned loopback listener distinguished a policy denial from connection refusal. Only boolean outcomes/errno were returned; the existing outside canary retained exact bytes and identity.

| Actual operation | Observation |
|---|---|
| Open outside canary for read/write; create outside sibling | Denied, `EPERM` |
| Bind outside Unix socket | Denied, `EPERM` |
| Connect to live loopback listener; bind IPv4 loopback | Denied, `EPERM` |
| Create an unconnected IPv4 socket | Allowed |
| Execute fixed `/usr/bin/true` test child | Allowed; test worker waited for its own child |
| Write using test worker's `NSHomeDirectory()` | Denied; this does **not** establish denial of all inherited-container writes |

App Sandbox is not the earlier custom Seatbelt policy. In particular, permitted system execution and inherited-container access must not be described as blanket execution/write denial. Production executes only its fixed, signed parser helper and transfers bounded Data/control via anonymous pipes. Embedded document actions/macros are not executed. [Apple's inheritance rules](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html) require the two worker entitlements; the runtime test checks behavior separately from static entitlement presence.

The same production broker handled test-worker normal output, active hang/deadline, active cancellation, abrupt crash, malformed reply, output flood and two concurrent host requests. Expected outcomes were respectively decoded, timeout, cancellation, invalid response, invalid response, output limit and two decoded answers. **Every accepted parser had a matching physical-exit observation; none returned `cleanupFailed`.** Cancellation/deadline/crash callbacks were not mistaken for exit proof. No host PID signal or unrestricted helper fallback was used. The test worker's crash/malformed/flood cases establish broker/transport cleanup, not production-parser format correctness.

## Evidence still required

Repeat the applicable checks against the final four-product release bundle and its exact source/binary/spec graph. Add sustained sequential jobs, early handshake cancellation, actual input/response-cap memory measurements, broker death during parsing and clean-machine/advertised-OS runs. This diagnostic does not close Developer ID/notarization, physical M5, UI frame latency, battery/thermal or every decoder format gate.
