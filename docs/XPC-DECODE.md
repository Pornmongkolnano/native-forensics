# Bundled document broker and fresh parser workers

The packaged app uses a supported App Sandbox XPC broker and a fresh signed
parser worker for each document. It does not start `sandbox-exec` for bundled
inspection and does not retry through the CLI if sandbox, identity, protocol,
receipt, deadline or cleanup checks fail. ImageIO/PDFKit link into
`NFDocumentDecoding` and its CLI/worker executables; the XPC broker and document
client handle only bounded control data and bytes.

`NFDocumentDecoder` remains the required-Seatbelt development executable.
Non-bundled callers select `DocumentAnalysisClient(developmentHelperURL:)`.
The compatibility `helperURL` initializer selects XPC inside an `.app`; a
missing service or worker cannot select the development helper or unrestricted
inspection. Historical analysis schema 1 remains readable with absent
provenance; newly returned client results use schema 2.

## Package and entitlement contract

```text
NativeForensics.app/Contents/XPCServices/NFDocumentDecoderXPC.xpc
  Contents/Info.plist
  Contents/MacOS/NFDocumentDecoderXPC
  Contents/Helpers/NFDocumentDecoderWorker
```

The broker bundle identifier is `org.nativeforensics.NFDocumentDecoderXPC`,
package type `XPC!`, and its executable is `NFDocumentDecoderXPC`. Its complete
entitlement dictionary is one actual Boolean:

```xml
<dict><key>com.apple.security.app-sandbox</key><true/></dict>
```

The standalone helper's signing identifier is
`org.nativeforensics.NFDocumentDecoderWorker`. Its complete dictionary contains
exactly these two actual Booleans:

```xml
<dict>
  <key>com.apple.security.app-sandbox</key><true/>
  <key>com.apple.security.inherit</key><true/>
</dict>
```

Apple documents this helper configuration for inheriting the parent's sandbox.
It grants no separate file/network exception. Numeric `1`, string `"true"`,
false, additional entitlements and missing keys are rejected. Sign the worker
before the broker, then the containing app. Release signing, notarization and
local sandbox/identity enforcement are separate checks.

The host verifies the broker's sealed code, exact entitlement dictionary and
designated requirement before connecting. It validates the live broker's
kernel audit token, NSXPC PID/effective user, fixed executable, requirement and
CDHash against the verified bundle. Both host and broker validate the fixed
worker executable's complete SHA-256, signature, identifier, CDHash and exact
inherited entitlement dictionary. No arbitrary helper path, execution command,
security extension or entitlement change is exposed through RPC.

## Request and ownership flow

1. A host ownership gate admits one request. The host opens the recovered
   regular file without following its final symlink, verifies full size/SHA-256,
   holds its descriptor/identity and creates a second fully checked bounded
   memory snapshot. Queued cancellation cannot release another owner's gate.
2. The three-method Objective-C IPC surface carries `NSData` only. Wire version
   2 includes a random 128-bit job nonce and a shared absolute monotonic
   deadline. No recovered-file path, source descriptor or bookmark is sent.
3. The persistent broker admits one worker at a time. Each connection owns its
   own nonce/cancellation state. It launches only the fixed verified worker,
   in a new owned process group, with close-on-exec descriptors and a minimal
   environment. The worker inherits the broker's OS sandbox.
4. Anonymous stdin/stdout pipes use unsigned four-byte big-endian lengths for
   JSON controls (at most 4 KiB) and responses (at most 2 MiB). A framed session
   precedes a framed decode receipt and exactly its declared document bytes.
   No EOF-based body read or extra unbounded allocation is used.
5. The worker first reports a kernel-issued self-audit token while waiting for
   document bytes. The broker checks it against its actually spawned unreaped
   child. The host checks that worker's live token, signature, fixed executable,
   inherited entitlements and CDHash. It installs a Dispatch `.exit` process
   observer, waits for asynchronous kernel registration, and freshly verifies
   the original live audit-token peer inside the registration handler. Only
   then may document bytes reach the parser.
6. The worker independently checks the complete memory snapshot's size/SHA-256.
   Receipt validation, native parsing and bounded response encoding share an
   autorelease scope. Independent deadline and stdin-revocation monitors can
   self-exit even when a parser stalls. The broker keeps stdin open during work;
   its death closes that pipe. Unexpected trailing bytes are rejected.
7. The worker sends a bounded derived result and exits. Before any terminal
   XPC reply, the broker stops and reaps its own still-unreaped leader/group.
   An unreaped child pins ownership; the broker never signals a cached PID
   after discovering it is no longer its child. It does not kill the shared
   broker or another connection's job. The broker's slot becomes available
   only after this cleanup.
8. The host verifies nonce/version/source receipt and all analysis limits. PNG
   thumbnails require bounded dimensions, complete chunk framing/CRCs and
   validated compressed scanlines before UI decoding. It rechecks its original
   recovered file and both decoder/broker executable receipts, and requires
   the trusted kernel observer's physical exit event before returning.

All established limits remain: 128 MiB recovered input, 2 MiB serialized
response, 1 MiB text, 512 KiB derived PNG, 100 million source pixels, 200 pages,
128 metadata items/archive members. Default wall-clock timeout remains 12
seconds. No-core-dump, CPU 12/13-second and descriptor-128 limits apply to each
fresh worker; the persistent broker has no cumulative 12-second CPU limit.
Extra IPC/memory copies are real overhead and must be measured in the bundled
runtime, rather than equating input-byte and resident-memory limits.

## Cancellation and physical exit

A matching nonce revokes only that connection's worker. Broker polling,
connection invalidation and independent worker monitors leave native parsing
responsive to deadline or cancellation. The broker can signal its own pinned
unreaped leader/group and uses `waitpid` on that child. The host never signals
an XPC service PID or calls `waitpid` on a process it did not create.

Audit-token absence alone does **not** prove physical termination: exec changes
macOS's identity version while the process can continue. This is why fresh
Security guest lookups are used for authentication, and a registered,
live-verified kernel process observer is used for exit. An untrusted synthetic
exit event after failed registration is not accepted. If physical cleanup
cannot be confirmed by the deadline plus bounded allowance, the host fails
with `cleanupFailed` and disables further XPC inspection for that app session.
Caller cancellation wins result/error races after cleanup. If cancellation or
identity validation fails after a begin request but before observer trust, the
host requests a nonce-bound drain acknowledgement through the same bounded
begin control method. Only a live authenticated broker's confirmation of its
owned child reap releases ownership; absent confirmation poisons the host gate.
Unexpected broker ownership/reaping errors quarantine the broker's worker slot
and never authorize a cached-PID signal or usable terminal reply.

Keeping the broker alive avoids per-job `launchd` restart throttling while every
native parse still receives a fresh process. The earlier debug one-process XPC
experiment completed two normal jobs in about 10.11 seconds, with about 10.05
seconds between process starts. That is diagnostic evidence for this change,
not final evidence for the new packaged architecture.

## Provenance and historical records

Current contract version `2.1.0` records actual parser-worker executable
SHA-256/CDHash separately from `brokerExecutableSHA256` and
`brokerCodeSigningCDHash`. Backend fingerprints used by indexes and PDF
comparison receipts identify the parser executable. Fixed interpretation
options and their canonical SHA-256 include actual request timeout and the
unchanged limits. `derivedTextSHA256` covers final canonical `DocumentTextPage`
JSON, including source-unit references/truncation flags, matching index
receipts. It is not a hash of original recovered-file text bytes.

The host generates provenance after receipt/response validation; helper claims
cannot substitute another parser or broker identity. Current XPC provenance
requires both broker identity fields. Development/fake-fixture results cannot
carry broker fields, and fixture provenance is explicitly `testFixture`.
`validateMetadata()` checks identity/policy/checksum shape without fabricating
omitted historical text; `validate(pages:)` also checks the full derived digest.
Historical schema 1 is kept readable with explicitly absent provenance.

## Actual OS boundary and verification

App Sandbox grants its own container and required OS/framework resources. It
permits container writes and can permit system execution under inherited
policy; it is not the old custom Seatbelt no-write/no-other-exec profile. No
network, user-selected-file, application-group, Apple Events or absolute-path
exception is present. The whole workbench/native engine has separate scope.

In the earlier signed debug policy fixture, outside read/writable-open/create,
loopback connect/bind and Unix outside bind failed with `EPERM`. IPv4 socket
creation, own-container write and `/usr/bin/true` execution succeeded. These
observations must not be mislabeled as denial of all sockets, writes or exec.
The fresh inherited worker must be retested, and a live loopback listener and
existing owned canary must distinguish policy errors from missing resources.

`DocumentXPCTests`, `DocumentProvenanceTests` and `DocumentWorkerWireTests`
cover replay/receipt, malformed/output caps, coverage flags, full PNG response,
exact entitlements, framing, queued ownership and a physical exit observer
across exec. `Tests/Runtime/NFDocumentDecoderWorkerFixture.m` replaces only an
owned test copy's worker, while using the actual broker and public client. Its
synthetic normal/boundary/crash/hang/malformed/flood modes exercise real child
cleanup and inherited policy. Production PDF/image/text/Office/ZIP decoding,
128 MiB limits, concurrency and memory must also run against the actual signed
production worker. Unit/source checks and old debug reports are distinct from
final packaged runtime proof.

`DocumentAnalysisClient.currentDecoderIdentity()` inspects current backend
metadata without launching a parser or opening a service connection. Its
immutable identity binds the actual parser and broker SHA/CDHashes, isolation,
decoder contract, fixed options/options digest and explicit IPC version. XPC
inspection repeats signed metadata and checks both original file receipts
afterward, rejecting a changed or mixed snapshot. The older worker-only
`decoderBinarySHA256()` delegates to that fresh inspection. Persisted identity
validation checks shape/current policy; it does not replace a new inspection.
`matches(provenance)` compares every shared metadata field while leaving the
result-derived text digest and historical missing provenance unchanged.

Same-broker cancellation recovery diagnostics use `cancel-early-recover` in
one still-running application host: await first public-client cancellation and
owned drain, then decode a fresh second worker. A separate host invocation can
use a new application-service broker. Cross-host availability does not prove
that the earlier broker's worker slot was reused. Failed raw driver receipts
remain diagnostic evidence and are not upgraded by a later successful run.

Primary references:

- [Embedding a sandboxed helper](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app)
- [Apple sandbox inheritance entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html)
- [Apple XPC lifecycle](https://developer.apple.com/documentation/xpc)
- [Dispatch registration contract](https://github.com/apple-oss-distributions/libdispatch/blob/libdispatch-1462.0.4/dispatch/source.h#L712-L714)
- [Kernel exec identity update](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.1.13/bsd/kern/kern_exec.c#L6651-L6653)
- [Kernel process observer handling](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.1.13/bsd/kern/kern_proc.c#L3968-L4006)
