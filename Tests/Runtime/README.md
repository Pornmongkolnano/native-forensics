# Owned document worker runtime fixtures

Current architecture tests use `NFDocumentDecoderWorkerFixture.m`. Replace only
the worker executable in an owned copy of the staged app; keep the actual
production XPC broker and public host client unchanged. Sign the fixture as
`org.nativeforensics.NFDocumentDecoderWorker` with exactly true Boolean
`com.apple.security.app-sandbox` and `com.apple.security.inherit`, then re-sign
the broker and app. The real broker launches, owns and reaps the fresh worker.
Do not package the fixture in a release artifact or describe it as the native
production parser.

The harness owns an existing outside-container canary and a live loopback
listener. Bake that path/ephemeral port into compiler definitions. Supply each
argument separately to subprocess rather than composing unescaped shell code:

```sh
xcrun clang -fobjc-arc -fblocks -std=gnu11 -mmacosx-version-min=14.0 \
  -I Sources/NFDecoderIPC/include \
  '-DNF_XPC_CANARY_PATH="/private/tmp/OWNED_UUID/outside-canary"' \
  '-DNF_XPC_INHERITED_CONTROL_DIRECTORY="/ABSOLUTE/OWNED/BROKER_CONTAINER/Data/PRIVATE_UUID"' \
  -DNF_XPC_LOOPBACK_PORT=OWNED_EPHEMERAL_PORT \
  Tests/Runtime/NFDocumentDecoderWorkerFixture.m \
  Sources/NFDecoderIPC/NFDecoderIPC.m \
  -framework Foundation -framework Security -lbsm \
  -o OWNED_TEST_APP/Contents/XPCServices/NFDocumentDecoderXPC.xpc/Contents/Helpers/NFDocumentDecoderWorker
```

The fixture implements the same version-2 anonymous pipe protocol: UInt32
big-endian length + bounded session JSON, a framed self-audit-token hello, a
framed decode receipt and exactly its declared ≤128 MiB input bytes. Stdin
stays open; immediate and independent polling detects extra bytes or broker
death. An independent monotonic deadline and per-worker CPU/core/descriptor
limits remain active. Framed derived responses are ≤2 MiB except the deliberate
flood mode.

| Complete recovered input bytes | Fixture behavior |
| --- | --- |
| `NF_TEST_NORMAL` | Valid receipt-bound synthetic text response |
| `NF_TEST_BOUNDARY` | Text contains only operation success/errno JSON |
| `NF_TEST_CRASH` | Fresh worker exits with status 86 |
| `NF_TEST_HANG` | Worker stalls while deadline/cancellation drains it |
| `NF_TEST_MALFORMED` | Invalid framed JSON |
| `NF_TEST_FLOOD` | Response exceeds the 2 MiB output cap |
| `NF_TEST_RESPONSE_CAP` | Valid frame within six bytes of 2 MiB; derived text below 1 MiB |
| `NF_TEST_CRASH_ONCE`, `NF_TEST_MALFORMED_ONCE`, `NF_TEST_HANG_ONCE` | First fresh worker creates a fixed one-byte cookie and takes the fault route; next fresh worker validates that cookie and returns the normal response |

Test-only compiler definitions `NF_TEST_HELLO_DELAY_MS=0...2000` and
`NF_TEST_BAD_HELLO_VERSION=1` delay or invalidate the worker hello after the
independent deadline is armed. They exercise early cancellation and broker
handshake refusal with no added shipping RPC. Default builds use no delay and
the correct protocol version. See [GATES.md](GATES.md) for the deterministic
owned-copy stress, cancellation, physical-exit and memory harness.

Boundary attempts cover outside read/writable-open/create, IPv4 socket/connect/
bind, Unix outside bind, home-directory write/removal and execution/reaping of
benign `/usr/bin/true`. A writable-open success never writes the canary. No DNS,
external address, runtime arbitrary path/command RPC, user evidence or provider
request is used. Require actual permission errors, not missing-file or refused-
connection errors, when claiming a sandbox denial. Socket creation, container
writes and system execution may succeed under App Sandbox; report observations
honestly. The loopback listener must remain alive throughout the check.
The legacy result key `ownContainerWrite` attempts a path returned by
`NSHomeDirectory()`. With the worker's sanitized environment that path may
resolve to the user's home instead of the broker's container. Its denial does
not establish that the inherited sandbox denies every container write.
`inheritedContainerWrite` instead uses the separately compiled, newly created
private directory under the actual broker container Data directory. The host
checks its retained one-byte output's UID, mode, single link, inode, size and
hash independently. It must succeed as a positive control. The three `ONCE`
routes use only fixed whitelisted leaves in this directory, with no runtime
path input. Both attempts pause for a fixed 150 ms after cookie validation so
the external harness can register and recheck their exact kernel objects;
the independent cancellation/deadline watchdog remains active throughout.

Assert actual fresh parser PID start→physical exit order, distinct workers,
retained broker identity, no launchd restart gap between concurrent/sequential
jobs, and a healthy job after a crash/malformed/flood. Production format,
128 MiB cap and memory checks must also use the actual production worker bytes.
Fixture tests prove the actual broker/client cleanup and inherited policy;
source/unit checks are not final signed-package runtime proof.

`NFDocumentDecoderXPCFixture.m` is retained only for the earlier independent
one-process XPC experiment. It is **not** compatible with the current broker/
worker protocol. Earlier logs diagnosed the restart delay and policy scope;
never replace the current production broker with that historical fixture.
