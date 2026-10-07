# Document decoder access boundary

`DocumentAnalysisClient` now applies a required per-request Seatbelt policy before
starting `NFDocumentDecoder`. All application and workflow-probe callers use that
public client. There is no public switch or environment variable that disables
the policy, and no automatic unrestricted fallback. This is a development
backend whose compatibility must be retested on each supported macOS release.

## Request and access flow

1. The parent opens the recovered regular file without following its final
   symlink, checks its complete byte count and SHA-256, and retains its descriptor.
2. The parent starts the fixed system launcher `/usr/bin/sandbox-exec` with the
   fixed policy. The selected input and helper paths are opaque `-D` parameters;
   they are never interpolated into the policy language. POSIX `realpath`
   parameters handle standard system/SwiftPM directory aliases. Foundation's
   URL symlink resolver may retain the friendly `/var` or `/tmp` spelling,
   which does not match Seatbelt's `/private/var` or `/private/tmp` vnode path.
3. The policy permits content reads of exactly that input and helper plus the
   Apple runtime/font/resource directories listed below. It permits no content
   write location and no network operations. It permits execution of only this
   request's helper. Other executable paths and process-fork operations remain
   denied by default.
4. The decoder verifies the input receipt again and decodes its verified memory
   snapshot with ImageIO/PDFKit or the bounded text/container readers. It emits
   bounded derived output through the already-open stdout pipe.
5. The parent validates the response and rechecks the original open file and
   named file identity/hash. On success, failure, timeout, or cancellation it
   stops and reaps its own process group. The source receipt, deadlines, output
   caps, and cancellation contract are unchanged by sandboxing.

The explicit system data-read grants are `/System/Library`,
`/System/Cryptexes/OS`, `/System/Volumes/Preboot/Cryptexes/OS`, `/usr/lib`, and
`/usr/share`. Only the runtime directories and helper have executable-mapping
grants. `/System/Volumes/Data` and user home directories are not granted.
These grants cover operating-system frameworks, dyld caches, fonts, and locale
resources; they do not grant the containing case, source-image directory, or
the rest of the scratch directory.

File metadata traversal is wider than content access, and the root directory
can be read for dyld bootstrapping. The profile also allows normal system calls,
sysctl reads, Mach bootstrap access, and the narrowly listed dyld signature
fcntl/sandbox-check operations. It grants no named Mach-service lookup or file
creation/write. This is a constrained file-content/network boundary, not a
claim that the process cannot learn file existence or use any system service.

No credentials, proxy configuration, loader overrides, or user environment are
passed to the child. Policy path parameters are visible in the launcher's
arguments; no document contents or credentials are placed there. Child
descriptors remain restricted to the request's stdin/stdout/stderr pipes.
Original pipe ends are normalized to descriptors at least 3 before adding
stdio duplication/close actions, including in the Codex process runner. An
independent trusted subprocess reproduced the old failure with all host stdio
closed and verified successful receipt-bound document decoding after the fix;
the running test host's standard streams were never changed.

## Failure and test behavior

If the fixed launcher is missing, not a regular executable, or inaccessible,
the client reports `sandboxUnavailable` before spawning. If macOS rejects the
policy or refuses the decoder launch, the request fails without usable output;
the client does not retry outside the sandbox. A decoder CLI invoked directly
does not apply this parent-owned policy and must not be presented as an
equivalent restricted inspection path.

`DocumentSandboxTests` compiles a small independent C probe from synthetic
source and runs it through the same public client and policy. It requires an
actual selected-file data read and rejects:

- a read of a different existing private file;
- a writable open of the selected input and creation of a scratch sibling;
- IPv4 socket creation/connect/bind and Unix-socket bind;
- execution of a different benign executable.

Network probes use only loopback port zero/ephemeral bind and a local Unix
socket path, with no DNS or external address. The input filename deliberately
contains quotes and text resembling a profile clause to verify that parameters
remain data. The existing `DocumentDecoderTests` and `DocumentOfficeTests` now
run real PDF, image, UTF-8, bounded Office, and ZIP inputs under the default
required policy and verify receipt-bound results. Source bytes remain unchanged.

Intentional fake-helper mutation/timeout/flood tests use an internal
`@testable`-only `disabledForTesting` initializer. Production app and public
library callers cannot select it. It is not inferred from helper filenames,
build configuration, or failed sandbox launches.

Relevant focused check:

```sh
swift test --filter 'Document(Sandbox|Decoder|Office|Client)Tests' \
  --experimental-maximum-parallelization-width 4
```

## Platform and distribution limits

Apple's installed `sandbox-exec(1)` manual marks the launcher deprecated.
[Apple DTS explains that custom Seatbelt policy language is not supported for
third-party product development](https://developer.apple.com/forums/thread/661939).
The implementation therefore claims empirical enforcement on tested systems,
not a supported Apple API contract or future platform guarantee. Its profile is
project code; the operation names and dyld bootstrap needs were checked against
the current system policy files without importing their broader permissions.

[Apple App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)
is the supported entitlement-based model. A future signed distribution must
evaluate an isolated App Sandbox/XPC decoder with minimal file grants and test
its actual boundary; ad-hoc signing, notarization, resource limits, and this
Seatbelt development backend are distinct properties. This change does not
disable Gatekeeper, change quarantine, add Apple developer identities, sandbox
the entire workbench, or assert that the native filesystem engine is sandboxed.
