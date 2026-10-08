# Document decoder XPC packaging

The 0.7.0 app (build 16) embeds
`Contents/XPCServices/NFDocumentDecoderXPC.xpc`. Its executable is
`Contents/MacOS/NFDocumentDecoderXPC`, identifier is
`org.nativeforensics.NFDocumentDecoderXPC`, package type is `XPC!`, and service
type is `Application`. The exact XML inputs live at
`script/specs/document_xpc_info.plist` and
`script/specs/document_xpc_entitlements.plist`.

The broker's complete entitlement dictionary contains one boolean grant:
`com.apple.security.app-sandbox=true`. The parent desktop app remains
unsandboxed. Packaging does not grant network, source-file, user-selected-file,
bookmark, sandbox-inheritance or exception access to the service. The runtime
passes bounded document bytes rather than filesystem capabilities; its lifecycle
and live-peer validation contract is in [XPC decoder](XPC-DECODE.md).

The broker owns a fresh parser executable for every request at
`Contents/XPCServices/NFDocumentDecoderXPC.xpc/Contents/Helpers/NFDocumentDecoderWorker`,
with signature identifier `org.nativeforensics.NFDocumentDecoderWorker`.
`script/specs/document_worker_entitlements.plist` contains exactly two boolean
keys: `com.apple.security.app-sandbox=true` and `com.apple.security.inherit=true`.
The child inherits the broker's sandbox; it receives no additional network,
source-file, bookmark or exception entitlement. The parser worker is terminated
and reaped independently, so a normal request does not require restarting the
XPC service. Runtime wire version 2 authenticates both broker and owned worker;
the result attributes decoder SHA-256/CDHash to the actual parser worker and
records the broker separately.

`build_and_run.sh` captures graph schema 3 before compiling the app, development
CLI, XPC broker and parser worker. Each graph contains every transitive compiled target,
including `NFDecoderIPC`, `NFDocumentDecoding`, `ForensicsCore` and its derived PNG
validator where appropriate. The app and XPC graphs additionally pin all three XML
specifications; the worker graph pins its own entitlement specification.
The post-build seal rejects changed, missing or additional
relevant source inputs and records the raw compiled SHA-256 for every product.

Staging checks those raw bytes, strips only the staged release copies with system
`strip -S`, checks executable bytes for private build paths, signs the CLI and
parser worker, signs the enclosing XPC bundle with its exact entitlement file, and finally signs
the parent app. It preserves original `.build` binaries and dSYMs. A failure
removes the stage and preserves the previously published app.

`Contents/Resources/document-xpc-manifest.json` schema 2 binds the signed broker
executable, copied Info.plist, entitlement XML digest, architecture, minimum
macOS, raw compiled hash, full source graph and staging transform. The enclosing
app signature seals this manifest. Its nested worker receipt independently binds
the signed worker executable, raw compiled bytes, source graph, entitlement XML
digest, architecture, minimum macOS and staging policy. The validator compares shared inputs across
app, CLI, broker and worker graphs, checks service identity and matching version/build,
and compares actual signed entitlements against the minimal policy. Numeric
`1`, string `true`, false values and additional keys cannot satisfy that policy.

Each app/helper/broker/worker executable must contain exactly the declared architecture
and Mach-O macOS deployment target and load only canonical `/usr/lib/` or
`/System/Library/` dependencies. Nested signatures are verified separately before
the outer bundle's deep verification. Release trust additionally requires the
same Developer ID team and hardened runtime for the broker, worker and every other
component; local ad hoc validity remains separate from notarization and Gatekeeper
acceptance.

The distribution includes every graph input, including the XML specifications,
and rechecks the copied `Source/` tree. `Source/Repack.command` uses the included
packaging script and original app/materials without a checkout cache. Historical
0.6 versioned archives remain unchanged. Python synthetic packaging regressions
are separate from launched, signed XPC sandbox/runtime verification and memory
measurements.
