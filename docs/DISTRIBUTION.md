# NativeForensics distribution package

The package contains `NativeForensics.app`, `Install.command`, a narrow original
`InstallSupport` atomic publisher, `SHA256SUMS`, `distribution-manifest.json`,
`install-support-build-receipt.json`, `Licenses/`, `Source/` and `Relink/`. Do not separate the binary from the source,
license and relink materials when sharing it. The package contains no Autopsy,
PhotoRec, Homebrew runtime, evidence images, user cases or provider credentials.
PhotoRec remains an optional independently installed external tool; missing it
disables carving with a diagnostic rather than downloading an executable.

## Install or verify

Unzip into an ordinary folder owned by your user. Open `Install.command` with
Terminal, or run the following from that folder:

```sh
./Install.command --verify-only
./Install.command
```

The default destination is `~/Applications/NativeForensics.app`; `--destination`
accepts an existing absolute folder owned and writable by the current user.
The installer needs only macOS system tools, not Python, Xcode or Homebrew.
Do not run it with sudo. It checks the full package inventory, hashes, app
identity, CPU architecture, minimum macOS and code signatures before staging.
It preserves quarantine/extended attributes and never disables Gatekeeper.
Open the installed app through Finder; if macOS refuses an untrusted development
build, use a properly signed/notarized release instead of reducing system policy.

An existing application is preserved by default. Quit it before explicitly
upgrading:

```sh
./Install.command --replace
```

Replacement accepts only the NativeForensics bundle identity. A private stage
on the destination filesystem is verified before an exclusive atomic rename.
The publisher rejects symlinks, overlaps, unowned/unwritable parents and concurrent
installer locks. A successful replacement retains the previous application in
the printed backup folder. Failed publication rolls back; if rollback itself is
blocked by another writer, the recovery copy is retained and its location is
reported. No case, evidence, preferences or independently installed Autopsy is
changed. After confirming the new app works, you can remove the retained old app
yourself. The ZIP checksum obtained separately from the distributor establishes
which exact archive was received; a self-contained hash manifest alone does not
authenticate its publisher.

The installer retains its hidden `.nativeforensics-install-stage.*` directory
and reports a path candidate for manual review. Successful publication normally
leaves it empty; failure or interruption can leave the uncommitted app there.
No shell cleanup removes that pathname, because its entry or an ancestor could
have changed. A path candidate does not prove which directory is currently there.
Read the publisher receipt and actual destination before interpreting a failure:
publication can succeed even when later lock cleanup fails.

## Build the package

Build/verify the app first through this repository's existing workflow, then:

```sh
python3 script/package_native_distribution.py \
  --app dist/NativeForensics.app \
  --output dist/NativeForensics-development-arm64.zip \
  --mode development
```

The script rejects an existing output, validates the app runtime closure and
nested signatures, checks that pinned source/patches/relink files correspond to
its engine receipt, and verifies complete app/document-decoder source graphs. It copies only
explicit source/material inputs, never ignored local evidence/cases. It builds
the original publisher with the same architecture/minimum macOS, signs it ad hoc,
and records development/notarization/clean-machine limitations in the manifest.
No input runtime binary is fetched. ZIP members are sorted, have a fixed timestamp
and normalized permissions, contain no extended-attribute/host-path records, and
are published exclusively. Identical input bytes yield identical ZIP bytes with
the same Python/zlib implementation. This is archive reproducibility, not a claim
of bit-identical Swift/Apple SDK builds across toolchain versions.

Packaging retains its `.nativeforensics-distribution-*.noindex` work directory
and temporary ZIP name, with path candidates reported on stderr. Successful
exclusive publication leaves the temporary and final names as hard links to the
same archive inode; modifying either changes that archive. Neither candidate
diagnostics nor a pathname authorize automatic deletion. Retained work artifacts
are outside the ZIP's explicit package inventory.

`build_and_run.sh` captures source graphs before Swift compilation, compares the
same graphs after compilation, records raw compiled app/CLI-decoder/XPC-broker/parser-worker hashes, and passes
that build receipt into staging. The graphs include each relevant target's source,
CSQLite3 headers/modulemap, the Objective-C `NFDecoderIPC` protocol, shared
`NFDocumentDecoding` parser sources, Package.swift, build/package/validation
recipes, app icon inputs and the XPC XML metadata/entitlement specifications.
Staging checks both the compiled bytes and current graph, then seals
app/CLI-decoder/XPC-broker/parser-worker source receipts inside the bundle signature. Pre-sign raw
binary hashes are labeled separately from the signed bundled helper hashes;
putting the enclosing app's final byte hash inside its own sealed resources would
create a circular hash. The distribution tool compares each graph against both
the checkout and the copied `Source/` tree, rejecting changed, missing or added
relevant inputs. These checks bind observed build inputs and do not authenticate
a publisher or independently prove compiler reproducibility.
The Swift graphs observe pre/post compilation boundaries; an edit followed by
Undo during compilation is outside that boundary check, so keep the source tree
stable throughout the build. The installer C is compiled from captured stdin
bytes. Its receipt records the source and builder digests, compiler recipe, raw
compiled hash and signed hash. The shipped source, actual architecture, Mach-O
deployment target and system-only runtime closure are checked against it. A
prebuilt helper without that captured compile/sign receipt is refused.

The development build workflow retains input snapshots and staging/backup
directories instead of deleting objects through mutable pathnames. Stage and
backup directories use a `.noindex` suffix. Failure can leave an unverified stage;
successful replacement retains the previous app. Diagnostics go to stderr and
identify path candidates for manual review, preserving stdout path receipts and
the original error or exit status. This cleanup policy does not change the
existing publication/rollback sequence or establish crash recovery.

Release staging verifies raw compiled copies first, applies standard system
`strip -S` to remove linker debug maps, then scans all executable bytes for host
user/temporary path prefixes before signing. Raw `.build` binaries and dSYMs stay
untouched. The configuration and exact staging transform are recorded in all four
source receipts. Local debug bundles preserve debug maps and are refused by the
distribution packager. `strip -S` does not scrub runtime strings: any path literal
remaining after debug-map removal is a privacy blocker and needs a source or
compiler-path-policy repair before release. The current measured leaks were only
linker STABS/N_OSO records, and no compiler prefix maps were needed after removal.

Old incomplete development receipts can only be inspected explicitly with
`script/validate_app_bundle.py --allow-legacy-development`. That flag never enables
distribution packaging; current 0.6.0+ bundles must have complete source receipts.
Schema 1 and 2 source graphs remain inspectable as historical input graphs; current 0.7
bundles require schema 3 and the embedded broker/worker pair. Historical versioned ZIPs are
never replaced. `--source-root` additionally verifies the recorded graphs against a chosen source
tree when inspecting a current bundle outside the distribution workflow.

The embedded broker is signed before the parent with only
`com.apple.security.app-sandbox=true`. Its bare parser worker is signed first with
exactly true App Sandbox and sandbox-inheritance keys, inheriting the broker's
restrictions without additional grants. The desktop app remains unsandboxed.
All executables must match the receipt's single architecture and minimum macOS,
resolve only macOS system libraries, and pass signature validation. See
[XPC packaging contract](XPC-PACKAGING.md) for the exact service layout and receipts.

The included packaging script can verify and repack the unchanged app, source
and materials without the original checkout or `.engine` cache:

```sh
./Source/Repack.command --output /absolute/new/NativeForensics-repacked.zip
```

This requires Python 3 and the macOS command-line toolchain for artifact
inspection. It validates the original package's entire inventory, source graphs,
publisher receipt, signatures, runtime closure and declared trust mode before
writing a new ZIP. The output must be outside the package. It retains all original
bytes and trust claims, and does not rebuild modified code or upgrade trust.

### Source and relink material bindings

Repacking rechecks included dependency archives and copied patches against the
engine receipt's pinned digests. Retained objects, static archives and
`Relink.command` must match its recorded hashes. Portable `link-command.json`
must match the generated system-link recipe, while its original-command digest
must match the sealed engine receipt. Outer version/build labels must match the
validated app, and repack trust details must equal the freshly measured trust
receipt. Regenerating outer file hashes cannot replace these correspondence
checks; they do not authenticate a publisher or establish compiler reproducibility.

### Release trust gate

Development packaging never asserts a trusted public release. `--mode release`
requires `--install-support` pointing to a prebuilt original publisher with its
matching `--install-support-receipt` and checks
Developer ID Application signing with hardened runtime on the app and every
helper, a valid stapled app ticket, and actual `spctl` Notarized Developer ID
acceptance for the app and publisher. Any missing requirement rejects packaging
without touching the output. Build the publisher and its receipt together:

```sh
python3 script/package_native_distribution.py \
  --build-install-support /absolute/new/InstallSupport \
  --install-support-receipt /absolute/new/install-support-build-receipt.json \
  --architecture arm64 --minimum-macos 14.0
```

The command signs ad hoc by default. A distributor can explicitly supply
`--sign-identity` and `--hardened-runtime` when preparing a Developer ID build.
The signed bytes must remain unchanged when using that receipt. Release packaging
passes both helper and receipt; it cannot derive source correspondence from the
current C filename or signing team alone. The receipt records an observed build;
it is not independent authentication of an external distributor's compiler run.
Notarization submission needs the distributor's Apple credentials and an explicit
release workflow; this tool does not infer credentials or upload automatically.

An example preparation workflow after credentials become available is:
compile the publisher through the captured-input command above, sign nested code
inside out using Developer ID/hardened runtime/timestamp, sign the enclosing app,
submit the app and standalone publisher together using `xcrun notarytool`, check
the accepted submission log, staple the app, then run the release packaging gate.
Because signing changes helper bytes, regenerate corresponding helper receipts
before sealing the app; do not rewrite a receipt after sealing it. These are
preparation steps, not evidence they have already succeeded.

## Corresponding source and LGPL static relinking

`Source/Dependencies/` contains the exact checksum-pinned Sleuth Kit 4.15.0,
libewf 20240506 and nlohmann/json 3.11.3 inputs. `Source/NativeEngine/`,
`Source/patches/`, and `Source/script/build_native_engine.py` contain the original
helper, all recorded patches and the exact configure/build transformation. Source
for the original Swift app/document decoder, Package.swift and installer publisher
is included separately from dependency notices. Upstream archives retain full
copyright/file-specific license texts and bundled libyal support source.
The owner has not yet selected a license for original project code; dependency
notices continue to apply to their respective components.

`Relink/` contains `NFTSKEngine.o`, `libtsk.a`, `libewf.a`, a portable
`link-command.json` and `Relink.command`. The original link command's host paths
are omitted; its verified digest is retained in the distribution manifest. To
link the helper against a compatible modified libewf, back up the package,
replace `Relink/libewf.a` with your built archive, then run:

```sh
./Relink/Relink.command
```

This needs the macOS developer command-line toolchain and produces an ad hoc
signed `NFTSKEngine-relinked` beside the materials. It does not overwrite the
distributed helper or app, and changing a helper invalidates the original
distribution receipt/signature. A modified build must create its own consistent
receipts and signatures. It must not remove Gatekeeper/quarantine to pretend to
retain the original publisher's trust. The project does not restrict debugging
or reverse engineering modifications to the LGPL portions for personal use.
The package supplies the retained source/object materials; this document does
not assert a blanket license applies to every TSK file or all integrations.

To rebuild the pinned dependency/helper configuration offline from the included
source archives, run `Source/Rebuild-engine.command` with Python 3 and Xcode
command-line tools installed. The builder rechecks all source/patch digests and
uses only macOS system runtime libraries; any different dependency release must
be an explicitly updated specification. Source/license materials do not by
themselves prove broad filesystem support or clean-machine performance.

## Validation boundaries

Local package/hash/signature checks and synthetic installer transaction tests
are repeatable gates. Gatekeeper/notarization, clean-machine GUI launch, additional
macOS compatibility and physical MacBook Air M5 RAM/thermal/battery measurements
are separate gates. A development ZIP does not close those gates. Current measured
results are recorded in the project validation documentation and must match the
artifact's exact app/helper versions. The embedded app engine receipt continues
to say distribution materials are not inside the app; the outer distribution
manifest records that those materials accompany it in this ZIP.
