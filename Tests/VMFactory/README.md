# Disposable APFS snapshot fixture factory

This directory is a standalone laboratory prototype, outside the application and SwiftPM targets. Its current helper fetches only Apple's supported restore metadata and an HTTP HEAD response. It does not download a restore image, instantiate/start a VM, create a disk, or read existing user VMs.

Apple's [installation contract](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine) supplies the supported restore image, hardware model and minimum CPU/RAM constraints. The public `com.apple.security.virtualization` entitlement is required by the installed SDK to load restore metadata; it is used only on the ad-hoc signed laboratory helper. It grants no private APFS snapshot entitlement and changes no host security setting.

Run the compiler only after obtaining the parent agent's serialized compiler window:

```sh
mkdir -p local/.vm-lab
swiftc -parse-as-library -O -framework Virtualization Tests/VMFactory/RestoreMetadataProbe.swift -o local/.vm-lab/restore-metadata-probe
codesign --force --sign - --entitlements Tests/VMFactory/metadata-helper.entitlements.plist local/.vm-lab/restore-metadata-probe
local/.vm-lab/restore-metadata-probe . > local/.vm-lab/restore-plan.json
```

The planner permits only Apple's HTTPS restore URL and Apple HTTPS redirects, including the exact `updates.cdn-apple.com` host observed from the supported restore API. Redirects must remain HEAD and are capped at three. It refuses missing/unknown restore lengths, records final URL/timestamp/validator headers and reports a failed preflight for images above the unchanged 20 GiB transfer budget. HEAD length is an estimate, not a downloaded-byte or artifact-integrity receipt. The planner caps guest memory at 6 GiB and reports a 50 GiB sparse guest plus 8 GiB working budget and a 30 GiB free reserve. A second independent fully allocated 50 GiB copy is calculated separately. Owned COW acquisition after permanent guest shutdown is the proposed path; no streaming copy fallback is authorized by this prototype. Before each later phase, actual physical allocation and free space must be checked again. Source acquisition receives complete selected-file hashes before and after all readers, independent from logical snapshot-file digests.

The applicable host license must be checked from its installed license, not assumed from an older web version. Section 2B is the Mac App Store/automatic-download license grant; its subsection (iii) permits up to two additional macOS copies/instances for the listed purposes on an owned/controlled Apple-branded host already running macOS. The separate preinstalled-only grant in section 2A must not be substituted for that license basis. This helper records the installed license digest and leaves the existing macOS guest count unknown. A concrete factory needs an applicable license basis and confirmation that adding one guest stays within the allowance; finding an installed virtualization application or counting running VMs does not establish the number of existing macOS copies/instances.

The proposed isolated guest workflow seeds exact version-one bytes, creates a guest snapshot with Apple's guest tool, then changes/renames/deletes fixed files and records version-two bytes. It uses no Apple account, keychain contents or user evidence. Guest-only administrative operations are distinct from host privileges. The VM must be shut down before acquisition. Host snapshot reads must prove exact historical bytes, snapshot identity, base volume identity, kernel read-only flags and unchanged container bytes. No VM creation, installation, historical snapshot mount or positive snapshot-content result has happened yet.

An isolated VM snapshot fixture will not establish physical Apple Silicon Secure Enclave FileVault compatibility; [Apple's FileVault description](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web) distinguishes internal hardware-bound storage from removable-storage encryption.

## Reviewed pinned transfer

The metadata-only run on 8 October 2026 identified Apple's supported macOS 27.0.1 build 26A434 restore with HEAD length 26,637,307,067 bytes (24.81 GiB). Its initial 20 GiB provisional budget reported a failed transfer preflight; no IPSW body was fetched. The parent reviewed the actual size and approved only that exact pinned artifact for the prepared `OwnedRestoreDownloader` component, subject to refreshed complete-space calculations, the unchanged 30 GiB reserve and resolved license/guest-copy prerequisites. It permits no automatic larger image/new-build substitution. The captured HEAD validators and the observed download hash are distinct from an independent Apple-published content hash or authenticated examiner receipt.

`OwnedRestoreDownloader.swift` is library-only and starts no transfer by itself. The separate `OwnedRestoreDownloaderHarness.swift` exercises response, budget, ownership, resume and path-tampering rules without calling its network transfer. Their compiler/runtime gate remains separate from any actual download. A successful completed transfer must still be loaded through `VZMacOSRestoreImage.image(from:)` and checked for the pinned build, supported hardware model and minimum requirements before the later controlled VM creation.
