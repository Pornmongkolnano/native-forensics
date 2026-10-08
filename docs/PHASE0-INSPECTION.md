# Phase 0 selected-file inspection faults

`ImageInspector.inspect(url:progress:)` hashes exactly one selected regular local file. Its result is a selected-container-file SHA-256 and original file size/identity, not a logical/decompressed image hash or a complete split-image set. Header signatures remain hints rather than filesystem validation.

The existing multi-chunk fixture is bytes 0...255 repeated 12,288 times, followed by bytes 0...16. It is 3,145,745 bytes: three 1 MiB reads plus a 17-byte tail under normal regular-file reads. An external `/usr/bin/shasum` 6.02 invocation produced:

```text
69112280f593fd44684d97d3fe42cdcb84da4ae495d8e1db649f06c3596a7ce6  large-pattern.dd
```

The sanitized [external receipt](benchmarks/phase0-multichunk-shasum.json) retains the recipe, size, command, version, output and exit code. No source image or binary fixture is committed. The Core test reconstructs the same recipe independently and compares public inspection with that fixed external digest. Generating this receipt does not itself execute the Swift/native test gate.

## Mid-read I/O error and ownership

An internal, per-call test seam supplies `readForTesting` and an optional descriptor-close observer. The public API always selects `FileAccess.read`; there is no public skip-verification option, global reader replacement or altered buffer/resource cap. Source opening, read-only ownership, original-size bound, descriptor/path identity checks and final digest construction remain in the production path. A successful injected read cannot avoid those checks. Counts outside the requested read range are rejected before indexing the buffer.

The EIO fixture opens a real regular file, consumes its actual first 1,048,576 bytes through `FileAccess.read`, and observes the real descriptor at offset 1,048,576. On the next read after that prefix, the injected reader raises the same EIO diagnostic shape as the production reader. Positive short reads are accumulated up to the exact prefix boundary. This models a deterministic mid-read failure on otherwise intact synthetic bytes; it is not an open failure, premature EOF, source mutation or a claim of reproducing a physically failing device.

The test checks the known prefix, positive real-read count, attempted read at the prefix boundary, read-only descriptor flags, EIO error, absence of an `InspectedImage`/partial digest receipt, and exactly one successful close of the inspector's owned descriptor. A close observer records the actual `Darwin.close` status. Checking a descriptor number after the operation would be race-prone because another task can reuse it. The separate descriptor used by final path identity verification retains its existing ownership in `FileAccess`.

The cancellation fixture pauses an active read owner at that boundary, cancels its parent, verifies that inspection has not returned or closed early, then releases the owner. Cancellation must unwind the child and close its source before the parent returns; no digest is published. An early inspection failure wakes the test's gate waiter and drains the task as well. Both fault paths compare source bytes and the device/inode/size/mtime/ctime identity before and after inspection. Progress is throttled, so a fast failed prefix may expose only initial zero progress; the test observes actual read bytes and rejects final completion progress instead of requiring a timed update.

## Validation and source-hash reuse

`ImageInspectionFaultTests` provides the external-oracle comparison, deterministic mid-read EIO and cancellation-drain cases. Existing `ForensicsCoreTests` retain empty/known/multi-chunk, local regular-file, signature scope, mutation, pathname replacement and cancellation checks. Current execution receipts belong to the repository's serial gate; test source alone does not close P0.1.

Default engine and content-index source verification continues to hash all required containers. Incremental derived-text reuse still requires fresh full hashes before and after its work. Current [workload guidance](LARGE-WORKLOADS.md) treats private snapshot optimization as future work and excludes inode/mtime caches or a public skip switch. This change introduces no source-hash reuse optimization.
