# Explicit EFS credential input

The native sheet accepts an explicitly selected PKCS#1 RSA private DER file
(64 KiB maximum) and matching certificate DER file (128 KiB maximum). It has no
PFX/P12/password/keychain/trust-evaluation path. The strict RSA integers,
certificate purpose, matching public key and encrypted-file profile are owned
by the native engine, rather than a second cryptographic parser in the UI.

The sheet is available only for a source-bound listing entry that records an
allocated regular NTFS file, encrypted EFS status, DATA attribute type 128, a
known attribute ID, and an explicitly empty attribute name. A missing attribute
name, a colon-free filename or a guessed attribute ID never establishes an
unnamed stream. Its context includes the exact case/evidence, generation ID,
listing date, engine/patch/options, ordered source files/hashes, matching volume
and complete selected file entry. The workspace must compare that context to
its current validated selection before reading and before helper transfer.

Choosing credentials stores transient URLs and display filenames, not their
bytes. The scheduler must grant immediate extraction admission first. A busy
application refuses before reading and does not queue copied credentials. The
choices are cleared after admission. An admitted task retains its permit until
the actual key reader, helper operation, producer buffer clearing and cleanup
have drained. Close and cancellation await that ownership boundary.

The Core reader opens every pathname component through held `O_NOFOLLOW`
directory descriptors, rejects nonregular/nonlocal files, checks file caps
before allocation, and reads directly into owned mutable buffers in chunks no
larger than 16 KiB. Held and freshly reopened file identities must agree in
device, inode, size, modification time and change time. It recognizes only a
complete minimally framed outer DER SEQUENCE; that does not establish a valid
private RSA key or X.509 certificate.

A ten-second monotonic read deadline and cancellation are checked between
bounded reads and interrupted syscall retries. A stalled kernel read remains
awaited through descriptor release; this is not a promise to forcibly interrupt
arbitrary filesystem I/O. All read errors use fixed messages without credential
paths or bytes.

`EFSKeyMaterial.consume` lends private and certificate buffers synchronously
once. The transport must write the private bytes and then certificate bytes
immediately after the nonsecret NDJSON transport descriptor. Those pointers
must not escape the callback. The producer clears its allocations with
`memset_s` and frees them on success, failure, discard and deinitialization.
Immutable framework/kernel copies and caller-created copies are outside that
observed ownership; complete physical-memory erasure is not claimed. No key
digest or credential path belongs in a manifest, argument, environment, log or
JSON request.

A late successful publication remains bound to its original context even if
selection changes or cancellation is requested after the publication boundary.
The root workspace receives that original receipt once through the publication
callback for presentation after the history writer finishes, so a history
refresh cannot race the new record. The output receipt is visible in the sheet
before that writer starts. An asynchronous history callback runs to completion
under the same retained workflow permit, even when cancellation or Quit was
already requested. Its uncancelled owned task is awaited rather than queued as
detached fire-and-forget work. A failed or durability-unconfirmed history save
never changes the accepted output publication into an extraction failure; its
typed outcome and original immutable record ID remain separate. This preserves
output facts without adopting them as a different selected file. EFS CBC is unauthenticated: a successfully decrypted output and
its SHA-256 describe emitted bytes, not authentic historical plaintext.

The new Core tests cover both input caps, read-only descriptors, redirection and
special-file rejection, same-size mutation/path replacement, partial I/O,
credential-side failure cleanup, single use, cancellation drain and deadline
rejection. Native tests use injected fake operations to check immediate
admission, exact selection invalidation, close/cancel drain, diagnostic
suppression, publication binding, already-cancelled post-publication history,
Quit during history writing and separate history failure/durability outcomes.
Their small DER envelopes are state/read
fixtures, not positive RSA/EFS cryptographic oracles. Actual native-helper,
bundled GUI and release proofs remain separate gates.
