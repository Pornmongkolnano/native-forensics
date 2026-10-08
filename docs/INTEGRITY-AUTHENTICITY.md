# Optional signed integrity reports

`CaseIntegritySignature` adds an optional local Ed25519 envelope around an
unchanged `CaseIntegrityReport`. Unsigned audit reports and their existing
renderers remain available. Signing, encoding and verification operate on values
in memory: they do not open evidence, audit a case, modify receipts, save files,
generate keys, write the keychain or contact an external service.

The signer must supply a `CryptoKit.Curve25519.Signing.PrivateKey`. The verifier
must supply a `CryptoKit.Curve25519.Signing.PublicKey` whose trust was established
independently of the envelope. There is no verification overload that chooses
the embedded key as a trusted key. The embedded key only identifies the claimed
signer and must equal the caller's trusted key.

```swift
// callerPrivateKey and independentlyTrustedPublicKey come from the caller's
// own approved key and trust policy; this API never creates or stores them.
let signed = try CaseIntegritySignature.sign(report: report, using: callerPrivateKey)
let localEnvelopeBytes = try CaseIntegritySignature.json(signed)
let verifiedReport = try CaseIntegritySignature.decodeAndVerify(
    localEnvelopeBytes, trustedPublicKey: independentlyTrustedPublicKey)
```

## What verification establishes

A successful verification binds the complete typed report to possession of the
private key corresponding to the independently trusted public key. An attacker
who rewrites a report and recomputes its SHA-256 still needs that private key to
produce an accepted signature. An attacker who replaces the report, signature
and embedded key with a new valid envelope fails against the original trusted
key.

This origin assurance is only as strong as the external trust anchor and private
key custody. For example, an organization could authenticate a public key or its
SHA-256 fingerprint through a separately controlled channel. A key copied only
from the same report, or from an attacker-controlled file alongside it, provides
no independent anchor. Changing the caller's trusted key changes the verifier's
trust decision; the API cannot determine whether the caller made that decision
correctly. Ephemeral keys can sign locally but provide no examiner identity
unless their public keys are anchored independently.

Signing does not prove the report was produced by the auditor, make its claims
true, authenticate source evidence, establish chain of custody, refresh source
hashes or prove that evidence was available at signing time. The report's
`sourceRehashed`, `isPartial`, individual statuses and recorded digests keep their
existing meanings. A signed historical receipt remains historical. A signature
also provides no trusted timestamp or replay protection: a valid old envelope
can be presented again. Identity, approved algorithms, key rotation/revocation,
trusted timestamping and freshness policy remain caller responsibilities.

## Full report and canonical bytes

The envelope has its own schema version `1`, independent of report schema `1`.
It carries the algorithm `Ed25519`, canonicalization
`nativeforensics.case-integrity-report-json-v1`, lowercase report SHA-256,
32-byte public key, 64-byte signature, and the complete original report. Data
fields use JSONEncoder's base64 representation. Unsupported envelope versions,
algorithms, canonicalization versions, malformed cryptographic fields and report
schemas fail closed.

The report hash covers the full `CaseIntegrityReport` model, including case path,
private source paths, IDs, fractional dates, audit flags, all checks, their order
and optional values. It does not use the redacted report export projection.
Version 1 uses compact Foundation `JSONEncoder` output with `.sortedKeys`,
`.withoutEscapingSlashes` and `.deferredToDate`. Dates are finite numeric seconds
since the Foundation reference date, preserving the `Date` value rather than
discarding fractions through ISO-8601 formatting. Arrays retain their order and
nil optional values follow the report's existing synthesized Codable encoding.
This is an app-specific codec, not RFC 8785 or a promise of interoperability with
other JSON writers. A future incompatible codec needs a new canonicalization
version.

The signature covers a fixed UTF-8 domain prefix
`NativeForensics/CaseIntegritySignedEnvelope/v1` followed by a NUL byte and a
canonical JSON metadata object containing the envelope version, algorithm,
canonicalization version, complete report digest and signer public key. Thus
the report digest and envelope interpretation are signed together.

CryptoKit randomizes its Ed25519 signing operation to reduce side-channel risk,
so separate calls with the same key and report can produce different valid
signature bytes. The report's canonical bytes, hash and signer key remain the
same. Canonical envelope JSON is stable for a particular envelope; separate
signing calls need not produce identical envelope bytes. See Apple's
[signing API documentation](https://developer.apple.com/documentation/cryptokit/curve25519/signing/privatekey/signature(for:)).

`decodeAndVerify` accepts only exact canonical bytes emitted by `json`, then
returns the verified typed report. Re-encoding must reproduce the original
bytes. Unknown keys, duplicate keys, alternative formatting, trailing documents
and other representations are rejected rather than leaving unsigned fields in
a document accepted as trusted. Direct `verify` validates a typed envelope and
returns the same report. `json` validates structure and report-hash consistency;
serializing an envelope is not trusted-key verification.

## Bounds and privacy

Default hard bounds are 16 MiB of canonical report JSON, 17 MiB of envelope JSON
and 20,001 checks. Callers can narrow these through
`CaseIntegritySignatureOptions`, but cannot enlarge or disable them. Invalid,
negative and oversized options fail. The verifier bounds untrusted envelope
bytes before JSON decoding. The full-model validator enforces existing string
and SHA-256 limits, finite dates and nonnegative byte counts. It also applies a
conservative aggregate escaped-string budget before allocating report JSON, so
many individually small paths cannot trigger a very large encoding. Actual
encoded byte counts are checked as well.

The full envelope contains private local paths and messages. Signing it is an
explicit local integrity operation, not permission to publish, upload or send
those bytes to an AI service. This API has no publication or file-writing path.
Any caller that chooses to save or share an envelope must handle its private
contents explicitly. Existing redacted JSON/Markdown exports can still be used
for their original purpose; they are separate representations and are not the
signed full report.

Synthetic regression tests pin version 1 report bytes to an explicit fixture and
independently computed SHA-256, then cover exact full-report round trips, fractional time
and private-path changes, report/hash rewriting, wrong trust anchors, key and
signature substitution, envelope headers, strict JSON parsing and resource
limits. They use in-memory synthetic keys and reports without evidence reads or
key persistence.
