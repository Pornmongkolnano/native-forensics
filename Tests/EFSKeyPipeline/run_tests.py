#!/usr/bin/env python3
"""Independent known-byte and rejection oracles for a precompiled EFS probe.

Only newly generated synthetic identities are queried before/after import.
No compilation occurs. Reports omit secret bytes and private paths.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import subprocess
import time
import fixtures


def frame(efs: bytes, pfx: bytes, password: bytes, certificate: bytes,
          ciphertext: bytes, logical_size: int, trailing=b"", profile="pfx") -> bytes:
    return ((b"NFED\0\0\0\1" if profile == "der" else b"NFEP\0\0\0\1") + struct.pack("<IIIIQQ", len(efs), len(pfx), len(password),
                                           len(certificate), logical_size, len(ciphertext))
            + efs + pfx + password + certificate + ciphertext + trailing)


def changed(blob: bytes, offset: int, value: int) -> bytes:
    result = bytearray(blob)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


def run(probe: Path, corpus: Path) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text())
    if manifest.get("syntheticOnly") is not True or manifest.get("windowsCreated") is not False:
        raise RuntimeError("Only the generated synthetic corpus is accepted")
    observations: list[dict] = []

    def attempt(name: str, entry: dict, *, efs=None, owner=None, password=None,
                ciphertext=None, logical_size=None, trailing=b"", expected_error=None,
                expected_mismatch=False, profile="pfx", credential=None, certificate_override=None):
        owner = owner or entry["owner"]
        key = (corpus / (owner + (".private.pkcs1.der" if profile == "der" else ".pfx"))).read_bytes() if credential is None else credential
        pw = ((b"" if profile == "der" else (corpus / (owner + ".password")).read_bytes()) if password is None else password)
        certificate = (corpus / (owner + ".certificate.der")).read_bytes() if certificate_override is None else certificate_override
        metadata = (corpus / (entry["name"] + ".efs")).read_bytes() if efs is None else efs
        encrypted = (corpus / (entry["name"] + ".ciphertext")).read_bytes() if ciphertext is None else ciphertext
        expected = (corpus / (entry["name"] + ".expected")).read_bytes()
        request = frame(metadata, key, pw, certificate, encrypted,
                        entry["logicalBytes"] if logical_size is None else logical_size, trailing, profile)
        start = time.perf_counter()
        process = subprocess.run([str(probe)], input=request, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=20)
        elapsed = (time.perf_counter() - start) * 1000
        if len(process.stderr) > 8192 or (pw and pw in process.stderr) or key in process.stderr:
            raise AssertionError(name + ": credential disclosure or oversized response")
        diagnostic = json.loads(process.stderr)
        if diagnostic.get("ownedBufferWipeChecks") != 2:
            raise AssertionError(name + ": owned mutable prefetch buffer wipe not verified")
        for field in ["keychainBefore", "keychainAfter"]:
            if field in diagnostic and diagnostic[field] != {"certificates": 0, "keys": 0}:
                raise AssertionError(name + ": generated identity keychain state changed/unavailable")
        protection_before = diagnostic.get("dataProtectionBefore")
        protection_after = diagnostic.get("dataProtectionAfter")
        if protection_before != protection_after:
            raise AssertionError(name + ": data-protection query state changed")
        if protection_after and protection_after.get("available") and (protection_after["certificates"] != 0 or protection_after["keys"] != 0):
            raise AssertionError(name + ": generated identity appeared in data-protection store")
        if "keychainAfter" in diagnostic:
            query = b"NFEO\0\0\0\1" + struct.pack("<I", len(certificate)) + certificate
            after_process = subprocess.run([str(probe)], input=query, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            after_diagnostic = json.loads(after_process.stdout)
            if after_process.returncode != 0 or after_diagnostic.get("keychainAfterProcess") != {"certificates": 0, "keys": 0}:
                raise AssertionError(name + ": generated identity keychain changed after process exit")
            if after_diagnostic.get("dataProtectionAfterProcess") != protection_after:
                raise AssertionError(name + ": data-protection query changed after process exit")
        if expected_error:
            if process.returncode != 1 or diagnostic.get("status") != "rejected" or diagnostic.get("code") != expected_error:
                raise AssertionError(name + ": wrong rejection: " + json.dumps(diagnostic, sort_keys=True))
        else:
            if process.returncode != 0 or diagnostic.get("status") != "decrypted-observed-bytes":
                raise AssertionError(name + ": positive failed: " + json.dumps(diagnostic, sort_keys=True))
            if diagnostic.get("authenticatedPlaintext") is not False:
                raise AssertionError(name + ": CBC output wrongly claimed authenticated")
            if diagnostic.get("outputBytes") != len(process.stdout) or diagnostic.get("outputSHA256") != fixtures.digest(process.stdout):
                raise AssertionError(name + ": receipt differs from independently hashed bytes")
            if expected_mismatch:
                if process.stdout == expected or fixtures.digest(process.stdout) == fixtures.digest(expected):
                    raise AssertionError(name + ": mutated ciphertext did not change observed plaintext")
            elif process.stdout != expected or fixtures.digest(process.stdout) != fixtures.digest(expected):
                raise AssertionError(name + ": plaintext differs from supplied literal oracle")
        observations.append({"name": name, "status": diagnostic["status"], "code": diagnostic.get("code"),
                             "profile": profile, "elapsedMilliseconds": elapsed, "outputBytes": len(process.stdout),
                             "outputSHA256": fixtures.digest(process.stdout),
                             "keychainObserved": "keychainAfter" in diagnostic,
                             "dataProtectionObservation": protection_after,
                             "plaintextOracle": "mismatch-preserved" if expected_mismatch else "exact" if not expected_error else "rejected"})

    for entry in manifest["cases"]:
        attempt(entry["name"], entry)
        attempt(entry["name"] + "-der", entry, profile="der")
        if "ntfs" in entry:
            source = corpus / (entry["name"] + ".raw")
            before = fixtures.ntfs._hash(source)
            # Fixed, independent generator extents; this is not a TSK runlist test.
            with source.open("rb") as stream:
                stream.seek(100 * 4096); first = stream.read(4096)
                stream.seek(104 * 4096); remainder = stream.read(entry["physicalBytes"] - 4096)
            if fixtures.digest(first + remainder) != entry["ciphertextSHA256"]:
                raise AssertionError("Independent fragmented ciphertext geometry mismatch")
            attempt(entry["name"] + "-raw-fragment-oracle", entry, ciphertext=first + remainder)
            attempt(entry["name"] + "-der-raw-fragment-oracle", entry, ciphertext=first + remainder, profile="der")
            if fixtures.ntfs._hash(source) != before:
                raise AssertionError("Synthetic raw source changed")

    base = next(item for item in manifest["cases"] if item["name"] == "one-unit")
    data = (corpus / (base["name"] + ".efs")).read_bytes()
    # Literal Microsoft layout offsets:84 fixed header +4 array +20 entry,
    # 28 PublicKeyInfo +20 CertificateData +20 SHA1 +256 RSA.
    mutations = [
        ("length-mismatch", 0, len(data) - 1, "EFS_INVALID_METADATA"),
        ("efs-version1", 8, 1, "EFS_UNSUPPORTED_VERSION"),
        ("efs-version4", 8, 4, "EFS_UNSUPPORTED_VERSION"),
        ("efs-version5", 8, 5, "EFS_UNSUPPORTED_VERSION"),
        ("efs-version6", 8, 6, "EFS_UNSUPPORTED_VERSION"),
        ("array-in-header", 64, 72, "EFS_INVALID_METADATA"),
        ("array-outside", 64, 0xffffffff, "EFS_INVALID_METADATA"),
        ("no-recipient", 64, 0, "EFS_NO_RECIPIENT"),
        ("array-zero-count", 84, 0, "EFS_RECIPIENT_LIMIT"),
        ("array-too-many", 84, 65, "EFS_RECIPIENT_LIMIT"),
        ("entry-zero-length", 88, 0, "EFS_INVALID_METADATA"),
        ("entry-overflow-length", 88, 0xffffffff, "EFS_INVALID_METADATA"),
        ("credential-in-header", 92, 4, "EFS_UNSUPPORTED_RECIPIENT"),
        ("wrapped-key-small", 96, 64, "EFS_UNSUPPORTED_RECIPIENT"),
        ("wrapped-key-overflow", 100, 0xffffffff, "EFS_INVALID_METADATA"),
        ("wrapped-key-overlap", 100, 24, "EFS_INVALID_METADATA"),
        ("smartcard-wrap", 104, 1, "EFS_UNSUPPORTED_KEY_WRAPPING"),
        ("credential-zero-length", 108, 0, "EFS_INVALID_METADATA"),
        ("credential-overflow-length", 108, 0xffffffff, "EFS_INVALID_METADATA"),
        ("owner-hint-overlap", 112, 28, "EFS_INVALID_METADATA"),
        ("legacy-credential", 116, 1, "EFS_UNSUPPORTED_CREDENTIAL"),
        ("certificate-header-small", 120, 16, "EFS_INVALID_METADATA"),
        ("certificate-header-overflow", 124, 0xffffffff, "EFS_INVALID_METADATA"),
        ("thumbprint-outside", 136, 0xffffffff, "EFS_INVALID_METADATA"),
        ("thumbprint-size", 140, 19, "EFS_UNSUPPORTED_RECIPIENT"),
        ("name-overlaps-thumb", 144, 20, "EFS_INVALID_METADATA"),
        ("name-odd-offset", 152, 21, "EFS_INVALID_METADATA"),
    ]
    attempt("efs-version3-rsa-aes256", base, efs=changed(data, 8, 3))
    attempt("efs-version3-rsa-aes256-der", base, efs=changed(data, 8, 3), profile="der")
    for name, offset, value, error in mutations:
        attempt(name, base, efs=changed(data, offset, value), expected_error=error)
        attempt(name + "-der", base, efs=changed(data, offset, value), expected_error=error, profile="der")
    attempt("truncated-metadata", base, efs=data[:83], expected_error="EFS_INVALID_METADATA")
    attempt("wrong-private-key", base, owner="ddf4096", expected_error="EFS_NO_MATCHING_PRIVATE_KEY")
    attempt("wrong-password", base, password=b"KnownSyntheticWrongPassword", expected_error="EFS_KEY_IMPORT_FAILED")
    attempt("invalid-utf8-password", base, password=b"\xff\xfe", expected_error="EFS_KEY_INPUT_INVALID")
    attempt("nul-password", base, password=b"\0", expected_error="EFS_KEY_INPUT_LIMIT")
    attempt("unsupported-3des", base, efs=(corpus / "unsupported-3des.efs").read_bytes(), expected_error="EFS_UNSUPPORTED_CONTENT_CIPHER")
    attempt("wrong-certificate-purpose", base, efs=(corpus / "wrong-purpose.efs").read_bytes(), owner="wrongPurpose", expected_error="EFS_CERTIFICATE_PURPOSE_MISMATCH")
    wrapped_corruption = bytearray(data); wrapped_corruption[-1] ^= 0x40
    attempt("rsa-padding-corruption", base, efs=bytes(wrapped_corruption), expected_error="EFS_INVALID_WRAPPED_KEY")
    ciphertext = bytearray((corpus / (base["name"] + ".ciphertext")).read_bytes()); ciphertext[137] ^= 1
    attempt("cbc-tampering-is-not-authenticated", base, ciphertext=bytes(ciphertext), expected_mismatch=True)
    attempt("trailing-wire-bytes", base, trailing=b"x", expected_error="PROBE_TRAILING_INPUT")
    attempt("missing-final-physical-sector", base, ciphertext=b"", expected_error="PROBE_INPUT_LIMIT")
    attempt("der-wrong-private-key-for-certificate", base, profile="der",
            credential=(corpus / "ddf4096.private.pkcs1.der").read_bytes(), expected_error="EFS_CERTIFICATE_PRIVATE_KEY_MISMATCH")
    attempt("der-malformed-private-key", base, profile="der", credential=b"not DER", expected_error="EFS_KEY_INPUT_INVALID")
    attempt("der-truncated-private-key", base, profile="der", credential=(corpus / "ddf2048.private.pkcs1.der").read_bytes()[:-1], expected_error="EFS_KEY_INPUT_INVALID")
    attempt("der-wrong-algorithm", base, profile="der", credential=(corpus / "wrongAlgorithm.private.pkcs1.der").read_bytes(), expected_error="EFS_UNSUPPORTED_PRIVATE_KEY_TYPE")
    attempt("der-wrong-certificate-algorithm", base, profile="der", certificate_override=(corpus / "wrongAlgorithm.certificate.der").read_bytes(), expected_error="EFS_UNSUPPORTED_CERTIFICATE_KEY")
    attempt("der-wrong-certificate-purpose", base, profile="der", efs=(corpus / "wrong-purpose.efs").read_bytes(), owner="wrongPurpose", expected_error="EFS_CERTIFICATE_PURPOSE_MISMATCH")
    attempt("der-nonempty-password", base, profile="der", password=b"does-not-apply", expected_error="PROBE_INPUT_LIMIT")
    attempt("der-private-key-size-bound", base, profile="der", credential=b"x" * (64 * 1024 + 1), expected_error="PROBE_INPUT_LIMIT")
    attempt("der-invalid-fek-entropy", base, profile="der", efs=(corpus / "invalid-entropy.efs").read_bytes(), expected_error="EFS_INVALID_FILE_KEY")
    def der_integer(body):
        length_bytes = len(body).to_bytes(max(1, (len(body).bit_length() + 7) // 8), "big")
        length = bytes([len(body)]) if len(body) < 128 else bytes([0x80 | len(length_bytes)]) + length_bytes
        return b"\x02" + length + body
    # Canonical PKCS1 structures with unsupported bounded INTEGER geometry.
    # No real private key is contained in these intentionallyfake parameters.
    for name, modulus, exponent in [
        ("der-oversize-modulus", b"\x00\x80" + bytes(2047), b"\x01\x00\x01"),
        ("der-unsupported1536bit-modulus", b"\x00\x80" + bytes(191), b"\x01\x00\x01"),
        ("der-overlarge-public-exponent", b"\x00\x80" + bytes(255), b"\x01" + bytes(8)),
        ("der-even-public-exponent", b"\x00\x80" + bytes(255), b"\x02"),
    ]:
        fields = [b"\0", modulus, exponent] + [b"\x01"] * 6
        content = b"".join(der_integer(item) for item in fields)
        length_bytes = len(content).to_bytes(max(1, (len(content).bit_length() + 7) // 8), "big")
        length = bytes([len(content)]) if len(content) < 128 else bytes([0x80 | len(length_bytes)]) + length_bytes
        key_data = b"\x30" + length + content
        attempt(name, base, profile="der", credential=key_data, expected_error="EFS_UNSUPPORTED_PRIVATE_KEY")
    sid_case = next(row for row in manifest["cases"] if row["name"] == "legacy1024-packed-sid")
    sid_data = (corpus / (sid_case["name"] + ".efs")).read_bytes()
    # Literal fixture offsets:84+4+20+28 => SID starts136; byte0revision,
    # byte1subauthority count. Its declaredregion is28 bytes; certificate starts164.
    for name, blob in [
        ("sid-wrong-revision", sid_data[:136] + b"\x02" + sid_data[137:]),
        ("sid-excess-subauthorities", sid_data[:137] + b"\x10" + sid_data[138:]),
        ("sid-declared-overflow", changed(sid_data, 112, 0xffffffff)),
        ("sid-overlap-certificate", changed(sid_data, 112, 32)),
    ]:
        attempt(name, sid_case, efs=blob, expected_error="EFS_INVALID_METADATA", profile="der")
    protection_verified = all(row["dataProtectionObservation"]["available"]
        for row in observations if row["dataProtectionObservation"] is not None)
    return {"schemaVersion": 1, "checkCount": len(observations), "passed": len(observations),
            "syntheticOnly": True, "windowsInteroperabilityProven": False,
            "nativeEngineIntegrationProven": False, "keychainScope": "generated identities only, before/after/after process exit",
            "dataProtectionStoreVerified": protection_verified,
            "observations": observations}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = run(args.probe.resolve(), args.corpus.resolve())
    if args.report:
        fixtures.exclusive(args.report, (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({key: value for key, value in result.items() if key != "observations"}, sort_keys=True))
