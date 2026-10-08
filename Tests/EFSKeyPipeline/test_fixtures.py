"""Small independent fixture and secret-transport guards; no production build."""
import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

import fixtures


class FixtureTests(unittest.TestCase):
    def test_independent_standard_AES256_CBC_known_answer(self):
        fixtures.OpenSSLAES().nist_known_answer()

    def test_MS_metadata_lengths_and_relative_offsets(self):
        owner = {"role": "ddf", "public_key": b"disposablePublic", "thumbprint": bytes(range(20))}
        wrapped = bytes(range(256))
        fek = struct.pack("<IIII", 32, 256, 0x6610, 0) + bytes(range(32))
        with patch.object(fixtures, "openssl", return_value=wrapped):
            body = fixtures.metadata([(owner, fek)])
        self.assertEqual(len(body), 84 + 4 + 20 + 28 + 40 + 256)
        self.assertEqual(struct.unpack_from("<I", body, 0)[0], len(body))
        self.assertEqual(struct.unpack_from("<I", body, 8)[0], 2)
        self.assertEqual(struct.unpack_from("<II", body, 64), (84, 0))
        self.assertEqual(struct.unpack_from("<I", body, 84)[0], 1)
        self.assertEqual(struct.unpack_from("<IIIII", body, 88), (344, 20, 256, 88, 0))
        self.assertEqual(struct.unpack_from("<IIIIIII", body, 108), (68, 0, 3, 40, 28, 0, 0))
        self.assertEqual(body[156:176], bytes(range(20)))
        self.assertEqual(body[176:], wrapped[::-1])

    def test_distinct_ciphertext_units_use_logical_offsets(self):
        aes = fixtures.OpenSSLAES()
        key = bytes(range(32))
        plaintext = bytes(1024)
        ciphertext = fixtures.encrypted_bytes(aes, plaintext, key)
        self.assertNotEqual(ciphertext[:512], ciphertext[512:])
        self.assertEqual(len(ciphertext), 1024)
        first = aes.encrypt(bytes(512), key, struct.pack("<QQ", 0x5816657BE9161312, 0x1989ADBE44918961))
        second = aes.encrypt(bytes(512), key, struct.pack("<QQ", 0x5816657BE9161312 + 512, 0x1989ADBE44918961 + 512))
        self.assertEqual(ciphertext, first + second)

    def test_partial_last_unit_is_physically_complete(self):
        result = fixtures.encrypted_bytes(fixtures.OpenSSLAES(), b"x" * 513, bytes(range(32)))
        self.assertEqual(len(result), 1024)
        self.assertEqual(fixtures.encrypted_bytes(fixtures.OpenSSLAES(), b"", bytes(range(32))), b"")

    def test_generated_secret_files_exclusive0600(self):
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT / "local") as directory:
            destination = Path(directory) / "disposable.pfx"
            fixtures.exclusive(destination, b"syntheticSecret")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                fixtures.exclusive(destination, b"changed")
            self.assertEqual(destination.read_bytes(), b"syntheticSecret")

    def test_password_and_key_bytes_only_anonymous_pipe(self):
        secret_key = b"SYNTHETIC-ONLY-PRIVATE-KEY"
        password = b"SYNTHETIC-ONLY-PASSWORD"
        seen = {}
        class Result:
            returncode = 0
            stdout = b"syntheticContainer"
        def run(argv, **options):
            seen["argv"] = argv
            seen["options"] = options
            self.assertNotIn(secret_key.decode(), repr(argv))
            self.assertNotIn(password.decode(), repr(argv))
            self.assertNotIn("env", options)
            descriptors = options["pass_fds"]
            seen["pipeValues"] = [os.read(fd, 4096) for fd in descriptors]
            return Result()
        with patch.object(fixtures.subprocess, "run", side_effect=run):
            result = fixtures.openssl_password(["pkcs12", "-inkey", secret_key,
                                               "-passout", "PASSWORD_DESCRIPTOR"], password)
        self.assertEqual(result, b"syntheticContainer")
        self.assertEqual(seen["pipeValues"], [password + b"\n", secret_key])
        for fd in seen["options"]["pass_fds"]:
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
