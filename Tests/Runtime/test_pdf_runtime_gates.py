"""Pure regressions for independent PDF text, refusal and lifecycle oracles.

No document parser, fixture generator process, signed executable, or provider
is launched. PDF byte construction below invokes only the stdlib producer.
"""
import copy
import hashlib
import re
import unittest
from unittest.mock import patch

import run_document_runtime_gates as gates
import run_pdf_runtime_gates as pdf


EXPECTED_PAGES = ("A😀ก้e\u0301Z", "Bก้😀e\u0301Y")
EXPECTED_UTF16 = ("41003dd800de010e490e650001035a00",
                  "4200010e490e3dd800de650001035900")
EXPECTED_RANGES = [
    {"pageNumber": 1, "utf16Offset": 1, "utf16Length": 2, "literal": "😀"},
    {"pageNumber": 1, "utf16Offset": 3, "utf16Length": 1, "literal": "ก"},
    {"pageNumber": 1, "utf16Offset": 4, "utf16Length": 1, "literal": "้"},
    {"pageNumber": 1, "utf16Offset": 5, "utf16Length": 2, "literal": "e\u0301"},
    {"pageNumber": 1, "utf16Offset": 6, "utf16Length": 1, "literal": "\u0301"},
    {"pageNumber": 1, "utf16Offset": 7, "utf16Length": 1, "literal": "Z"},
    {"pageNumber": 2, "utf16Offset": 1, "utf16Length": 1, "literal": "ก"},
    {"pageNumber": 2, "utf16Offset": 2, "utf16Length": 1, "literal": "้"},
    {"pageNumber": 2, "utf16Offset": 3, "utf16Length": 2, "literal": "😀"},
    {"pageNumber": 2, "utf16Offset": 5, "utf16Length": 2, "literal": "e\u0301"},
    {"pageNumber": 2, "utf16Offset": 6, "utf16Length": 1, "literal": "\u0301"},
    {"pageNumber": 2, "utf16Offset": 7, "utf16Length": 1, "literal": "Y"},
]


class PDFOracleFixtures(unittest.TestCase):
    def setUp(self):
        self.source = {"sha256": "3" * 64, "bytes": 64}
        self.identities = {
            "worker": {"sha256": "1" * 64, "codeSigningCDHash": "1" * 40,
                       "path": "/synthetic/app/worker"},
            "broker": {"sha256": "2" * 64, "codeSigningCDHash": "2" * 40,
                       "path": "/synthetic/app/broker"},
        }

    @staticmethod
    def pages():
        return [{"pageNumber": number, "text": text, "isTruncated": False,
                 "referenceLabel": f"Page {number}", "referenceKind": "page"}
                for number, text in enumerate(EXPECTED_PAGES, 1)]

    def analysis(self, locked=False):
        pages = [] if locked else self.pages()
        options = {"timeoutSeconds": 12.0, "maximumInputBytes": 128 * gates.MIB,
                   "maximumResponseBytes": 2 * gates.MIB, "maximumTextBytes": gates.MIB,
                   "maximumThumbnailBytes": 512 * 1024, "maximumImagePixels": 100000000,
                   "maximumPages": 200, "maximumMetadataItems": 128, "maximumArchiveMembers": 128,
                   "maximumMetadataValueBytes": 4096, "allowInferredWindows1252": True,
                   "previewedImageFrame": 1, "previewedPDFPage": 1, "includesOCR": False,
                   "evaluatesOfficeFormulasOrMacros": False, "fetchesExternalResources": False}
        provenance = {
            "schemaVersion": 1, "decoderIdentifier": "NativeForensics.document-decoder",
            "decoderVersion": "2.1.0", "isolation": "appSandboxXPC", "options": options,
            "decoderExecutableSHA256": self.identities["worker"]["sha256"],
            "decoderCodeSigningCDHash": self.identities["worker"]["codeSigningCDHash"],
            "brokerExecutableSHA256": self.identities["broker"]["sha256"],
            "brokerCodeSigningCDHash": self.identities["broker"]["codeSigningCDHash"],
            "optionsSHA256": gates.document_receipt_digest(options),
            "derivedTextSHA256": gates.document_receipt_digest(pages),
        }
        value = {"schemaVersion": 2, "contentKind": "pdf", "mimeType": "application/pdf",
                 "status": "failed" if locked else "decoded", "sourceSHA256": self.source["sha256"],
                 "sourceByteCount": self.source["bytes"], "textPages": pages,
                 "rawMetadata": [], "warnings": [], "provenance": provenance}
        if locked:
            value["failureCode"] = "LOCKED_PDF"
        else:
            value["pageCount"] = 2
        return value

    @staticmethod
    def rehash_text(analysis):
        analysis["provenance"]["derivedTextSHA256"] = gates.document_receipt_digest(analysis["textPages"])

    def validate(self, analysis, locked=False):
        validator = pdf.validate_locked_pdf if locked else pdf.validate_unicode_pdf
        return validator(analysis, self.source, self.identities, timeout=12.0)

    def lifecycle_gate(self, locked=False):
        observer = {"processIdentifier": 101, "parentProcessIdentifier": 100,
                    "startSeconds": 1234, "startMicroseconds": 5678,
                    "role": "worker", "path": self.identities["worker"]["path"],
                    "physicalExitObserved": True, "physicalExitUptimeNanoseconds": 150}
        return {
            "signedExecutables": copy.deepcopy(self.identities),
            "report": {"available": True, "attempts": [{"ordinal": 1, "analysis": self.analysis(locked),
                                                          "errorCode": None}],
                       "events": [{"ordinal": 1, "kind": kind, "processIdentifier": 101,
                                   "uptimeNanoseconds": timestamp}
                                  for kind, timestamp in (("started", 100), ("exited", 200))]},
            "physicalObservers": [observer],
            "observedWorkerIdentity": {key: value for key, value in observer.items()
                                       if not key.startswith("physicalExit")},
            "memory": {"observedProcesses": [{key: value for key, value in observer.items()
                                                if not key.startswith("physicalExit")}]},
        }


class UnicodePDFOracleTests(PDFOracleFixtures):
    def test_fixed_literals_and_raw_utf16_ranges_are_independent(self):
        self.assertEqual(pdf.UNICODE_PAGES, EXPECTED_PAGES)
        self.assertEqual(pdf.LOCKED_CONTROL, "NF LOCK CONTROL")
        value = pdf.validate_fixed_utf16(self.pages())
        self.assertEqual(value["rawUtf16Ranges"], EXPECTED_RANGES)
        self.assertEqual(tuple(value["pageUTF16LEHex"]), EXPECTED_UTF16)
        for page, expected in zip(self.pages(), EXPECTED_UTF16):
            self.assertEqual(page["text"].encode("utf-16le").hex(), expected)
            self.assertEqual(len(page["text"].encode("utf-8")), 15)
        for span in value["rawUtf16Ranges"]:
            raw = bytes.fromhex(EXPECTED_UTF16[span["pageNumber"] - 1])
            start = span["utf16Offset"] * 2
            end = start + span["utf16Length"] * 2
            self.assertEqual(raw[start:end].decode("utf-16le"), span["literal"])

    def test_positive_unicode_pdf_uses_existing_decoded_receipt_oracle(self):
        analysis = self.analysis()
        with patch.object(gates, "validate_attempt", wraps=gates.validate_attempt) as receipt_oracle:
            self.validate(analysis)
        receipt_oracle.assert_called_once_with(analysis, self.source, self.identities, 12.0)

    def test_nfc_missing_mark_replacement_and_extra_text_fail_even_after_rehash(self):
        substitutions = [("nfc", "A😀ก้éZ"), ("missing-tone", "A😀กe\u0301Z"),
                         ("replacement", "A\ufffdก้e\u0301Z"), ("extra-newline", EXPECTED_PAGES[0] + "\n")]
        for name, text in substitutions:
            with self.subTest(name=name):
                analysis = self.analysis()
                analysis["textPages"][0]["text"] = text
                self.rehash_text(analysis)
                with self.assertRaises(AssertionError):
                    self.validate(analysis)
                with self.assertRaises(AssertionError):
                    pdf.validate_fixed_utf16(analysis["textPages"])

    def test_reversed_page_text_cannot_pass_with_valid_recomputed_digest(self):
        analysis = self.analysis()
        analysis["textPages"][0]["text"], analysis["textPages"][1]["text"] = EXPECTED_PAGES[::-1]
        self.rehash_text(analysis)
        with self.assertRaises(AssertionError):
            self.validate(analysis)

    def test_page_inventory_reference_and_truncation_are_required(self):
        mutations = [lambda a: a.update(pageCount=1), lambda a: a["textPages"].pop(),
                     lambda a: a["textPages"][0].update(pageNumber=2),
                     lambda a: a["textPages"].reverse(),
                     lambda a: a["textPages"][0].update(referenceLabel="Text document"),
                     lambda a: a["textPages"][0].update(referenceKind="document"),
                     lambda a: a["textPages"][0].update(isTruncated=True)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                analysis = self.analysis()
                mutate(analysis)
                self.rehash_text(analysis)
                with self.assertRaises(AssertionError):
                    self.validate(analysis)

    def test_pdf_kind_mime_schema_and_decoded_status_cannot_be_relabelled(self):
        for field, value in (("contentKind", "text"), ("mimeType", "text/plain"),
                             ("schemaVersion", 1), ("status", "unsupported"), ("status", "failed")):
            with self.subTest(field=field, value=value):
                analysis = self.analysis()
                analysis[field] = value
                with self.assertRaises(AssertionError):
                    self.validate(analysis)


class PDFReceiptBindingTests(PDFOracleFixtures):
    def test_source_byte_count_and_hash_are_bound_for_success_and_refusal(self):
        for locked in (False, True):
            for field, value in (("sourceByteCount", 63), ("sourceSHA256", "4" * 64)):
                with self.subTest(locked=locked, field=field):
                    analysis = self.analysis(locked)
                    analysis[field] = value
                    with self.assertRaises(AssertionError):
                        self.validate(analysis, locked)

    def test_worker_broker_isolation_and_contract_are_bound_for_both_statuses(self):
        fields = (("decoderExecutableSHA256", "4" * 64), ("decoderCodeSigningCDHash", "4" * 40),
                  ("brokerExecutableSHA256", "4" * 64), ("brokerCodeSigningCDHash", "4" * 40),
                  ("decoderIdentifier", "foreign.parser"), ("decoderVersion", "2.0.0"),
                  ("schemaVersion", 0), ("isolation", "testFixture"))
        for locked in (False, True):
            for field, value in fields:
                with self.subTest(locked=locked, field=field):
                    analysis = self.analysis(locked)
                    analysis["provenance"][field] = value
                    with self.assertRaises(AssertionError):
                        self.validate(analysis, locked)

    def test_rehashed_changed_input_response_text_and_timeout_caps_are_rejected(self):
        fields = (("maximumInputBytes", 32 * gates.MIB), ("maximumResponseBytes", gates.MIB),
                  ("maximumTextBytes", gates.MIB - 1), ("timeoutSeconds", 11.0))
        for locked in (False, True):
            for field, value in fields:
                with self.subTest(locked=locked, field=field):
                    analysis = self.analysis(locked)
                    options = analysis["provenance"]["options"]
                    options[field] = value
                    analysis["provenance"]["optionsSHA256"] = gates.document_receipt_digest(options)
                    with self.assertRaises(AssertionError):
                        self.validate(analysis, locked)

    def test_missing_provenance_and_stale_options_or_derived_text_digest_fail(self):
        for locked in (False, True):
            for field in (None, "optionsSHA256", "derivedTextSHA256"):
                with self.subTest(locked=locked, field=field):
                    analysis = self.analysis(locked)
                    if field is None:
                        analysis.pop("provenance")
                    else:
                        analysis["provenance"][field] = "4" * 64
                    with self.assertRaises(AssertionError):
                        self.validate(analysis, locked)


class LockedPDFOracleTests(PDFOracleFixtures):
    def test_locked_pdf_is_a_bound_semantic_failure_without_readable_content(self):
        self.validate(self.analysis(locked=True), locked=True)
        pdf.validate_pdf_lifecycle(self.lifecycle_gate(locked=True))

    def test_malformed_unsupported_success_and_missing_failure_code_do_not_prove_lock(self):
        mutations = [lambda a: a.update(failureCode="MALFORMED_PDF"), lambda a: a.pop("failureCode"),
                     lambda a: a.update(status="unsupported"), lambda a: a.update(status="decoded"),
                     lambda a: a.update(contentKind="unknown"), lambda a: a.update(mimeType="text/plain")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                analysis = self.analysis(locked=True)
                mutate(analysis)
                with self.assertRaises(AssertionError):
                    self.validate(analysis, locked=True)

    def test_rehashed_locked_plaintext_and_thumbnail_leakage_fail(self):
        for field, value in (("textPages", self.pages()), ("thumbnailPNG", "c3ludGhldGlj"),
                             ("title", "NF LOCK CONTROL"), ("pageCount", 1),
                             ("warnings", ["NF LOCK CONTROL"]),
                             ("rawMetadata", [{"name": "PDF.Title", "value": "NF LOCK CONTROL"}])):
            with self.subTest(field=field):
                analysis = self.analysis(locked=True)
                analysis[field] = value
                self.rehash_text(analysis)
                with self.assertRaises(AssertionError):
                    self.validate(analysis, locked=True)

    def test_transport_error_is_not_semantic_locked_pdf_refusal(self):
        gate = self.lifecycle_gate(locked=True)
        gate["report"]["attempts"][0].update(analysis=None, errorCode="invalidResponse")
        with self.assertRaises(AssertionError):
            pdf.validate_pdf_lifecycle(gate)


class PDFLifecycleOracleTests(PDFOracleFixtures):
    def test_single_accepted_worker_needs_independent_physical_exit(self):
        pdf.validate_pdf_lifecycle(self.lifecycle_gate())

    def test_missing_duplicate_and_reversed_lifecycle_events_fail(self):
        mutations = [lambda g: g["report"]["events"].pop(),
                     lambda g: g["report"]["events"].append(copy.deepcopy(g["report"]["events"][-1])),
                     lambda g: g["report"]["events"].reverse(),
                     lambda g: g["report"]["events"][1].update(uptimeNanoseconds=100),
                     lambda g: g["report"]["events"][1].update(processIdentifier=102),
                     lambda g: g["report"]["events"][0].update(ordinal=2)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                gate = self.lifecycle_gate()
                mutate(gate)
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)

    def test_backend_and_exact_one_successful_transport_attempt_are_required(self):
        mutations = [lambda g: g["report"].update(available=False),
                     lambda g: g["report"]["attempts"].clear(),
                     lambda g: g["report"]["attempts"].append(copy.deepcopy(g["report"]["attempts"][0])),
                     lambda g: g["report"]["attempts"][0].update(ordinal=2),
                     lambda g: g["report"]["attempts"][0].update(errorCode="timeout")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                gate = self.lifecycle_gate()
                mutate(gate)
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)

    def test_exact_observer_count_and_kernel_exit_are_required(self):
        for mutation in (lambda g: g["physicalObservers"].clear(),
                         lambda g: g["physicalObservers"].append(copy.deepcopy(g["physicalObservers"][0])),
                         lambda g: g["physicalObservers"][0].update(physicalExitObserved=False)):
            gate = self.lifecycle_gate()
            mutation(gate)
            with self.assertRaises(AssertionError):
                pdf.validate_pdf_lifecycle(gate)

    def test_observer_pid_path_role_and_birth_cannot_be_unbound(self):
        fields = (("processIdentifier", 102), ("path", "/synthetic/foreign/worker"),
                  ("role", "broker"), ("startSeconds", 0), ("startMicroseconds", -1))
        for field, value in fields:
            with self.subTest(field=field):
                gate = self.lifecycle_gate()
                gate["physicalObservers"][0][field] = value
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)
        for field in ("path", "startSeconds", "startMicroseconds"):
            with self.subTest(missing=field):
                gate = self.lifecycle_gate()
                gate["physicalObservers"][0].pop(field)
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)

    def test_observer_birth_and_parent_must_match_independent_initial_sample(self):
        for field, value in (("startSeconds", 1235), ("startMicroseconds", 5679),
                             ("parentProcessIdentifier", 999)):
            with self.subTest(field=field):
                gate = self.lifecycle_gate()
                gate["physicalObservers"][0][field] = value
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)
        for sampled in ({}, None):
            with self.subTest(sampled=sampled):
                gate = self.lifecycle_gate()
                if sampled is None:
                    gate.pop("observedWorkerIdentity")
                else:
                    gate["observedWorkerIdentity"] = sampled
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)

    def test_complete_foreign_observer_sample_cannot_replace_signed_accepted_worker(self):
        for field, value in (("processIdentifier", 102), ("path", "/synthetic/foreign/worker"),
                             ("role", "broker")):
            with self.subTest(field=field):
                gate = self.lifecycle_gate()
                gate["physicalObservers"][0][field] = value
                gate["observedWorkerIdentity"][field] = value
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)

    def test_signed_worker_path_cannot_be_missing_or_empty(self):
        mutations = [lambda g: g.pop("signedExecutables"),
                     lambda g: g["signedExecutables"].pop("worker"),
                     lambda g: g["signedExecutables"]["worker"].pop("path"),
                     lambda g: g["signedExecutables"]["worker"].update(path="")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                gate = self.lifecycle_gate()
                mutate(gate)
                with self.assertRaises(AssertionError):
                    pdf.validate_pdf_lifecycle(gate)


class LiteralPDFProducerTests(unittest.TestCase):
    def test_pdf_object_offsets_stream_lengths_and_unicode_mapping_are_coherent(self):
        body = pdf.pdf_bytes(EXPECTED_PAGES)
        self.assertIsInstance(body, bytes)
        self.assertEqual(body, pdf.pdf_bytes(EXPECTED_PAGES))
        self.assertLess(len(body), 64 * 1024)
        self.assertTrue(body.startswith(b"%PDF-"))
        self.assertIn(b"/ToUnicode", body)
        self.assertIn(b"D83DDE00", body.upper())
        for scalar in (b"0E01", b"0E49", b"0301"):
            self.assertIn(scalar, body.upper())
        end = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", body)
        self.assertIsNotNone(end)
        xref_offset = int(end.group(1))
        table = re.match(rb"xref\s+0\s+(\d+)\s*\n", body[xref_offset:])
        self.assertIsNotNone(table)
        count = int(table.group(1))
        self.assertGreaterEqual(count, 7)
        cursor = xref_offset + table.end()
        for number in range(count):
            row = re.match(rb"(\d{10}) (\d{5}) ([fn])\s*\n", body[cursor:])
            self.assertIsNotNone(row)
            cursor += row.end()
            if number == 0:
                self.assertEqual(row.group(3), b"f")
            else:
                self.assertEqual(row.group(3), b"n")
                offset = int(row.group(1))
                self.assertLess(offset, xref_offset)
                self.assertTrue(body[offset:].startswith(f"{number} 0 obj\n".encode()))
        stream_count = 0
        for object_body in re.findall(rb"\d+ 0 obj\n(.*?)\nendobj\n", body[:xref_offset], re.S):
            start = re.search(rb"\bstream\r?\n", object_body)
            if start is None:
                continue
            stream_count += 1
            length = re.search(rb"/Length\s+(\d+)\b", object_body[:start.start()])
            self.assertIsNotNone(length)
            suffix = object_body[start.end() + int(length.group(1)):]
            self.assertRegex(suffix, rb"^\r?\n?endstream\s*$")
        self.assertGreaterEqual(stream_count, 3)
        objects = {int(number): object_body for number, object_body in
                   re.findall(rb"(\d+) 0 obj\n(.*?)\nendobj\n", body[:xref_offset], re.S)}

        def reference(dictionary, key):
            value = re.search(rb"/" + key + rb"\s+(\d+)\s+0\s+R", dictionary)
            self.assertIsNotNone(value)
            return int(value.group(1))

        def stream(dictionary):
            start = re.search(rb"\bstream\r?\n", dictionary)
            length = re.search(rb"/Length\s+(\d+)\b", dictionary[:start.start()])
            return dictionary[start.end():start.end() + int(length.group(1))]

        cmap_ids = [reference(object_body, b"ToUnicode") for object_body in objects.values()
                    if b"/ToUnicode" in object_body]
        self.assertEqual(len(cmap_ids), 1)
        cmap = stream(objects[cmap_ids[0]])
        mapping = {int(code, 16): bytes.fromhex(value.decode()).decode("utf-16be")
                   for code, value in re.findall(rb"<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{4,})>", cmap)}
        self.assertEqual(set(mapping.values()), set("".join(EXPECTED_PAGES)))
        root = reference(body[xref_offset:], b"Root")
        pages = objects[reference(objects[root], b"Pages")]
        kids = re.search(rb"/Kids\s*\[([^]]+)\]", pages)
        self.assertIsNotNone(kids)
        page_ids = [int(number) for number in re.findall(rb"(\d+)\s+0\s+R", kids.group(1))]
        decoded = []
        for page_id in page_ids:
            content = stream(objects[reference(objects[page_id], b"Contents")])
            glyphs = re.findall(rb"<([0-9A-Fa-f]+)>\s*Tj", content)
            self.assertEqual(len(glyphs), 1)
            decoded.append("".join(mapping[code] for code in bytes.fromhex(glyphs[0].decode())))
        self.assertEqual(tuple(decoded), EXPECTED_PAGES)
        self.assertNotIn(b"/Encrypt", body)
        self.assertNotEqual(hashlib.sha256(body).digest(), hashlib.sha256(pdf.pdf_bytes(("NF LOCK CONTROL",))).digest())


if __name__ == "__main__":
    unittest.main()
