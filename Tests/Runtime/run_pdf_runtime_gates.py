#!/usr/bin/env python3
"""Owned synthetic PDF gates against an unchanged, already-signed app copy.

No compiler, signer, GUI, password prompt, provider call or user PDF is used.
The fixed ToUnicode fixture tests extraction semantics, not visual Thai/emoji
glyph layout, OCR, production search coordinates or all real-world PDFs.
Run only in the coordinator's serialized runtime window. Retain all artifacts.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import run_document_runtime_gates as runtime

UNICODE_PAGES = ("A😀ก้e\u0301Z", "Bก้😀e\u0301Y")
UNICODE_UTF16LE_HEX = ("41003dd800de010e490e650001035a00", "4200010e490e3dd800de650001035900")
LOCKED_CONTROL = "NF LOCK CONTROL"
# Public fixture constants, deliberately not credentials or caller input.
TEST_USER_PASSWORD = "NativeForensics-public-synthetic-user-20261008"
TEST_OWNER_PASSWORD = "NativeForensics-public-synthetic-owner-20261008"
GATE_NAMES = ("production-locked-pdf", "production-unicode-pdf")
SCOPE = ("Exact ToUnicode decoder page/raw UTF-16 output only; no visual Thai/emoji glyph-layout, "
         "OCR, production search-offset or general PDF compatibility claim")


def pdf_bytes(pages):
    """Small independent PDF object/xref producer with explicit UTF-16 CMap.

    Standard Helvetica proxy glyphs make the page visible, while ToUnicode
    defines its synthetic text. No platform font/shaping or decoder is called.
    """
    runtime.require(pages and all(isinstance(page, str) and page for page in pages), "empty PDF fixture pages")
    characters = list(dict.fromkeys("".join(pages)))
    runtime.require(len(characters) <= 26, "fixture exceeds proxy glyph alphabet")
    codes = {character: position + 1 for position, character in enumerate(characters)}
    mappings = "\n".join(f"<{code:02X}> <{character.encode('utf-16be').hex().upper()}>"
                         for character, code in codes.items())
    cmap = ("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
            "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
            "/CMapName /NFSyntheticUTF16 def\n/CMapType 2 def\n"
            "1 begincodespacerange\n<00> <FF>\nendcodespacerange\n"
            f"{len(codes)} beginbfchar\n{mappings}\nendbfchar\n"
            "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n").encode("ascii")
    def stream(body):
        return f"<< /Length {len(body)} >>\nstream\n".encode() + body + b"endstream"
    page_ids = [5 + index * 2 for index in range(len(pages))]
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               (f"<< /Type /Pages /Count {len(pages)} /Kids [" +
                " ".join(f"{number} 0 R" for number in page_ids) + "] >>").encode(),
               ("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 1 "
                f"/LastChar {len(codes)} /Widths [" + " ".join("600" for _ in codes) + "] "
                "/Encoding << /Type /Encoding /Differences [1 " +
                " ".join("/" + chr(65 + index) for index in range(len(codes))) +
                "] >> /ToUnicode 4 0 R >>").encode(), stream(cmap)]
    for number, text in zip(page_ids, pages):
        objects.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 180] "
                        f"/Resources << /Font << /F1 3 0 R >> >> /Contents {number + 1} 0 R >>").encode())
        encoded = bytes(codes[character] for character in text).hex().upper()
        objects.append(stream(f"BT /F1 18 Tf 24 120 Td <{encoded}> Tj ET\n".encode()))
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def validate_fixed_utf16(pages):
    runtime.require(isinstance(pages, list) and len(pages) == 2, "wrong fixed Unicode page inventory")
    ranges = ((("😀", 1, 2), ("ก", 3, 1), ("้", 4, 1), ("e\u0301", 5, 2), ("\u0301", 6, 1), ("Z", 7, 1)),
              (("ก", 1, 1), ("้", 2, 1), ("😀", 3, 2), ("e\u0301", 5, 2), ("\u0301", 6, 1), ("Y", 7, 1)))
    observations = []
    for number, (page, literal, units_hex, expected_ranges) in enumerate(
            zip(pages, UNICODE_PAGES, UNICODE_UTF16LE_HEX, ranges), 1):
        text = page.get("text")
        runtime.require(isinstance(text, str) and text.encode("utf-8") == literal.encode("utf-8"),
                        "fixed Unicode page UTF-8 literal changed; no normalization or trimming allowed")
        units = text.encode("utf-16le")
        runtime.require(units.hex() == units_hex and len(units) == 16 and len(text.encode("utf-8")) == 15,
                        "fixed Unicode raw UTF-16 units changed")
        for needle, offset, length in expected_ranges:
            runtime.require(units[offset * 2:(offset + length) * 2] == needle.encode("utf-16le"),
                            "fixed raw UTF-16 range differs")
            observations.append({"pageNumber": number, "literal": needle,
                                 "utf16Offset": offset, "utf16Length": length})
    return {"rawUtf16Ranges": observations, "pageUTF16LEHex": list(UNICODE_UTF16LE_HEX), "scope": SCOPE}


def validate_unicode_pdf(analysis, source, identities, timeout=12.0):
    # Keep the existing decoded positive oracle unchanged and applied to the
    # original response, including its complete derived-text digest.
    runtime.validate_attempt(analysis, source, identities, timeout)
    runtime.require(analysis.get("contentKind") == "pdf" and analysis.get("mimeType") == "application/pdf"
                    and analysis.get("failureCode") is None and analysis.get("pageCount") == 2,
                    "expected a decoded two-page PDF")
    pages = analysis.get("textPages")
    runtime.require(isinstance(pages, list) and len(pages) == 2, "wrong decoded PDF page inventory")
    for number, page in enumerate(pages, 1):
        runtime.require(page.get("pageNumber") == number and page.get("referenceLabel") == f"Page {number}"
                        and page.get("referenceKind") == "page" and page.get("isTruncated") is False,
                        "PDF page reference or complete coverage changed")
    return validate_fixed_utf16(pages)


def validate_locked_pdf(analysis, source, identities, timeout=12.0):
    """A semantic LOCKED_PDF refusal has its own strict origin/digest oracle."""
    runtime.require(analysis.get("schemaVersion") == 2 and analysis.get("status") == "failed"
                    and analysis.get("contentKind") == "pdf" and analysis.get("mimeType") == "application/pdf"
                    and analysis.get("failureCode") == "LOCKED_PDF", "expected semantic LOCKED_PDF refusal")
    runtime.require(analysis.get("textPages") == [] and analysis.get("thumbnailPNG") is None
                    and analysis.get("title") is None and analysis.get("pageCount") is None
                    and analysis.get("rawMetadata") == [] and analysis.get("warnings") == [],
                    "locked PDF disclosed derived content")
    runtime.require(analysis.get("sourceSHA256") == source["sha256"] and analysis.get("sourceByteCount") == source["bytes"],
                    "locked PDF source receipt mismatch")
    origin = analysis.get("provenance", {})
    runtime.require(origin.get("schemaVersion") == 1 and origin.get("decoderIdentifier") == "NativeForensics.document-decoder"
                    and origin.get("decoderVersion") == "2.1.0" and origin.get("isolation") == "appSandboxXPC",
                    "locked PDF decoder origin changed")
    for field, role, key in (("decoderExecutableSHA256", "worker", "sha256"),
                            ("decoderCodeSigningCDHash", "worker", "codeSigningCDHash"),
                            ("brokerExecutableSHA256", "broker", "sha256"),
                            ("brokerCodeSigningCDHash", "broker", "codeSigningCDHash")):
        runtime.require(origin.get(field) == identities[role][key], "locked PDF signed executable provenance mismatch")
    options = origin.get("options", {})
    runtime.require(options.get("maximumInputBytes") == 128 * runtime.MIB and
                    options.get("maximumResponseBytes") == 2 * runtime.MIB and
                    options.get("maximumTextBytes") == runtime.MIB and options.get("timeoutSeconds") == timeout,
                    "locked PDF runtime cap/timeout changed")
    runtime.require(origin.get("optionsSHA256") == runtime.document_receipt_digest(options), "locked PDF options digest differs")
    runtime.require(origin.get("derivedTextSHA256") == runtime.document_receipt_digest([]), "locked PDF empty-text digest differs")
    return {"failureCode": "LOCKED_PDF", "derivedContentAbsent": True, "passwordSubmittedToDecoder": False}


def validate_pdf_lifecycle(gate):
    report = gate["report"]
    runtime.validate_lifecycle(report, 1)
    starts = [event for event in report["events"] if event["kind"] == "started"]
    exits = [event for event in report["events"] if event["kind"] == "exited"]
    runtime.require(len(starts) == len(exits) == 1 and starts[0]["processIdentifier"] == exits[0]["processIdentifier"]
                    and type(starts[0]["processIdentifier"]) is int and starts[0]["processIdentifier"] > 0
                    and 0 < starts[0]["uptimeNanoseconds"] < exits[0]["uptimeNanoseconds"],
                    "PDF accepted worker lacks ordered physical-exit receipt")
    observers = gate.get("physicalObservers", [])
    runtime.require(len(observers) == 1, "PDF worker kernel exit observation unavailable")
    observed = observers[0]
    expected_path = gate.get("signedExecutables", {}).get("worker", {}).get("path")
    sampled = gate.get("observedWorkerIdentity", {})
    runtime.require(isinstance(expected_path, str) and expected_path
                    and observed.get("role") == "worker" and observed.get("physicalExitObserved") is True
                    and observed.get("processIdentifier") == starts[0]["processIdentifier"]
                    and all(type(observed.get(key)) is int and observed[key] >= 0 for key in ("startSeconds", "startMicroseconds"))
                    and observed.get("startSeconds", 0) > 0 and isinstance(observed.get("path"), str) and observed["path"]
                    and observed["path"] == expected_path,
                    "PDF physical observer differs from accepted signed worker")
    runtime.require(all(observed.get(key) is not None and observed[key] == sampled.get(key) for key in
                        ("processIdentifier", "parentProcessIdentifier", "startSeconds", "startMicroseconds", "path", "role")),
                    "PDF physical observer differs from independently sampled worker birth/path")


def write_exclusive(path, body):
    with path.open("xb") as output:
        output.write(body)
    path.chmod(0o400)


def generate_fixtures(root):
    # These imports occur only in the explicitly invoked generator/runtime
    # mode. Compiler-free oracle unit tests need only the standard library.
    from pypdf import PdfReader, PdfWriter
    from pypdf.errors import FileNotDecryptedError
    import pypdf
    import cryptography
    fixture = root / "fixtures"
    fixture.mkdir(mode=0o700)
    unicode_path, control_path, locked_path = (fixture / name for name in ("unicode.pdf", "locked-control.pdf", "locked.pdf"))
    write_exclusive(unicode_path, pdf_bytes(UNICODE_PAGES))
    write_exclusive(control_path, pdf_bytes((LOCKED_CONTROL,)))
    positive = PdfReader(unicode_path)
    runtime.require([page.extract_text() for page in positive.pages] == list(UNICODE_PAGES),
                    "independent ToUnicode fixture readback differs from fixed literals")
    original = PdfReader(control_path)
    runtime.require(len(original.pages) == 1 and original.pages[0].extract_text() == LOCKED_CONTROL,
                    "independent plaintext encryption control differs")
    writer = PdfWriter(clone_from=original)
    writer.pdf_header = "%PDF-1.6"  # AESV2 crypt filters belong to PDF 1.6.
    writer.encrypt(TEST_USER_PASSWORD, TEST_OWNER_PASSWORD, algorithm="AES-128")
    with locked_path.open("xb") as output:
        writer.write(output)
    locked_path.chmod(0o400)
    empty = PdfReader(locked_path)
    runtime.require(empty.is_encrypted and empty.decrypt("") == 0, "encrypted fixture accepts empty password")
    try:
        empty.pages[0]
    except FileNotDecryptedError:
        empty_read_refused = True
    else:
        raise AssertionError("encrypted fixture exposes a page without its nonempty synthetic password")
    known = PdfReader(locked_path)
    runtime.require(known.decrypt(TEST_USER_PASSWORD) != 0 and len(known.pages) == 1
                    and known.pages[0].extract_text() == LOCKED_CONTROL, "known-password fixture control failed")
    encryption = known.trailer["/Encrypt"]
    runtime.require(encryption.get("/Filter") == "/Standard" and encryption.get("/V") == 4
                    and encryption.get("/R") == 4 and encryption.get("/Length") == 128
                    and encryption["/CF"]["/StdCF"].get("/CFM") == "/AESV2", "fixture AES-128 dictionary differs")
    value = {"schemaVersion": 1, "syntheticOnly": True, "generator": "stdlib explicit ToUnicode PDF; pypdf AES-128",
             "pypdfVersion": pypdf.__version__, "cryptographyVersion": cryptography.__version__,
             "publicSyntheticUserPassword": TEST_USER_PASSWORD, "publicSyntheticOwnerPassword": TEST_OWNER_PASSWORD,
             "emptyPasswordRejected": True, "unopenedPageReadRefused": empty_read_refused,
             "knownPasswordControlPageText": LOCKED_CONTROL, "knownPasswordControlPageCount": 1,
             "unicodeReadback": list(UNICODE_PAGES), "scope": SCOPE,
             "files": {path.name: runtime.receipt(path) for path in (unicode_path, control_path, locked_path)}}
    with (root / "fixture-controls.json").open("x") as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    return {"production-locked-pdf": locked_path, "production-unicode-pdf": unicode_path}, value


def app_inventory(app):
    files = {}
    for parent, directories, leaves in os.walk(app, followlinks=False):
        for name in directories:
            runtime.require(not (Path(parent) / name).is_symlink(), "app has a symlink directory")
        for name in leaves:
            path = Path(parent) / name
            value = runtime.receipt(path)
            value["mode"] = stat.S_IMODE(path.lstat().st_mode)
            files[str(path.relative_to(app))] = value
    runtime.require(files, "empty production app")
    return files


def run_signed_probe(root, name, app, identities, source_path, timeout=12.0):
    """One natural signed decode; observe exact worker birth and kernel exit.

    No worker/broker signals, hidden service invocation or fixture worker is
    used. Missing physical observation remains unavailable, never inferred.
    """
    source = runtime.receipt(source_path)
    stdout_path, stderr_path = root / (name + ".json"), root / (name + ".stderr")
    command = [str(app / runtime.HOST), "--document-xpc-probe", "--input", str(source_path),
               "--sha256", source["sha256"], "--bytes", str(source["bytes"]),
               "--timeout", str(timeout), "--mode", "analyze"]
    monitor, watch, process, observer_error = runtime.OwnedProcesses(app), None, None, None
    gate = {"name": name, "sourceReceipt": source, "signedExecutables": identities,
            "reportPath": str(stdout_path), "physicalObservers": [], "oracleStatus": "pending"}
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            monitor.track(process.pid, "host")
            deadline = time.monotonic() + timeout + 8
            while process.poll() is None:
                runtime.require(time.monotonic() < deadline, "PDF owned host exceeded outer watchdog")
                rows = monitor.sample()
                workers = [row for row in rows if row["role"] == "worker"]
                runtime.require(len(workers) <= 1, "PDF gate observed overlapping production workers")
                if watch is None and observer_error is None and workers:
                    try:
                        watch = runtime.PhysicalExit(monitor, workers[0]["processIdentifier"])
                        sampled = {key: workers[0][key] for key in watch.identity}
                        runtime.require(watch.identity == sampled, "PDF worker birth changed between sample and kernel registration")
                        gate["observedWorkerIdentity"] = sampled
                    except AssertionError as error:
                        observer_error = str(error)
                if watch is not None:
                    watch.poll()
                time.sleep(.005)
            gate["hostReturnCode"] = process.returncode
        runtime.require(process.returncode == 0, "PDF bundled host failed; raw stderr retained")
        runtime.require(stdout_path.stat().st_size <= 2 * runtime.MIB + 65536, "PDF host report cap exceeded")
        gate["report"] = json.loads(stdout_path.read_bytes())
        runtime.require(runtime.receipt(source_path) == source, "synthetic PDF source changed during analysis")
        if watch is not None:
            gate["physicalObservers"] = [watch.report()]
        gate["physicalObserverError"] = observer_error
        gate["physicalObservationScope"] = "exact signed worker path/UID/PID/birth; registered EVFILT_PROC NOTE_EXIT; no bare worker/broker signals"
        gate["gateStatus"] = ("observed; semantic oracle pending" if gate["physicalObservers"] and
                              gate["physicalObservers"][0]["physicalExitObserved"] else
                              "unavailable: exact worker physical exit was not independently observed")
        return gate
    except BaseException as error:
        gate["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()  # Only this unreaped owned host child.
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        if process is not None:
            gate["hostReturnCode"] = process.returncode
        if watch is not None:
            try:
                gate["physicalObservers"] = [watch.report()]
            except BaseException as error:
                gate["physicalObserverFinalizationError"] = {"type": type(error).__name__, "message": str(error)}
            finally:
                watch.close()
        with (root / (name + ".process-attempt.json")).open("x") as output:
            json.dump(gate, output, ensure_ascii=False, indent=2)
            output.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-app", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path, required=True)
    args = parser.parse_args(argv)
    runtime.require(sys.platform == "darwin", "signed PDF runtime gates require macOS")
    parent = args.output_parent.absolute()
    runtime.require(parent.resolve(strict=True) == parent and stat.S_ISDIR(parent.lstat().st_mode)
                    and parent.lstat().st_uid == os.geteuid(), "output parent must be an existing canonical owned directory")
    source_app = args.production_app.absolute()
    runtime.require(source_app.resolve(strict=True) == source_app and source_app.suffix == ".app", "production app must be canonical")
    root = Path(tempfile.mkdtemp(prefix="nf-pdf-runtime-", suffix=".noindex", dir=parent))
    root.chmod(0o700)
    summary = {"schemaVersion": 1, "syntheticOnly": True, "providerRequests": 0, "guiMeasured": False,
               "complete": False, "requiredGateNames": list(GATE_NAMES), "gates": [], "scope": SCOPE,
               "root": str(root), "artifactsRetained": True, "runtimeExecuted": False}
    before_source = before_copy = fixtures = None
    status = 1
    try:
        before_source = app_inventory(source_app)
        app = root / "production.app"
        shutil.copytree(source_app, app, symlinks=False)
        before_copy = app_inventory(app)
        fields = ("bytes", "mode", "sha256")
        runtime.require({path: {key: row[key] for key in fields} for path, row in before_source.items()} ==
                        {path: {key: row[key] for key in fields} for path, row in before_copy.items()}, "app copy bytes or modes changed")
        identities = runtime.signed_identity(app)
        summary["signedExecutables"] = identities
        paths, fixtures = generate_fixtures(root)
        summary["fixtureControls"] = fixtures
        for name in GATE_NAMES:
            summary["runtimeExecuted"] = True
            gate = run_signed_probe(root, name, app, identities, paths[name])
            runtime.record_gate(root, summary["gates"], gate)
            report = gate["report"]
            runtime.validate_lifecycle(report, 1)
            runtime.require(report.get("schemaVersion") == 1 and report.get("backend") == "embedded-app-sandbox-xpc"
                            and report.get("mode") == "analyze" and report.get("sourceSHA256") == gate["sourceReceipt"]["sha256"]
                            and report.get("sourceByteCount") == gate["sourceReceipt"]["bytes"], "PDF host report source/backend changed")
            analysis = report["attempts"][0]["analysis"]
            oracle = validate_locked_pdf if name == "production-locked-pdf" else validate_unicode_pdf
            gate["independentOracle"] = oracle(analysis, gate["sourceReceipt"], identities)
            gate["semanticOracleStatus"] = "passed"
            if gate["gateStatus"].startswith("unavailable"):
                gate["oracleStatus"] = "unavailable"
                continue
            validate_pdf_lifecycle(gate)
            gate["oracleStatus"] = "passed"
        runtime.require([gate["name"] for gate in summary["gates"]] == list(GATE_NAMES), "PDF gate inventory differs")
        summary["complete"] = all(gate["oracleStatus"] == "passed" for gate in summary["gates"])
        status = 0 if summary["complete"] else 77
    except BaseException as error:
        summary["failure"] = {"type": type(error).__name__, "message": str(error)}
        for gate in summary["gates"]:
            if gate.get("oracleStatus") == "pending":
                gate["oracleStatus"], gate["oracleFailure"] = "failed", summary["failure"]
        status = 1
    finally:
        preservation = {}
        try:
            if before_source is not None:
                runtime.require(app_inventory(source_app) == before_source, "original production app changed")
                preservation["sourceAppUnchanged"] = True
            if before_copy is not None:
                runtime.require(app_inventory(root / "production.app") == before_copy, "runtime app copy changed")
                preservation["runtimeAppCopyUnchanged"] = True
            if fixtures is not None:
                runtime.require({name: runtime.receipt(root / "fixtures" / name) for name in fixtures["files"]} ==
                                fixtures["files"], "synthetic PDF inputs changed")
                preservation["allSyntheticFixtureInputsUnchanged"] = True
        except BaseException as error:
            summary["preservationFailure"] = {"type": type(error).__name__, "message": str(error)}
            summary["complete"], status = False, 1
        summary["preservation"] = preservation
        summary["exitStatus"] = status
        summary["recipeSHA256"] = {Path(__file__).name: runtime.digest(Path(__file__)),
                                   "run_document_runtime_gates.py": runtime.digest(Path(runtime.__file__))}
        with (root / "summary.json").open("x") as output:
            json.dump(summary, output, ensure_ascii=False, indent=2)
            output.write("\n")
        print(root / "summary.json", flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
