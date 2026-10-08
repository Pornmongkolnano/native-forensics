#!/usr/bin/env python3
"""Recorded exFAT ValidDataLength oracle, independent of upstream TSK.

Microsoft exFAT 7.6.5 defines all logical bytes beyond ValidDataLength as zero.
These generated images retain nonzero physical residual bytes in that tail.
https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from fixtures import _rolling_checksum, digest, exfat_image


def generate_exfat_initialized_fixtures(output: Path) -> list[dict]:
    output.mkdir(parents=True, exist_ok=True)
    receipt = output/"exfat-initialized-manifest.json"
    if receipt.exists():
        images=json.loads(receipt.read_text())["images"]
        for image in images:
            if digest(output/image["path"]) != image["logicalSha256"]:
                raise RuntimeError("Retained exFAT initialized fixture changed")
        return images
    images=[]
    for kind in ("prefix", "all-zero", "full", "invalid"):
        path=output/("exfat-valid-data-length-"+kind+".raw")
        image=exfat_image(path);target=image["files"][0];stored=bytes.fromhex(target["payloadHex"])
        initialized={"prefix":1,"all-zero":0,"full":len(stored),"invalid":len(stored)+1}[kind]
        with path.open("r+b") as stream:
            offset=280*512+3*32;stream.seek(offset);entry=bytearray(stream.read(96))
            struct.pack_into("<Q",entry,32+8,initialized)
            struct.pack_into("<H",entry,2,_rolling_checksum(entry,width=16,skip=(2,3)))
            stream.seek(offset);stream.write(entry)
        if kind != "invalid":
            logical=stored[:initialized]+bytes(len(stored)-initialized)
            target.update(payloadHex=logical.hex(),sha256=hashlib.sha256(logical).hexdigest())
        target.update(recordedValidDataLength=initialized,storedResidualSHA256=hashlib.sha256(stored).hexdigest())
        image.update(target=target,capabilityCase="exfat-valid-data-length-"+kind,
                     expectedExtractionError="INVALID_INITIALIZED_LENGTH" if kind=="invalid" else None,
                     logicalSha256=digest(path))
        images.append(image)
    receipt.write_text(json.dumps({"schemaVersion":1,"images":images},indent=2,ensure_ascii=False)+"\n")
    return images
