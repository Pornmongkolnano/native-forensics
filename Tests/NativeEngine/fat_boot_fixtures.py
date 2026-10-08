#!/usr/bin/env python3
"""Independent active-table and backup-boot FAT mapping regressions."""
from __future__ import annotations
import json
import struct
from pathlib import Path
from fixtures import digest, exfat_image, fat_image
from fat_completion_fixtures import fat_recovery_matrix


def generate_fat_boot_fixtures(output: Path) -> list[dict]:
    receipt=output/"fat-boot-manifest.json"
    if receipt.exists():
        images=json.loads(receipt.read_text())["images"]
        for image in images:
            if digest(output/image["path"]) != image["logicalSha256"]:raise RuntimeError("Retained FAT boot fixture changed")
        return images
    images=[]
    for filesystem in ("FAT32","exFAT"):
        path=output/(filesystem.lower()+"-backup-boot.raw")
        image=fat_image(path,32,512) if filesystem=="FAT32" else exfat_image(path)
        with path.open("r+b") as stream:
            boot=stream.read(512)
            if filesystem=="FAT32":stream.seek(6*512);stream.write(boot)
            stream.seek(0);stream.write(bytes(512))
            if filesystem=="exFAT":
                # Upstream's boot selector tests sector6 before sector12. A
                # valid extended-sector signature at6 stops its search even
                # though that sector is not an exFAT boot header. Corrupt both
                # earlier candidates to exercise its actual sector12 fallback.
                stream.seek(6*512);stream.write(bytes(512))
        image.update(logicalSha256=digest(path),bootCase="backup-boot",expectedBootSector=6 if filesystem=="FAT32" else 12)
        images.append(image)
    path=output/"fat32-active-second-table.raw";image=fat_recovery_matrix(path,32)
    geometry=image["recoveryMatrix"]["geometry"]
    with path.open("r+b") as stream:
        # FAT1 retains the oracle mappings. FAT0 contains plausible later data
        # that must never be chosen while BPB_ExtFlags selects the second table.
        stream.seek(40);stream.write(struct.pack("<H",0x81))
        for row in image["files"]:
            if row.get("recoveryCase") not in ("retained-fragmented","allocated-fragmented"):continue
            chain=row["originalEvidence"]["clusterOrder"]
            for index, cluster in enumerate(chain):
                stream.seek(geometry["reserved"]*512+cluster*4)
                stream.write(struct.pack("<I",cluster+1 if index+1<len(chain) else geometry["eoc"]))
    image.update(logicalSha256=digest(path),bootCase="active-second-table",selectedFAT=1,staleFAT=0)
    images.append(image)
    receipt.write_text(json.dumps({"schemaVersion":1,"images":images},indent=2,ensure_ascii=False)+"\n")
    return images
