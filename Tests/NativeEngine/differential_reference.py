#!/usr/bin/env python3
"""Read-only differential observations using retained upstream TSK CLI tools.

The CLI shares the pinned reader library with the adapter. Literal independently
constructed payloads are the correctness oracle; agreement with TSK is a
secondary reference, and known upstream divergences are reported explicitly.
No evidence is formatted, mounted, repaired or rewritten.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import platform


REPO=Path(__file__).resolve().parents[2]


def build_reference_tools(output: Path) -> None:
    """Build the original CLI source against the retained relink libraries."""
    output.mkdir(parents=True,exist_ok=True)
    cxx=subprocess.check_output(["/usr/bin/xcrun","--find","clang++"],text=True).strip()
    sdk=subprocess.check_output(["/usr/bin/xcrun","--sdk","macosx","--show-sdk-path"],text=True).strip()
    specification=json.loads((REPO/"NativeEngine/dependencies.json").read_text())
    receipt={"schemaVersion":1,"architecture":platform.machine(),"tools":{}}
    for tool in ("fls","icat"):
        source=REPO/f".engine/deps/sleuthkit-4.15.0/tools/fstools/{tool}.cpp"
        libraries=[REPO/".engine/relink/libtsk.a",REPO/".engine/relink/libewf.a"]
        argv=[cxx,"-std=c++17","-O2","-arch",platform.machine(),"-isysroot",sdk,
              "-mmacosx-version-min="+specification["minimumMacOS"],"-I",str(REPO/".engine/prefix/include"),
              "-I",str(REPO/".engine/deps/sleuthkit-4.15.0"),str(source),*map(str,libraries),
              "-lz","-lbz2","-liconv","-framework","CoreFoundation","-o",str(output/tool)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=120)
        (output/(tool+"-build.log")).write_text(result.stdout+result.stderr)
        if result.returncode:raise RuntimeError("Upstream CLI compilation failed: "+tool)
        subprocess.run(["/usr/bin/codesign","--force","--sign","-",str(output/tool)],check=True,capture_output=True)
        receipt["tools"][tool]={"sourceSHA256":sha(source.read_bytes()),"executableSHA256":sha((output/tool).read_bytes()),
                               "staticLibrariesSHA256":{library.name:sha(library.read_bytes()) for library in libraries}}
    (output/"build-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")


def sha(data): return hashlib.sha256(data).hexdigest()


def check_reference(fixtures: Path, tools: Path) -> dict:
    structures=json.loads((fixtures/"ntfs-structures.json").read_text())
    compression=json.loads((fixtures/"ntfs-compression.json").read_text())
    recovery=json.loads((fixtures/"ntfs-recovery-fixtures.json").read_text())["images"]
    initialized=json.loads((fixtures/"exfat-initialized-manifest.json").read_text())["images"]
    fat=[row for row in json.loads((fixtures/"fat-completion-manifest.json").read_text())["images"] if row.get("recoveryMatrix")]
    fat.extend(row for row in json.loads((fixtures/"fat-boot-manifest.json").read_text())["images"] if row.get("recoveryMatrix"))
    inventory=[];streams=[]
    all_images=structures+compression+recovery+initialized+fat
    source_hashes={image["path"]:sha((fixtures/image["path"]).read_bytes()) for image in all_images}
    tool_hashes={name:sha((tools/name).read_bytes()) for name in ("fls","icat")}
    env=dict(os.environ,TZ="UTC",LC_ALL="C")
    for image in structures:
        if image.get("expectedExtractionError"):continue
        result=subprocess.run([str(tools/"fls"),"-r","-p","-i","raw","-b","512","-m","/","-z","UTC",str(fixtures/image["path"])],capture_output=True,timeout=60,env=env)
        if result.returncode:raise AssertionError("upstream fls inventory failed: "+image["path"])
        rows={}
        for line in result.stdout.decode().splitlines():
            parts=line.split("|")
            if len(parts)!=11 or "-128-" not in parts[2]:continue
            path=parts[1].removesuffix(" (deleted)").lstrip("/")
            if path.startswith("$") or any(component in (".","..") for component in path.split("/")):continue
            if "/.:" in path:continue # CLI emits a directory ADS alias via '.'
            if path in rows:raise AssertionError("unexpected duplicate upstream data path")
            rows[path]=parts
        if set(rows)!={target["path"] for target in image["files"]}:raise AssertionError("upstream inventory/count differs from independent structure oracle")
        for target in image["files"]:
            fields=rows[target["path"]];expected=target["timestampsByTimezone"]["UTC"]
            if int(fields[6])!=target["size"]:raise AssertionError("upstream logical size differs")
            for index,kind in ((7,"accessed"),(8,"modified"),(9,"changed"),(10,"created")):
                if int(fields[index])!=expected[kind+"Epoch"]:raise AssertionError("upstream epoch differs")
        inventory.append({"case":image["structureCase"],"regularStreamCount":len(rows),"timestamps":"four whole-second fields matched"})
        for target in image["files"]:
            locator=f"{target['metaAddress']}-{target['attributeType']}-{target['attributeID']}"
            result=subprocess.run([str(tools/"icat"),"-i","raw","-b","512",str(fixtures/image["path"]),locator],capture_output=True,timeout=60,env=env)
            if result.returncode or result.stdout!=bytes.fromhex(target["payloadHex"]):raise AssertionError("upstream positive structure bytes differ")
            streams.append({"case":image["structureCase"],"path":target["path"],"byteCount":len(result.stdout),"sha256":sha(result.stdout),"matched":True})
    allowed={"compressed-one-byte-last-chunk","compressed-unused-high-flag-bits","compressed-uninitialized-tail-unmapped","compressed-uninitialized-all","exfat-valid-data-length-prefix","exfat-valid-data-length-all-zero"}
    observations=[]
    for image in compression+recovery+initialized:
        target=image["target"]
        if image.get("expectedExtractionError"):continue
        if "metaAddress" not in target:
            # The independent exFAT writer places HELLO primary at root entry3.
            locator="6"
        else:locator=f"{target['metaAddress']}-{target['attributeType']}-{target['attributeID']}"
        result=subprocess.run([str(tools/"icat"),"-i","raw","-b","512",str(fixtures/image["path"]),locator],capture_output=True,timeout=60,env=env)
        matched=result.returncode==0 and result.stdout==bytes.fromhex(target["payloadHex"])
        case=image["capabilityCase"]
        if not matched and case not in allowed:raise AssertionError("unexpected upstream differential bytes: "+case+" "+result.stderr.decode(errors="replace")[:300])
        observations.append({"case":case,"referenceExit":result.returncode,"referenceByteCount":len(result.stdout),"referenceSHA256":sha(result.stdout),"independentOracleSHA256":target["sha256"],"matched":matched,"knownReaderDivergence":not matched})
    fat_observations=[]
    for image in fat:
        result=subprocess.run([str(tools/"fls"),"-r","-p","-i","raw","-b","512","-m","/","-z","UTC",str(fixtures/image["path"])],capture_output=True,timeout=60,env=env)
        rows={parts[1].removesuffix(" (deleted)").lstrip("/"):parts for line in result.stdout.decode().splitlines() if len(parts:=line.split("|"))==11}
        for target in image["files"]:
            if not target.get("recoveryCase"):continue
            if target["path"] not in rows:raise AssertionError("upstream FAT inventory dropped a declared candidate")
            result=subprocess.run([str(tools/"icat"),"-r","-i","raw","-b","512",str(fixtures/image["path"]),rows[target["path"]][2]],capture_output=True,timeout=60,env=env)
            original=target["originalEvidence"]["sha256"]
            rejected=target.get("rejectedForwardScanCandidate")
            if rejected and result.stdout!=bytes.fromhex(rejected["payloadHex"]):raise AssertionError("upstream cleared-chain bytes differ from independently predicted wrong candidate")
            fat_observations.append({"image":image["path"],"case":target["recoveryCase"],"path":target["path"],"nativeExpectedError":target.get("expectedError"),"referenceExit":result.returncode,"referenceByteCount":len(result.stdout),"referenceSHA256":sha(result.stdout),"originalSHA256":original,"referenceMatchesOriginal":sha(result.stdout)==original,"matchesIndependentRejectedGuess":bool(rejected),"historicalOwnershipProved":False})
    for name,digest in source_hashes.items():
        if sha((fixtures/name).read_bytes())!=digest:raise AssertionError("source changed during differential reference")
    for name,digest in tool_hashes.items():
        if sha((tools/name).read_bytes())!=digest:raise AssertionError("reference executable changed")
    return {"schemaVersion":1,"passed":True,"reader":"TSK4.15.0 retained upstream fls/icat linked to pinned patched static libraries","independence":"Independent payload/civil timestamp/count constructors; CLI shares reader lineage and is secondary reference","inventory":inventory,"structureStreams":streams,"observations":observations,"fatRecoveryObservations":fat_observations,"sourceHashesPreserved":True,"referenceToolsSHA256":tool_hashes}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures",required=True,type=Path);parser.add_argument("--tools",required=True,type=Path);parser.add_argument("--report",required=True,type=Path)
    parser.add_argument("--build-tools",action="store_true")
    args=parser.parse_args()
    if args.build_tools:build_reference_tools(args.tools.resolve())
    report=check_reference(args.fixtures.resolve(),args.tools.resolve());args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({"passed":report["passed"],"structureBytes":len(report["structureStreams"]),"positiveOtherStreams":len(report["observations"]),"fatRecoveryStreams":len(report["fatRecoveryObservations"]),"knownDivergences":sum(row["knownReaderDivergence"] for row in report["observations"])}))
