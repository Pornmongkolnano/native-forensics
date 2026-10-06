#!/usr/bin/env python3
"""Recover a failed comparison without losing its successful or failed attempts.

The timed runners remain unchanged. Fresh replacement pairs run both apps and
at most two extra measured pairs per workload are allowed. Statistics describe
successful imports only; every failure and actual application attempt is kept.
"""
import argparse
import copy
import datetime
import json
from pathlib import Path
import random
import uuid

import compare_forensics_pipeline as b


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--failed-report", required=True, type=Path)
    args = parser.parse_args()
    original_path = b.owned_path(args.failed_report)
    old = json.loads(original_path.read_text())
    b.require(old["status"] == "failed", "Only a retained failed experiment can be recovered")
    b.require(all(b.digest(b.REPO / path) == sha for path, sha in old["recipeSHA256"].items()),
              "Timed recipe changed; cannot combine observations")
    setup = json.loads((original_path.parent / "setup.json").read_text())
    b.verify_setup(setup)
    variant = old["referenceVariant"]
    binary = (b.REPO / ".build/release/ForensicsPipelineBenchmark").resolve()
    helper = (b.REPO / ".engine/bin/NFTSKEngine").resolve()
    classes = b.LOCAL / "verifier-classes"
    provenance = old["provenance"]
    b.require(b.digest(binary) == provenance["nativeBenchmarkSHA256"]
              and b.digest(helper) == provenance["nativeHelperSHA256"]
              and b.digest(classes / "AutopsyCaseVerifier.class") == provenance["verifierClassSHA256"],
              "Timed executable changed; cannot combine observations")
    output = b.LOCAL / ("recovered-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        + "-" + uuid.uuid4().hex[:6])
    output.mkdir()
    report = copy.deepcopy(old)
    report.update(status="running", workloads=[], correctnessControls=[])
    report.pop("error", None)
    report["recovery"] = {"originalFailedReport": str(original_path), "sourceExperimentPreserved": True,
        "timedRecipesUnchanged": True, "recoveryHarnessSHA256": b.digest(Path(__file__)),
        "maximumExtraMeasuredPairsPerImage": 2, "environmentBeforeRecovery": b.environment_receipt(),
        "statistics": "Conditional on complete known-payload imports. Failed attempts are retained, never counted as faster results. Adaptive replacements run both applications as new pairs."}
    rng = random.Random(old["seed"] + 1)

    def pair_run(image_name, expected, attempt, warmup=False):
        image = Path(setup["inputs"][image_name]["path"])
        initial = b.source_state(image)
        order = ["native", "autopsy"]
        rng.shuffle(order)
        pair = {"iteration": attempt, "warmup": warmup, "order": order,
                "replacement": attempt > 5 and not warmup}
        for app in order:
            b.require(b.source_state(image) == initial, "Source changed before attempt")
            if app == "native":
                record = b.native_pipeline(binary, helper, image, output)
                record["validation"] = b.native_readback(record, helper, expected, image)
            else:
                record = b.run_pipeline(setup, output, variant, image_name,
                                       label=f"recovery-{image_name.split('.')[0]}-{attempt}")
                b.require(record["existingSolrUnchanged"] and record["protectedFilesAndSourcesUnchanged"]
                          and record["ownedSolrPortsFreeAfterCleanup"], "Mandatory isolation/source gate failed")
                if record["structuralGatePassed"]:
                    record["validation"] = b.autopsy_readback(record, setup, expected, image, classes, variant)
                else:
                    record["validation"] = {"passed": False, "files": [], "verifiedPayloads": 0,
                        "declaredPayloads": len(expected["files"]), "error": record.get("error")}
            b.require(b.source_state(image) == initial, "Source changed after attempt")
            pair[app] = record
            print(json.dumps({"image": image_name, "attempt": attempt, "warmup": warmup,
                "application": app, "wallSeconds": record["wallSeconds"],
                "pipelineCompleted": app == "native" or record["structuralGatePassed"],
                "verified": record["validation"].get("verifiedPayloads"),
                "expected": len(expected["files"]), "payloadPassed": record["validation"].get("passed")}), flush=True)
        pair["successful"] = all(pair[app]["validation"]["passed"] for app in ("native", "autopsy"))
        pair["metadataComparison"] = b.metadata_comparison(pair)
        b.write_json(output / f"{image_name}-pair-{attempt}.json", pair)
        return pair

    try:
        for image_name in ("fat16-512.raw", "large-fat32.raw", "ntfs-streams.raw"):
            expected = setup["inputs"][image_name]["facts"]
            workload = {"image": image_name, "imageSize": expected["logicalSize"], "sha256": expected["logicalSha256"],
                        "filesystem": expected["filesystem"], "pairs": []}
            if image_name == "fat16-512.raw":
                previous = sorted(original_path.parent.glob(image_name + "-pair-*.json"))
                workload["pairs"] = [json.loads(path.read_text()) for path in previous]
                for pair in workload["pairs"]:
                    pair["successful"] = True
                    pair["reusedUnchangedTimedObservation"] = True
                for path in original_path.parent.glob("pair-fat16-512-*/receipt.json"):
                    record = json.loads(path.read_text())
                    if not record["structuralGatePassed"]:
                        # The original runner stopped at its Autopsy-first crash.
                        record["validation"] = {"passed": False, "files": [], "verifiedPayloads": 0,
                                                "declaredPayloads": len(expected["files"])}
                        workload["pairs"].append({"iteration": 5, "warmup": False, "order": ["autopsy", "native"],
                            "autopsy": record, "nativeAttempted": False, "successful": False,
                            "failureClass": "JVM SIGSEGV in __findenv_locked; exit 137", "retainedFailedAttempt": True})
                b.require(len(workload["pairs"]) == 6 and sum(p.get("successful", False) and not p["warmup"]
                          for p in workload["pairs"]) == 4, "Expected exact four-success/fifth-crash source experiment")
                first_attempt = 6
            elif image_name == "ntfs-streams.raw":
                workload["pairs"] = [pair_run(image_name, expected, 1)]
                workload["performanceRatioAllowed"] = False
                report["correctnessControls"].append(workload)
                continue
            else:
                workload["pairs"] = [pair_run(image_name, expected, 0, warmup=True)]
                first_attempt = 1
            for attempt in range(first_attempt, 8):
                successful = [p for p in workload["pairs"] if p.get("successful") and not p["warmup"]]
                if len(successful) == 5:
                    break
                workload["pairs"].append(pair_run(image_name, expected, attempt))
            successful = [p for p in workload["pairs"] if p.get("successful") and not p["warmup"]]
            workload["performanceRatioAllowed"] = len(successful) == 5
            if len(successful) == 5:
                workload["summary"] = b.summarize(successful)
                workload["summary"]["conditionalOnSuccessfulImports"] = True
            workload["applicationAttempts"] = {}
            for app in ("native", "autopsy"):
                measured = [p[app] for p in workload["pairs"] if not p["warmup"] and app in p]
                workload["applicationAttempts"][app] = {"measured": len(measured),
                    "completedKnownPayloads": sum(bool(r["validation"]["passed"]) for r in measured),
                    "failedKnownPayloads": sum(not r["validation"]["passed"] for r in measured)}
            report["workloads"].append(workload)
        b.verify_setup(setup)
        b.require(all(b.digest(b.REPO / path) == sha for path, sha in old["recipeSHA256"].items())
                  and b.digest(binary) == provenance["nativeBenchmarkSHA256"]
                  and b.digest(helper) == provenance["nativeHelperSHA256"]
                  and b.digest(classes / "AutopsyCaseVerifier.class") == provenance["verifierClassSHA256"],
                  "Source or measured runtime changed")
        report["sourceAndRuntimeHashesUnchanged"] = True
        report["status"] = "completed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["environmentAfter"] = b.environment_receipt()
        b.write_json(output / "report.json", report)
        print(json.dumps({"report": str(output / "report.json"), "status": report["status"]}), flush=True)


if __name__ == "__main__":
    main()
