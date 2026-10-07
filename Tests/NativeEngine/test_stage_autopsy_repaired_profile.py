"""JNI-only staging gates, exercised with disposable synthetic profiles."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "script"))
import benchmark_autopsy_pipeline as pipeline
import stage_autopsy_repaired_profile as repair_stage


class RepairedProfileStageTests(unittest.TestCase):
    def setUp(self):
        pipeline.LOCAL.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="repair-stage-unit-", dir=pipeline.LOCAL)
        self.directory = Path(self.temporary.name)
        self.runtime = self.directory / "original-runtime"
        self.native = self.directory / "original-native"
        self.native.mkdir()
        (self.native / "libtsk.23.dylib").write_bytes(b"synthetic preserved exFAT-capable TSK")
        (self.native / "libtsk_jni.dylib").write_bytes(b"synthetic original JNI")
        for relative, content in {
            "bin/autopsy": "#!/bin/sh\nexit 0\n",
            "etc/autopsy.conf": "synthetic launch configuration\n",
            "etc/autopsy.clusters": "autopsy\nplatform\n",
            "platform/lib/nbexec": "synthetic nbexec\n",
            "autopsy/solr/server/etc/jetty.xml": "synthetic private Solr configuration\n",
        }.items():
            path = self.runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.jar = self.runtime / "autopsy/modules/ext/sleuthkit-4.15.0.jar"
        self.jar.parent.mkdir(parents=True)
        self.jar_entries = {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
            "org/sleuthkit/datamodel/Synthetic.class": b"synthetic immutable Java class",
            pipeline.JNI_RESOURCE: b"synthetic original JNI",
            "NATIVELIBS/x86_64/mac/libtsk_jni.dylib": b"synthetic unchanged x86 JNI",
        }
        self.write_jar(self.jar, self.jar_entries)
        for name in pipeline.MODULES:
            self.write_jar(self.runtime / "autopsy/modules" / name,
                           {"Synthetic.class": b"synthetic private STOP.KEY nfabcde " + name.encode()})
        self.java = self.directory / "java-home"
        (self.java / "bin").mkdir(parents=True)
        (self.java / "lib").mkdir()
        (self.java / "bin/java").write_text("#!/bin/sh\nexit 0\n")
        (self.java / "bin/java").chmod(0o755)
        (self.java / "bin/javac").write_text("synthetic javac\n")
        self.jdk = self.directory / "original-jdk"
        (self.jdk / "bin").mkdir(parents=True)
        (self.jdk / "bin/java").write_text("synthetic original launch wrapper\n")
        variant = {
            "runtime": str(self.runtime), "jdk": str(self.jdk),
            "nativeDirectory": str(self.native),
            "safetyAdapter": {"type": "synthetic private Solr STOP.KEY", "key": "nfabcde"},
            "modules": [{"name": name, "sha256": pipeline.digest(self.runtime / "autopsy/modules" / name)}
                        for name in pipeline.MODULES],
            "nativeFiles": [{"path": str(path), "sha256": pipeline.digest(path)}
                            for path in sorted(self.native.iterdir())],
            "effectiveFiles": pipeline.effective_runtime_files(self.runtime, self.jdk),
        }
        resource = pipeline.jni_resource_receipt(variant)
        variant.update(tskJarSHA256=resource["jarSHA256"], jniResourceEntry=resource["resourceEntry"],
                       jniResourceSHA256=resource["sha256"])
        self.setup = {"schemaVersion": pipeline.SETUP_VERSION, "javaHome": str(self.java),
                      "variants": {"installed-adapted": variant}, "inputs": {},
                      "protectedFiles": [], "commonJars": [{"path": str(self.jar),
                                                               "sha256": pipeline.digest(self.jar)}],
                      "privateSolrPorts": {"http": 41137, "stop": 41138, "rmi": 41139},
                      "privateSolrStopKey": "nfabcde"}
        self.setup_path = self.directory / "original-setup.json"
        self.setup_path.write_text(json.dumps(self.setup))
        self.candidate_jni = self.directory / "candidate-jni.dylib"
        self.candidate_jni.write_bytes(b"synthetic repaired JNI")
        self.candidate = self.directory / "candidate.jar"
        entries = dict(self.jar_entries)
        entries[pipeline.JNI_RESOURCE] = self.candidate_jni.read_bytes()
        self.write_jar(self.candidate, entries)
        self.repair = {"status": "built-not-installed-not-functionally-validated",
                       "protectedInputsUnchanged": True, "exportedSymbolsIdentical": True,
                       "strictCodeSignatureVerified": True,
                       "onlyChangedZIPmember": pipeline.JNI_RESOURCE,
                       "originalJar": {"path": str(self.jar), "sha256": pipeline.digest(self.jar)},
                       "nativeTSK": {"path": str(self.native / "libtsk.23.dylib"),
                                     "sha256": pipeline.digest(self.native / "libtsk.23.dylib")},
                       "candidateJar": {"path": str(self.candidate), "sha256": pipeline.digest(self.candidate)},
                       "candidateJNI": {"path": str(self.candidate_jni), "sha256": pipeline.digest(self.candidate_jni)}}
        self.repair_path = self.directory / "repair.json"
        self.output = self.directory / "repaired-profile"
        self.save_repair()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_jar(path, entries):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)

    def save_repair(self):
        self.repair_path.write_text(json.dumps(self.repair))

    def stage(self):
        return repair_stage.stage(self.setup_path, self.repair_path, self.output)

    def replace_candidate(self, entries):
        self.write_jar(self.candidate, entries)
        self.repair["candidateJar"]["sha256"] = pipeline.digest(self.candidate)
        self.save_repair()

    def test_stage_preserves_private_solr_and_original_bytes(self):
        original_setup_bytes = self.setup_path.read_bytes()
        original_jar_bytes = self.jar.read_bytes()
        setup = self.stage()
        selected = setup["variants"]["repaired-mac"]
        staged_runtime = Path(selected["runtime"])
        self.assertEqual(selected["safetyAdapter"], self.setup["variants"]["installed-adapted"]["safetyAdapter"])
        self.assertEqual(setup["privateSolrPorts"], self.setup["privateSolrPorts"])
        self.assertEqual(setup["privateSolrStopKey"], "nfabcde")
        for name in pipeline.MODULES:
            self.assertEqual((staged_runtime / "autopsy/modules" / name).read_bytes(),
                             (self.runtime / "autopsy/modules" / name).read_bytes())
        staged_config = staged_runtime / "autopsy/solr/server/etc/jetty.xml"
        self.assertFalse(staged_config.is_symlink())
        self.assertEqual(staged_config.read_bytes(), (self.runtime / "autopsy/solr/server/etc/jetty.xml").read_bytes())
        self.assertFalse((staged_runtime / "autopsy/modules/ext/sleuthkit-4.15.0.jar").is_symlink())
        self.assertEqual((Path(selected["nativeDirectory"]) / "libtsk.23.dylib").read_bytes(),
                         (self.native / "libtsk.23.dylib").read_bytes())
        self.assertEqual(self.setup_path.read_bytes(), original_setup_bytes)
        self.assertEqual(self.jar.read_bytes(), original_jar_bytes)
        pipeline.verify_setup(setup)

    def test_changed_java_class_is_rejected_before_output(self):
        entries = dict(self.jar_entries)
        entries[pipeline.JNI_RESOURCE] = self.candidate_jni.read_bytes()
        entries["org/sleuthkit/datamodel/Synthetic.class"] = b"unreviewed Java class mutation"
        self.replace_candidate(entries)
        with self.assertRaisesRegex(ValueError, "Only the ARM64 JNI resource"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_added_jar_entry_is_rejected_before_output(self):
        entries = dict(self.jar_entries)
        entries[pipeline.JNI_RESOURCE] = self.candidate_jni.read_bytes()
        entries["org/sleuthkit/datamodel/Unreviewed.class"] = b"unreviewed addition"
        self.replace_candidate(entries)
        with self.assertRaisesRegex(ValueError, "JAR entries"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_changed_libtsk_receipt_is_rejected_before_output(self):
        self.repair["nativeTSK"]["sha256"] = "0" * 64
        self.save_repair()
        with self.assertRaisesRegex(ValueError, "preserve.*libtsk"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_candidate_and_jni_symlinks_are_rejected_before_output(self):
        for artifact, original in (("candidateJar", self.candidate), ("candidateJNI", self.candidate_jni)):
            with self.subTest(artifact=artifact):
                link = self.directory / (artifact + "-link")
                link.symlink_to(original)
                saved = self.repair[artifact]["path"]
                self.repair[artifact]["path"] = str(link)
                self.save_repair()
                with self.assertRaisesRegex(ValueError, "reviewed repair receipt"):
                    self.stage()
                self.assertFalse(self.output.exists())
                self.repair[artifact]["path"] = saved

    def test_candidate_symlink_ancestor_is_rejected_before_output(self):
        link = self.directory / "linked-artifact-directory"
        link.symlink_to(self.directory, target_is_directory=True)
        self.repair["candidateJar"]["path"] = str(link / self.candidate.name)
        self.save_repair()
        with self.assertRaisesRegex(ValueError, "reviewed repair receipt"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_candidate_hash_mismatch_is_rejected_before_output(self):
        self.candidate.write_bytes(b"unreviewed artifact bytes")
        with self.assertRaisesRegex(ValueError, "reviewed repair receipt"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_failed_or_unvalidated_build_receipt_is_rejected_before_output(self):
        for field, value in (("status", "failed"), ("protectedInputsUnchanged", False),
                             ("exportedSymbolsIdentical", False), ("strictCodeSignatureVerified", False),
                             ("onlyChangedZIPmember", "org/sleuthkit/datamodel/Synthetic.class")):
            with self.subTest(field=field):
                saved = self.repair[field]
                self.repair[field] = value
                self.save_repair()
                with self.assertRaises(ValueError):
                    self.stage()
                self.assertFalse(self.output.exists())
                self.repair[field] = saved

    def test_staged_launch_config_native_and_jar_mutations_fail_frozen_profile(self):
        setup = self.stage()
        selected = setup["variants"]["repaired-mac"]
        paths = [Path(selected["runtime"]) / relative for relative in
                 ("bin/autopsy", "etc/autopsy.conf", "platform/lib/nbexec",
                  "autopsy/solr/server/etc/jetty.xml", "autopsy/modules/ext/sleuthkit-4.15.0.jar")]
        paths.extend((Path(selected["jdk"]) / "bin/java",
                      Path(selected["nativeDirectory"]) / "libtsk_jni.dylib",
                      Path(selected["nativeDirectory"]) / "libtsk.23.dylib"))
        for path in paths:
            with self.subTest(path=path.relative_to(self.output)):
                original = path.read_bytes()
                path.write_bytes(original + b"unreviewed staged mutation")
                with self.assertRaises(ValueError):
                    pipeline.verify_setup(setup)
                path.write_bytes(original)
                pipeline.verify_setup(setup)

    def test_existing_output_profile_is_never_overwritten(self):
        self.stage()
        first_receipt = (self.output / "setup.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual((self.output / "setup.json").read_bytes(), first_receipt)


if __name__ == "__main__":
    unittest.main()
