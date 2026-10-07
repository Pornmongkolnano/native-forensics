# Isolated Autopsy JNI correctness repair

These small patches apply to The Sleuth Kit 4.15.0 commit
`01de0345edaa1ebf21dba6939a7c6bc7129e6e7d`. They are dependency modifications for
the local comparison, rather than NativeForensics engine source.

- `001-jni-posix-timezone-lifetime.patch` replaces the POSIX stack-buffer
  `putenv` call with copying `setenv` while the JNI string is valid. Windows
  keeps the existing `_putenv` path. This retains process-wide timezone state;
  simultaneous imports with different zones require separate work.
- `002-jni-directory-data-streams.patch` admits named DATA attributes on
  non-root NTFS directories and emits local regular-file row types. Directory
  objects, INDEX_ROOT rows, flags, sequences, parents and slack logic are
  preserved. Supplemental streams do not suppress the fallback directory row.
  Filesystem-root inode streams, empty basenames and dot aliases are excluded
  because Java's root identity and parent bookkeeping need a separate repair.
  The direct C++ database importer remains unchanged.

The modified upstream JNI files retain Brian Carrier's copyright notices and
are distributed under the Common Public License 1.0. See the upstream
[license](https://github.com/sleuthkit/sleuthkit/blob/01de0345edaa1ebf21dba6939a7c6bc7129e6e7d/licenses/cpl1.0.txt)
and [source](https://github.com/sleuthkit/sleuthkit/tree/01de0345edaa1ebf21dba6939a7c6bc7129e6e7d/bindings/java/jni).
Apple's [environment manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/putenv.3.html)
documents the POSIX string-lifetime requirement.

`script/build_autopsy_jni_repair.py` accepts explicit source, JAR, native TSK,
original JNI and JDK paths. It requires audited hashes, copies only the four JNI
files and compiler-discovered TSK headers, and links the existing corrected
`libtsk.23.dylib` without rebuilding it. All generated files and personal paths
remain under ignored `local/autopsy-comparison/repair-20261007` in fresh builds.

The build receipt records commands, toolchain, source and patch hashes,
architecture, unchanged ABI and dependency closure, code-signature validation,
and every JAR member's original/candidate hashes. Only
`NATIVELIBS/aarch64/mac/libtsk_jni.dylib` may change. A build pass is packaging
evidence; direct synthetic validation must separately prove loaded JNI
identity, timestamps, streams and database relationships before timing. The
script never installs a candidate, changes a frozen baseline, or opens an
existing case.
