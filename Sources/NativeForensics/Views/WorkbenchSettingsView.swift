import SwiftUI

struct WorkbenchSettingsView: View {
    @AppStorage("workbenchAppearance") private var appearance = "system"
    @AppStorage("codexCLIPath") private var codexCLIPath = CodexCLIAvailability.defaultPath

    var body: some View {
        Form {
            Section {
                Picker("Appearance", selection: $appearance) {
                    Text("System").tag("system")
                    Text("Light").tag("light")
                    Text("Dark").tag("dark")
                }
                .pickerStyle(.segmented)
                Text("Follow macOS, or choose an appearance for this workbench.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Appearance")
            }
            WorkSchedulingSettingsView()
            Section("Analysis scope") {
                Text("Filesystem listing and extraction for RAW/EWF images. FAT16, FAT32, exFAT and NTFS are covered by synthetic tests.")
                Text("Local text/hex previews support files up to 1 MiB, showing up to 32 KiB. Examiner notes, bookmarks, saved AI analyses and export history are stored separately from evidence.")
                    .foregroundStyle(.secondary)
                Text("File Views use filename hints. Verified document previews inspect supported image, PDF, text, ZIP and Office content locally. Content Search rebuilds a bounded index across the case's recorded filesystems; omitted, failed, partial and historical content stay labeled.")
                    .foregroundStyle(.secondary)
                Text("Recovery uses a separately installed PhotoRec executable for one RAW image. Optical History supports a bounded UDF 2.01 VAT profile. Timeline combines recorded filesystem timestamps with optional verified Chromium History and bounded UTF-8 log imports. Raw and unresolved times remain labeled.")
                    .foregroundStyle(.secondary)
                Text("APFS provides an experimental read-only system view of one selected volume's allocated files and regular-file main data forks in supported UDIF or raw GPT images. Known snapshots in plaintext images can be selected and verified. Container and Disk-user volume credentials are separate. Encrypted snapshots, deleted APFS recovery and boot FileVault remain unavailable.")
                    .foregroundStyle(.secondary)
                Text("Explicit EFS extraction accepts matching RSA private DER and certificate DER for the supported allocated, fully initialized, nonsparse, uncompressed, unnamed NTFS AES-256 profile. Output hashes describe emitted bytes; they do not authenticate historical plaintext.")
                    .foregroundStyle(.secondary)
                Text("OCR and other activity artifact families remain unavailable. Deleted-file contents may have been overwritten.")
                    .foregroundStyle(.secondary)
            }
            Section("Codex evidence analysis") {
                TextField("Installed CLI path", text: $codexCLIPath)
                    .textFieldStyle(.roundedBorder)
                Text("Tested with Codex CLI 0.160.1. Sign in separately with codex login; compatibility must be checked after CLI upgrades. A reviewed question and optional text excerpt are sent to OpenAI only when you choose Send to Codex.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let issue = CodexCLIAvailability.issue(for: codexCLIPath) {
                    Text(issue).font(.caption).foregroundStyle(.orange)
                }
                Text("Compare Evidence prepares two verified UTF-8 or PDF files locally. You choose text or decoded page ranges and redactions, review the exact combined request, and explicitly send. PDF references identify decoded text, rather than original-file byte ranges. Resolved citations identify disclosed text; they do not verify AI conclusions.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development")
                Text("Phase 1 · Development build, signed for local use. General distribution and clean-machine compatibility are not verified.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 570)
    }
}
