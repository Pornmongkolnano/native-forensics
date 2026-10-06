import SwiftUI

struct WorkbenchSettingsView: View {
    @AppStorage("workbenchAppearance") private var appearance = "system"

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
            Section("Analysis scope") {
                Text("Filesystem listing and extraction for RAW/EWF images. FAT16, FAT32, exFAT and NTFS are covered by synthetic tests.")
                Text("File Views use filename hints. Content search, file previews, carving and artifact analysis are unavailable.")
                    .foregroundStyle(.secondary)
                Text("APFS, FileVault and UDF are unavailable. Deleted-file contents may have been overwritten.")
                    .foregroundStyle(.secondary)
            }
            Section {
                LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development")
                Text("Phase 1 · Development build, signed for local use. General distribution and clean-machine compatibility are not verified.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 430)
    }
}
