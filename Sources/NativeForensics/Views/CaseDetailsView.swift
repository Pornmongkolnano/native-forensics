import AppKit
import ForensicsCore
import SwiftUI

struct CaseDetailsView: View {
    let forensicCase: ForensicCase
    var workspace: WorkspaceStore? = nil

    var body: some View {
        Form {
            Section("Case Manifest") {
                LabeledContent("Name", value: forensicCase.manifest.name)
                LabeledContent("Case ID", value: forensicCase.manifest.id.uuidString)
                LabeledContent("Created", value: forensicCase.manifest.createdAt.formatted())
                LabeledContent("Evidence Records", value: "\(forensicCase.manifest.evidence.count)")
                LabeledContent("Manifest Format", value: "Version \(forensicCase.manifest.schemaVersion)")
                if let provenance = forensicCase.manifest.provenance {
                    LabeledContent("Recorded Jobs", value: "\(provenance.jobs.count)")
                    Text("This format retains component versions, parameters, ordered source hashes and partial-job warnings. The exact earlier manifest is preserved for controlled rollback.")
                        .font(.caption).foregroundStyle(.secondary)
                    if let workspace {
                        Button("Restore Earlier Manifest Format") { workspace.changeCaseProvenanceFormat(upgrade: false) }
                            .disabled(workspace.isBusy || !provenance.jobs.isEmpty)
                        Text("Restore is available only when no evidence or job provenance would be discarded.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else if let workspace {
                    Button("Upgrade Case to Provenance Format 2") { workspace.changeCaseProvenanceFormat(upgrade: true) }
                        .disabled(workspace.isBusy)
                    Text("Upgrade explicitly preserves the earlier manifest and all existing evidence and work records. Opening this case alone does not change its format.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            Section("Storage") {
                LabeledContent("Case Folder") {
                    Text(forensicCase.bundleURL.path)
                        .textSelection(.enabled)
                        .multilineTextAlignment(.trailing)
                }
                Button("Show Case in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([forensicCase.bundleURL])
                }
                Text("The case holds a manifest; source image bytes stay at their original location.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Available in This Version") {
                Text("Read a selected file, calculate SHA-256, record file-level metadata, and reopen the saved case.")
                Text("Select evidence to analyze its filesystem, recover RAW file candidates or inspect supported optical history. Source bytes stay read-only; content readability and metadata provenance are separate checks.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
    }
}
