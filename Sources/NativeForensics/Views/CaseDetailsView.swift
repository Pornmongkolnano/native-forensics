import AppKit
import ForensicsCore
import SwiftUI

struct CaseDetailsView: View {
    let forensicCase: ForensicCase

    var body: some View {
        Form {
            Section("Case Manifest") {
                LabeledContent("Name", value: forensicCase.manifest.name)
                LabeledContent("Case ID", value: forensicCase.manifest.id.uuidString)
                LabeledContent("Created", value: forensicCase.manifest.createdAt.formatted())
                LabeledContent("Evidence Records", value: "\(forensicCase.manifest.evidence.count)")
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
                Text("Filesystem enumeration, recovery, content search, and artifact analysis are planned milestones.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
    }
}
