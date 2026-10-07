import AppKit
import ForensicsCore
import SwiftUI

struct SidebarView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        List(selection: selection) {
            Section("Data Sources") {
                Label("All Data Sources", systemImage: "externaldrive")
                    .tag(WorkspaceNavigationSelection.overview)
                    .selectionDisabled(workspace.isBusy)
                ForEach(workspace.currentCase?.manifest.evidence ?? [], id: \.id) { evidence in
                    dataSourceRow(evidence)
                        .tag(WorkspaceNavigationSelection.dataSource(evidence.id))
                        .selectionDisabled(workspace.isBusy)
                }
            }

            Section("File Views") {
                ForEach(FilesystemCategory.allCases) { category in
                    HStack(spacing: 9) {
                        Image(systemName: category.symbol)
                            .foregroundStyle(category == .deleted ? Color.orange : Color.secondary)
                            .frame(width: 16)
                        Text(category.title)
                    }
                    .tag(WorkspaceNavigationSelection.fileView(category))
                    .help(category.help)
                    .selectionDisabled(workspace.isBusy || workspace.selectedEvidence == nil)
                    .disabled(workspace.selectedEvidence == nil)
                }
            }

            Section("Optical") {
                Label("Optical History", systemImage: "opticaldisc")
                    .tag(WorkspaceNavigationSelection.optical)
                    .help("Current and historical UDF namespace records from linked VAT states.")
                    .selectionDisabled(workspace.isBusy || workspace.selectedEvidence == nil)
                    .disabled(workspace.selectedEvidence == nil)
            }

            Section("Recovery") {
                Label("Recovered Files", systemImage: "arrow.uturn.backward.circle")
                    .tag(WorkspaceNavigationSelection.recovery)
                    .help("Signature-recovered candidates with separate byte verification and document decoding.")
                    .selectionDisabled(workspace.isBusy || workspace.selectedEvidence == nil)
                    .disabled(workspace.selectedEvidence == nil)
            }

            Section("Case") {
                Label("Case Details", systemImage: "folder.badge.gearshape")
                    .tag(WorkspaceNavigationSelection.caseDetails)
                    .selectionDisabled(workspace.isBusy || workspace.currentCase == nil)
                    .disabled(workspace.currentCase == nil)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top, spacing: 0) {
            workspaceHeader
        }
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 6) {
                    Image(systemName: "lock.shield")
                    Text("Read-only evidence")
                }
                Text("File types are based on extensions.")
                    .font(.caption2)
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var selection: Binding<WorkspaceNavigationSelection?> {
        Binding(get: { workspace.navigationSelection }, set: { selection in
            if let selection { workspace.navigate(to: selection) }
        })
    }

    private var workspaceHeader: some View {
        HStack(spacing: 10) {
            Image(nsImage: NSApplication.shared.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .frame(width: 36, height: 36)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("Native Forensics")
                    .font(.headline)
                    .lineLimit(1)
                Text(workspace.currentCase?.manifest.name ?? "Evidence Workbench")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(workspace.currentCase?.manifest.name ?? "Create or open a forensic case.")
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 14)
    }

    private func dataSourceRow(_ evidence: EvidenceRecord) -> some View {
        HStack(spacing: 9) {
            Image(systemName: "externaldrive")
                .foregroundStyle(.secondary)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(URL(fileURLWithPath: evidence.sourcePath).lastPathComponent)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(evidence.container.rawValue.uppercased()) · \(EvidenceFormatting.bytes(evidence.byteCount))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .help("Browse the saved filesystem for \(URL(fileURLWithPath: evidence.sourcePath).lastPathComponent).")
        .accessibilityElement(children: .combine)
    }
}
