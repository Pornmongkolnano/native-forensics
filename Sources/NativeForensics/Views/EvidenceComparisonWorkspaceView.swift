import ForensicsCore
import SwiftUI

struct EvidenceComparisonWorkspaceView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        @Bindable var selection = workspace.comparisonSelection
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Compare Evidence with Codex", systemImage: "doc.on.doc")
                    .font(.headline)
                Spacer()
                Button("Saved Comparisons…", action: workspace.openComparisonHistory)
                    .disabled(!workspace.canOpenComparisonHistory)
                    .help("Read this case’s historical comparison receipts locally.")
                Button("Prepare Comparison…", action: workspace.openComparison)
                    .buttonStyle(.borderedProminent)
                    .disabled(!workspace.canOpenComparison)
            }
            Text("Choose two regular files from the selected data source. UTF-8 inputs support 1 MiB; PDFs support 128 MiB after verified decoding. Names do not establish format. Select excerpts and review the exact request before sending.")
                .font(.callout).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 24) {
                choice("File A", file: selection.firstFile)
                choice("File B", file: selection.secondFile)
            }
            HStack {
                TextField("Search recorded paths", text: $selection.query)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Comparison file search")
                if selection.isSearching { ProgressView().controlSize(.small) }
                Button("Use as A") { selection.useSelected(asFirst: true) }
                    .disabled(selection.selectedCandidateID == nil)
                Button("Use as B") { selection.useSelected(asFirst: false) }
                    .disabled(selection.selectedCandidateID == nil)
            }
            Table(selection.rows, selection: $selection.selectedCandidateID) {
                TableColumn("Path", value: \.path)
                TableColumn("Size") { file in
                    Text(EvidenceFormatting.bytes(file.size)).monospacedDigit()
                }.width(100)
                TableColumn("Allocation") { file in
                    Text(file.isDeleted ? "Deleted metadata" : "Allocated")
                }.width(140)
            }
            .frame(minHeight: 192)
            HStack {
                Text("\(selection.rows.count) shown · \(selection.matchCount) candidates · UTF-8 ≤1 MiB / decoded PDF ≤128 MiB")
                Spacer()
                if workspace.selectedFilesystemResult == nil { Text("Analyze a filesystem first.") }
            }
            .font(.caption).foregroundStyle(.secondary)
            if let error = selection.errorMessage { Text(error).foregroundStyle(.red) }
        }
        .padding(16)
        .disabled(workspace.isBusy)
    }

    private func choice(_ title: String, file: FilesystemEntry?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(file?.path ?? "Select a file below")
                .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                .help(file?.path ?? title)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
