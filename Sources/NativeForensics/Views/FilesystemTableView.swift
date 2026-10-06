import ForensicsCore
import SwiftUI

struct FilesystemTableView: View {
    @Bindable var workspace: WorkspaceStore

    private var displayTimezone: String {
        workspace.timestampDisplayTimezone == "UTC" ? "UTC" : workspace.selectedFilesystemResult?.options.timezone ?? "UTC"
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Find file path", text: $workspace.filesystemSearchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 360)
                    .onChange(of: workspace.filesystemSearchText) { _, _ in
                        workspace.refreshFilesystemRows()
                    }
                Spacer()
                Picker("Display times", selection: $workspace.timestampDisplayTimezone) {
                    Text("UTC").tag("UTC")
                    Text("Evidence timezone").tag("evidence")
                }
                .frame(maxWidth: 260)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Table(workspace.filesystemRows, selection: $workspace.selectedFileID) {
                TableColumn("Path") { file in
                    Label(file.path, systemImage: file.isDirectory ? "folder" : "doc")
                        .lineLimit(1)
                        .help(file.path)
                }
                .width(min: 180, ideal: 350)

                TableColumn("Allocation") { file in
                    Text(file.isDeleted ? "Deleted" : "Allocated")
                        .font(.caption)
                        .foregroundStyle(file.isDeleted ? Color.orange : Color.secondary)
                }
                .width(min: 70, ideal: 85, max: 100)

                TableColumn("Size") { file in
                    Text(EvidenceFormatting.bytes(file.size))
                        .monospacedDigit()
                }
                .width(min: 70, ideal: 85, max: 110)

                TableColumn("Modified (\(displayTimezone))") { file in
                    Text(FilesystemFormatting.timestamp(file.modifiedEpoch, in: displayTimezone))
                        .font(.caption)
                        .monospacedDigit()
                }
                .width(min: 145, ideal: 175)
            }
            .disabled(workspace.isEngineRunning)
            .contextMenu(forSelectionType: String.self) { selection in
                if selection.count == 1, let id = selection.first {
                    Button("Extract File…") {
                        workspace.selectedFileID = id
                        workspace.chooseExtractionDestination()
                    }
                    .disabled(workspace.isBusy || workspace.filesystemFilesByID[id]?.isDirectory != false)
                }
            }
            .overlay {
                if workspace.filesystemRows.isEmpty {
                    ContentUnavailableView {
                        Label(workspace.filesystemSearchText.isEmpty ? "No Entries Recorded" : "No Matching Paths", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text(workspace.filesystemSearchText.isEmpty ? "Review the analysis status and warnings. An empty result does not establish that the image contains no files." : "Try another filename or path.")
                    }
                }
            }
        }
    }
}
