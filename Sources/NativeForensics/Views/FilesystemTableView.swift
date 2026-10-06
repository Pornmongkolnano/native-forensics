import AppKit
import ForensicsCore
import SwiftUI

struct FilesystemTableView: View {
    @Bindable var workspace: WorkspaceStore
    @State private var page = 0
    private let pageSize = 100

    private var lastPage: Int { max(0, (workspace.filesystemRows.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var pageRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, workspace.filesystemRows.count)
    }
    private var pageRows: ArraySlice<FilesystemEntry> { workspace.filesystemRows[pageRange] }
    private var pageSummary: String {
        if workspace.isFilteringFilesystem { return "Updating matches…" }
        let count = workspace.filesystemRows.count
        guard count > 0 else { return "0 entries" }
        return "Entries \((pageRange.lowerBound + 1).formatted())–\(pageRange.upperBound.formatted()) of \(count.formatted())"
    }

    private var displayTimezone: String {
        workspace.timestampDisplayTimezone == "UTC" ? "UTC" : workspace.selectedFilesystemResult?.options.timezone ?? "UTC"
    }

    private var rowCount: String {
        if workspace.isFilteringFilesystem { return "Filtering…" }
        let total = workspace.selectedFilesystemResult?.files.count ?? 0
        if workspace.filesystemSearchText.isEmpty && workspace.filesystemCategory == .all {
            return "\(total.formatted()) entries"
        }
        return "\(workspace.filesystemRows.count.formatted()) of \(total.formatted())"
    }

    private var isRestrictedView: Bool {
        !workspace.filesystemSearchText.isEmpty || workspace.filesystemCategory != .all
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Find file path", text: $workspace.filesystemSearchText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Find file path")
                    .onExitCommand { workspace.filesystemSearchText = "" }
                if !workspace.filesystemSearchText.isEmpty {
                    Button { workspace.filesystemSearchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .help("Clear file search")
                    .accessibilityLabel("Clear file search")
                }
                if workspace.isFilteringFilesystem {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel("Filtering file paths")
                }
                Text(rowCount)
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .fixedSize()
                Picker("Display times", selection: $workspace.timestampDisplayTimezone) {
                    Text("Times: UTC").tag("UTC")
                    Text("Times: Evidence").tag("evidence")
                }
                .labelsHidden()
                .accessibilityLabel("Display times")
                .frame(width: 138)
                .help("Display timestamps in \(displayTimezone). Recorded seconds and nanoseconds remain unchanged.")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Table(pageRows, selection: $workspace.selectedFileID) {
                TableColumn("Name") { file in
                    HStack(spacing: 9) {
                        ForensicFileIcon(file: file, isSelected: workspace.selectedFileID == file.id)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(file.name.isEmpty ? file.path : file.name)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(file.path)
                                .font(.caption2)
                                .foregroundStyle(workspace.selectedFileID == file.id
                                    ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8) : .secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .padding(.vertical, 3)
                    .help(file.path)
                }
                .width(min: 160, ideal: 270, max: 400)

                TableColumn("State") { file in
                    Label(file.isDeleted ? "Deleted" : "Allocated", systemImage: file.isDeleted ? "trash" : "checkmark.circle")
                        .font(.caption)
                        .foregroundStyle(workspace.selectedFileID == file.id
                            ? Color(nsColor: .alternateSelectedControlTextColor)
                            : file.isDeleted ? Color.orange : Color.secondary)
                }
                .width(82)

                TableColumn("Size") { file in
                    Text(EvidenceFormatting.bytes(file.size))
                        .font(.caption)
                        .monospacedDigit()
                        .help("\(file.size.formatted()) bytes")
                }
                .width(76)

                TableColumn("Modified") { file in
                    Text(FilesystemFormatting.timestamp(file.modifiedEpoch, in: displayTimezone))
                        .font(.caption)
                        .monospacedDigit()
                        .help("\(displayTimezone) · \(FilesystemFormatting.rawTime(file.modifiedEpoch, nanoseconds: file.modifiedNanoseconds))")
                }
                .width(142)
            }
            .disabled(workspace.isEngineRunning || workspace.isFilteringFilesystem)
            .contextMenu(forSelectionType: String.self) { selection in
                if !workspace.isFilteringFilesystem,
                   selection.count == 1, let id = selection.first,
                   pageRows.contains(where: { $0.id == id }),
                   let file = workspace.filesystemFilesByID[id] {
                    Button {
                        workspace.selectedFileID = id
                        workspace.showInspector = true
                    } label: {
                        Label("Show File Details", systemImage: "sidebar.right")
                    }
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(file.path, forType: .string)
                    } label: {
                        Label("Copy Full Path", systemImage: "doc.on.doc")
                    }
                    Divider()
                    Button {
                        workspace.selectedFileID = id
                        workspace.chooseExtractionDestination()
                    } label: {
                        Label("Extract File…", systemImage: "square.and.arrow.up")
                    }
                    .disabled(workspace.isBusy || workspace.isFilteringFilesystem || file.isDirectory)
                }
            }
            .overlay {
                if workspace.filesystemRows.isEmpty && !workspace.isFilteringFilesystem {
                    ContentUnavailableView {
                        Label(isRestrictedView ? "No Matching Files" : "No Entries Recorded", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text(isRestrictedView ? "Try another filename or path, or select All Files. File categories use filename extensions." : "Review the analysis status and warnings. An empty result does not establish that the image contains no files.")
                    }
                }
            }

            Divider()
            HStack(spacing: 10) {
                Text(pageSummary)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help("\(pageSummary). Search covers the full selected file view; the table displays up to \(pageSize) entries per page.")
                    .accessibilityLabel(pageSummary)
                Spacer(minLength: 0)
                HStack(spacing: 6) {
                    Button { changePage(to: 0) } label: { Image(systemName: "backward.end") }
                        .disabled(displayedPage == 0)
                        .help("First page")
                        .accessibilityLabel("First page")
                    Button { changePage(to: displayedPage - 1) } label: {
                        Label("Previous", systemImage: "chevron.left")
                    }
                    .disabled(displayedPage == 0)
                    .help("Previous page of filesystem entries")
                    .accessibilityLabel("Previous page")
                    Button { changePage(to: displayedPage + 1) } label: {
                        Label("Next", systemImage: "chevron.right")
                    }
                    .disabled(displayedPage == lastPage)
                    .help("Next page of filesystem entries")
                    .accessibilityLabel("Next page")
                    Button { changePage(to: lastPage) } label: { Image(systemName: "forward.end") }
                        .disabled(displayedPage == lastPage)
                        .help("Last page")
                        .accessibilityLabel("Last page")
                }
                .disabled(workspace.isBusy || workspace.isFilteringFilesystem)
            }
            .font(.caption)
            .controlSize(.small)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .onChange(of: workspace.filesystemSearchText) { _, _ in resetPage() }
        .onChange(of: workspace.filesystemCategory) { _, _ in resetPage() }
        .onChange(of: workspace.selectedEvidenceID) { _, _ in resetPage() }
        .onChange(of: workspace.selectedFilesystemResult?.savedAt) { _, _ in resetPage() }
        .onChange(of: workspace.filesystemRows.count) { _, _ in
            if page != displayedPage { changePage(to: displayedPage) }
        }
        .onChange(of: page) { _, _ in workspace.selectedFileID = nil }
    }

    private func resetPage() {
        page = 0
        workspace.selectedFileID = nil
    }

    private func changePage(to newPage: Int) {
        workspace.selectedFileID = nil
        page = min(max(0, newPage), lastPage)
    }
}
