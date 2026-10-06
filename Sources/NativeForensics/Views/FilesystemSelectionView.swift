import ForensicsCore
import SwiftUI

/// The selection strip borrows Autopsy's lower detail area without reading
/// evidence content or implying that text/hex preview has been implemented.
struct FilesystemSelectionView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Selected File", systemImage: "doc.text.magnifyingglass")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    workspace.showInspector = true
                } label: {
                    Label("File Details", systemImage: "sidebar.right")
                }
                .buttonStyle(.borderless)
                .font(.caption)
                .disabled(workspace.selectedFilesystemFile == nil)
            }
            if let file = workspace.selectedFilesystemFile {
                HStack(alignment: .center, spacing: 14) {
                    ForensicFileIcon(file: file, size: 28)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(file.name.isEmpty ? file.path : file.name)
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(file.path)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(file.path)
                    }
                    Spacer(minLength: 8)
                    VStack(alignment: .trailing, spacing: 4) {
                        Text("\(file.size.formatted()) bytes")
                            .font(.caption.monospacedDigit())
                        Label(file.isDeleted ? "Deleted" : file.isDirectory ? "Directory" : "Allocated",
                              systemImage: file.isDeleted ? "trash" : file.isDirectory ? "folder" : "checkmark.circle")
                            .font(.caption)
                            .foregroundStyle(file.isDeleted ? Color.orange : Color.secondary)
                    }
                }
            } else {
                Text("Select a result to see its path, size and allocation.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 9)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.background.secondary)
    }
}
