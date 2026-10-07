import ForensicsCore
import SwiftUI

struct ContentPreviewView: View {
    @Bindable var store: ContentPreviewStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Local Content Preview", systemImage: "doc.text.viewfinder")
                .font(.headline)
            Text("Read-only extraction · files up to 1 MiB · preview up to 32 KiB")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button(action: store.load) {
                    Label(store.preview == nil ? "Load Preview" : "Verify and Reload", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(!store.canLoad)
                if store.isLoading {
                    ProgressView().controlSize(.small)
                    Button("Cancel", action: store.cancel)
                }
            }
            Text(store.phase)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let message = store.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let preview = store.preview {
                previewBody(preview)
            } else if !store.hasSelection {
                Text("Select a regular file to inspect its content.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func previewBody(_ preview: LocalContentPreview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("Preview format", selection: $store.mode) {
                Text("Text · UTF-8").tag(ContentPreviewDisplayMode.text).disabled(!preview.supportsText)
                Text("Hex").tag(ContentPreviewDisplayMode.hex)
            }
            .pickerStyle(.segmented)
            .accessibilityLabel("Preview format")
            let included = store.mode == .text ? preview.textIncludedByteCount ?? 0 : preview.hexIncludedByteCount
            Text("Showing \(included.formatted()) / \(preview.receipt.byteCount.formatted()) extracted bytes")
                .font(.caption)
                .foregroundStyle(Int64(included) < preview.receipt.byteCount ? Color.orange : Color.secondary)
            GroupBox {
                if preview.receipt.byteCount == 0 {
                    Text("Empty file · 0 bytes")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else if store.mode == .text {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(store.visibleTextFragments) { row in
                            HStack(alignment: .top, spacing: 8) {
                                Text(row.fragmentNumber == 1 ? "\(row.lineNumber)" : "\(row.lineNumber)↳\(row.fragmentNumber)")
                                    .foregroundStyle(.secondary)
                                    .frame(minWidth: 30, alignment: .trailing)
                                    .accessibilityLabel("Line \(row.lineNumber), fragment \(row.fragmentNumber)")
                                Text(verbatim: row.text)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .font(.system(.caption, design: .monospaced))
                            .help("Extracted UTF-8 byte offset \(row.byteOffset)")
                        }
                    }
                } else {
                    ScrollView(.horizontal) {
                        LazyVStack(alignment: .leading, spacing: 6) {
                            ForEach(store.visibleHexRows) { row in
                                Text(verbatim: String(format: "%08X", row.byteOffset) + "  " + row.hexadecimal.padding(toLength: 47, withPad: " ", startingAt: 0) + "  " + row.ascii)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .accessibilityLabel("Byte offset \(row.byteOffset): \(row.hexadecimal)")
                            }
                        }
                    }
                }
            }
            HStack {
                Button { store.page = max(0, store.page - 1) } label: { Image(systemName: "chevron.left") }
                    .disabled(store.page <= 0)
                    .accessibilityLabel("Previous preview page")
                Text("\(store.page + 1) / \(store.pageCount)")
                    .font(.caption)
                    .monospacedDigit()
                Button { store.page = min(store.pageCount - 1, store.page + 1) } label: { Image(systemName: "chevron.right") }
                    .disabled(store.page >= store.pageCount - 1)
                    .accessibilityLabel("Next preview page")
                Spacer(minLength: 8)
                Button(action: store.copyVisiblePage) { Image(systemName: "doc.on.doc") }
                    .help("Copy visible page with line or byte references")
                    .accessibilityLabel("Copy visible preview page")
            }
            Text(store.mode == .text
                ? "Numbers refer to derived UTF-8 lines. Long lines are split into fragments of up to 256 bytes."
                : "Offsets refer to extracted bytes, not original disk-image addresses. Non-ASCII bytes appear as dots in the ASCII column.")
                .font(.caption2)
                .foregroundStyle(.secondary)
            DisclosureGroup("Verification and limitations") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Verified \(preview.receipt.verifiedAt.formatted(date: .abbreviated, time: .standard))")
                        .font(.caption)
                    Text(verbatim: preview.receipt.sha256)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    Text("SHA-256 scope: \(preview.receipt.hashScope) · \(preview.receipt.orderedContainerSHA256.count) ordered container hashes checked")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    ForEach(Array(preview.warnings.enumerated()), id: \.offset) { _, warning in
                        Text(verbatim: warning)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 8)
            }
            .font(.caption)
        }
    }
}
