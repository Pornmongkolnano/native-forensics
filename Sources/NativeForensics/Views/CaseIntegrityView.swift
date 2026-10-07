import AppKit
import ForensicsCore
import SwiftUI

struct CaseIntegrityView: View {
    @Bindable var store: CaseIntegrityWorkspaceStore
    @State private var page = 0
    private let pageSize = 100

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Case Integrity", systemImage: "checkmark.shield").font(.title2.weight(.semibold))
                Spacer()
                Button("Run Audit") { page = 0; store.runAudit() }.disabled(!store.canAudit)
                if store.isWorking { Button("Cancel") { store.cancelPendingWork() } }
                Menu("Export Report") {
                    Button("JSON…") { store.exportReport(format: .json) }
                    Button("Markdown…") { store.exportReport(format: .markdown) }
                }.disabled(!store.canExport)
                if let url = store.reportURL {
                    Button("Show Report") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                }
            }
            Toggle("Freshly rehash recorded evidence files", isOn: $store.freshEvidenceRehash).disabled(store.isWorking)
                .help("Reads each recorded selected file and compares its bytes to the manifest. Offline sources remain historical; EWF container-file hashes are not logical image hashes.")
            Text("Read-only audit · digests detect byte changes, not authenticity. Historical receipts do not establish current source integrity.")
                .font(.caption).foregroundStyle(.secondary)
            if let progress = store.progress {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("\(progress.stage) · \(progress.checkedFiles) items · \(ByteCountFormatter.string(fromByteCount: progress.bytesRead, countStyle: .file)) read")
                        .font(.caption).lineLimit(1)
                }
            }
            Text(store.statusMessage).font(.callout).textSelection(.enabled)
            if let error = store.errorMessage { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if let report = store.report {
                auditTable(report)
                Toggle("Include private host paths in exported reports", isOn: $store.includePrivatePaths)
                    .font(.caption).disabled(store.isWorking)
                Text("Unknown schemas and derived stores are unavailable. No baseline rewrite, repair or migration is performed.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                ContentUnavailableView("No audit report", systemImage: "checkmark.shield", description: Text("Run a metadata audit, or explicitly enable fresh evidence rehash first."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(16)
    }

    private func auditTable(_ report: CaseIntegrityReport) -> some View {
        let count = max(1, (report.checks.count + pageSize - 1) / pageSize)
        let current = min(max(0, page), count - 1)
        let rows = Array(report.checks.dropFirst(current * pageSize).prefix(pageSize))
        return VStack(spacing: 6) {
            Table(rows) {
                TableColumn("Status") { check in
                    Text(check.status.rawValue.capitalized).foregroundStyle(check.status == .fail ? Color.red : Color.primary)
                }.width(min: 80, ideal: 90, max: 120)
                TableColumn("Item") { check in Text(check.relativePath ?? check.evidenceID?.uuidString.lowercased() ?? "Case") }
                TableColumn("Check") { check in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(check.code).font(.caption.monospaced())
                        Text(check.message).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }.help(check.message)
                }
            }.frame(minHeight: 220)
            HStack {
                Text("\(report.checks.count) checks · Page \(current + 1) of \(count)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Previous") { page = max(0, current - 1) }.disabled(current == 0)
                Button("Next") { page = min(count - 1, current + 1) }.disabled(current + 1 >= count)
            }.controlSize(.small)
        }
    }
}
