import Foundation
import ForensicsCore
import SwiftUI

struct ContentIndexWorkspaceView: View {
    @Bindable var store: ContentIndexWorkspaceStore
    var onOpenReference: (ContentIndexReference) -> Void = { _ in }
    @State private var selectedHit: CaseContentSearchHit?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Content Search", systemImage: "doc.text.magnifyingglass").font(.title2.bold())
                Spacer()
                if store.hasActiveWork { Button("Cancel", action: store.cancel) }
                Button("Reload Index", action: store.reload).disabled(store.isWorking)
                Button("Rebuild Index", action: store.rebuild).disabled(!store.canRebuild)
                    .help("Verify sources and rebuild derived text across analyzed sources in this case.")
            }
            Text(store.phase).font(.callout).foregroundStyle(store.isStale ? .orange : .secondary)
            if let progress = store.progress, store.isRebuilding {
                ProgressView(value: Double(progress.finishedFiles), total: Double(max(progress.plannedFiles, 1)))
                Text("\(progress.finishedFiles)/\(progress.plannedFiles) · \(progress.filename)").font(.caption).lineLimit(1)
            } else if store.isLoading { ProgressView().controlSize(.small) }
            if let error = store.errorMessage { Text(error).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            if let index = store.snapshot {
                HStack(spacing: 16) {
                    count("Indexed", index.indexedCount)
                    count("Skipped", index.skippedCount)
                    count("Failed", index.failedCount)
                    count("Pending", index.pendingCount)
                    count("Uncovered sources", index.missingListingCount)
                    Spacer(minLength: 0)
                    if store.isStale { Label("Stale", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                    else if store.isHistorical { Label("Historical", systemImage: "clock").foregroundStyle(.secondary) }
                    if index.isPartial { Text("Partial coverage").foregroundStyle(.orange) }
                }.font(.caption)
                Text("Saved generation from \(index.builtAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption2).foregroundStyle(.secondary)
                HStack {
                    TextField("Literal text in decoded content…", text: $store.query)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Search case content")
                    Toggle("Case sensitive", isOn: $store.caseSensitive).toggleStyle(.checkbox)
                    if store.isSearching { ProgressView().controlSize(.small) }
                }
                if store.queryIsTooLong { Text("Search queries support up to 4,096 UTF-8 bytes.").font(.caption).foregroundStyle(.orange) }
                if let result = store.searchOutcome {
                    Text("\(result.hits.count) match\(result.hits.count == 1 ? "" : "es")\(result.hitLimitReached ? " · first 200 shown" : "") · UTF-16 positions in decoded text")
                        .font(.caption).foregroundStyle(.secondary)
                    if result.hits.isEmpty {
                        ContentUnavailableView("No matches in indexed text", systemImage: "magnifyingglass",
                            description: Text("Skipped, failed, pending, unlisted or undecoded content may still contain this text."))
                    } else {
                        List(result.hits) { hit in
                            VStack(alignment: .leading, spacing: 5) {
                                HStack {
                                    Button { selectedHit = hit } label: {
                                        Label(hit.reference.file.path, systemImage: "doc.text")
                                            .lineLimit(1).truncationMode(.middle)
                                    }.buttonStyle(.plain)
                                    Spacer()
                                    Text(referenceLabel(hit.reference)).font(.caption).foregroundStyle(.secondary)
                                    Button("Open File") { onOpenReference(hit.reference) }
                                        .help("Open the recorded file selection. A fresh preview must verify its bytes separately.")
                                }
                                Text(hit.snippet).font(.system(.callout, design: .monospaced)).lineLimit(3).textSelection(.enabled)
                            }.padding(.vertical, 4)
                        }
                    }
                } else {
                    List(index.documents) { document in
                        HStack {
                            Text(document.file.path).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(document.status.rawValue.capitalized).font(.caption)
                            if let reason = document.reason { Text(reason).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                        }
                    }
                }
                Text("Literal substring search; no normalization, OCR or cloud request. Index text is derived local data. Reopening does not verify current source bytes.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Build budget: 512 files · 32 MiB/file · 256 MiB recovered input · 16 MiB text · 600 s. Missing listings and files outside these budgets stay uncovered.")
                    .font(.caption2).foregroundStyle(.secondary)
            } else {
                ContentUnavailableView("Build a local content index", systemImage: "doc.text.magnifyingglass",
                    description: Text("Analyze each source first. Rebuild extracts supported documents through the verified helper and retains bounded text with its source references."))
                if store.missingListingCount > 0 {
                    Text("\(store.missingListingCount) source(s) currently have no readable filesystem listing.").font(.caption).foregroundStyle(.orange)
                }
            }
        }
        .padding(16)
        .sheet(item: $selectedHit) { hit in
            if let index = store.snapshot, let page = CaseContentIndexSearch.resolve(hit.reference, in: index) {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Derived Text Reference").font(.headline)
                        Spacer()
                        Button("Done") { selectedHit = nil }.keyboardShortcut(.cancelAction)
                    }
                    Text(hit.reference.file.path).textSelection(.enabled)
                    Text("\(referenceLabel(hit.reference)) · UTF-16 \(hit.reference.utf16Offset)…\(hit.reference.utf16Offset + hit.reference.utf16Length)")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("This is the saved decoder output. It is not a byte range in the source document and does not verify current source bytes.")
                        .font(.caption).foregroundStyle(.orange)
                    ScrollView { Text(referenceExcerpt(page.text, offset: hit.reference.utf16Offset))
                        .font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    Text("Content SHA-256: \(hit.reference.contentSHA256)\nDerived SHA-256: \(hit.reference.derivedTextSHA256)")
                        .font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                    Button("Open Recorded File") { onOpenReference(hit.reference); selectedHit = nil }
                }.padding(20).frame(minWidth: 620, minHeight: 420)
            } else {
                VStack { Text("This reference belongs to a different index generation."); Button("Done") { selectedHit = nil } }.padding(24)
            }
        }
    }

    private func count(_ title: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 2) { Text(title).foregroundStyle(.secondary); Text(String(value)).monospacedDigit() }
    }

    private func referenceLabel(_ value: ContentIndexReference) -> String {
        value.referenceLabel ?? "Page/body \(value.pageNumber)"
    }

    private func referenceExcerpt(_ value: String, offset: Int) -> String {
        let text = value as NSString
        var start = max(min(offset, text.length) - 1_024, 0), end = min(text.length, max(min(offset, text.length) - 1_024, 0) + 4_096)
        if start > 0, start < text.length, (0xDC00...0xDFFF).contains(text.character(at: start)),
           (0xD800...0xDBFF).contains(text.character(at: start - 1)) { start -= 1 }
        if end > 0, end < text.length, (0xD800...0xDBFF).contains(text.character(at: end - 1)),
           (0xDC00...0xDFFF).contains(text.character(at: end)) { end += 1 }
        return (start > 0 ? "…\n" : "") + text.substring(with: NSRange(location: start, length: end - start))
            + (end < text.length ? "\n…" : "")
    }
}
