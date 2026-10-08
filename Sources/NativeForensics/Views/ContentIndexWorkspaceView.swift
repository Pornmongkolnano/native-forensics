import Foundation
import ForensicsCore
import SwiftUI

struct ContentIndexWorkspaceView: View {
    @Bindable var store: ContentIndexWorkspaceStore
    var onOpenReference: (ContentIndexReference) -> Void = { _ in }
    @State private var selectedHit: CaseContentQueryHit?
    @State private var resolvedReference: ResolvedReference?
    @State private var isResolvingReference = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Content Search", systemImage: "doc.text.magnifyingglass").font(.title2.bold())
                Spacer()
                if store.hasActiveWork { Button("Cancel", action: store.cancel) }
                Button("Reload Index", action: store.reload).disabled(store.isWorking)
                Button("Update Index", action: store.update).disabled(!store.canUpdate)
                    .help("Fully verify sources and reuse only unchanged bound documents in a new index generation.")
                Button("Rebuild Index", action: store.rebuild).disabled(!store.canRebuild)
                    .help("Verify sources and rebuild derived text across analyzed sources in this case.")
            }
            Text(store.phase).font(.callout).foregroundStyle(store.isStale ? .orange : .secondary)
            if let progress = store.progress, store.isRebuilding {
                ProgressView(value: Double(progress.finishedFiles), total: Double(max(progress.plannedFiles, 1)))
                Text("\(progress.finishedFiles)/\(progress.plannedFiles) · reused \(progress.reusedFiles) · rebuilt \(progress.rebuiltFiles) · \(progress.filename)")
                    .font(.caption).lineLimit(1)
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
                    Picker("Search mode", selection: $store.searchMode) {
                        Text("Literal").tag(ContentIndexSearchMode.literal)
                        Text("Phrase").tag(ContentIndexSearchMode.phrase)
                        Text("Token prefix").tag(ContentIndexSearchMode.tokenPrefix)
                    }.frame(width: 210)
                    TextField(queryPlaceholder, text: $store.query)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Search case content")
                    Toggle("Case sensitive", isOn: $store.caseSensitive).toggleStyle(.checkbox)
                    if store.isSearching { ProgressView().controlSize(.small) }
                }
                Text(modeGuidance).font(.caption).foregroundStyle(.secondary)
                if store.queryIsTooLong { Text("Search queries support up to 4,096 UTF-8 bytes.").font(.caption).foregroundStyle(.orange) }
                if let result = store.searchOutcome {
                    if !result.queryTokens.isEmpty {
                        Text("Query words: " + result.queryTokens.map(\.text).joined(separator: " · "))
                            .font(.caption).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                    }
                    if let issue = result.queryIssue {
                        Text(queryIssueDescription(issue)).font(.callout).foregroundStyle(.orange)
                        Spacer()
                    } else {
                        Text("\(result.hits.count) match\(result.hits.count == 1 ? "" : "es")\(result.hitLimitReached ? " · first 200 shown" : "") · UTF-16 positions in decoded text")
                            .font(.caption).foregroundStyle(.secondary)
                        if result.hits.isEmpty {
                            ContentUnavailableView("No matches in indexed text", systemImage: "magnifyingglass",
                                description: Text("Skipped, failed, pending, unlisted or undecoded content may still contain this text."))
                        } else {
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 0) {
                                    ForEach(result.hits) { hit in
                                        let reference = hit.reference.indexReference
                                        VStack(alignment: .leading, spacing: 5) {
                                            HStack {
                                                Button { isResolvingReference = true; selectedHit = hit } label: {
                                                    Label(reference.file.path, systemImage: "doc.text")
                                                        .lineLimit(1).truncationMode(.middle)
                                                }.buttonStyle(.plain)
                                                    .accessibilityLabel("Show derived text reference for \(reference.file.path)")
                                                    .accessibilityIdentifier("content-index-reference-\(hit.id)")
                                                Spacer()
                                                Text(referenceLabel(reference)).font(.caption).foregroundStyle(.secondary)
                                                Button("Open File") {
                                                    guard CaseContentIndexSearch.resolve(reference, in: index) != nil else { return }
                                                    onOpenReference(reference)
                                                }
                                                    .buttonStyle(.borderless)
                                                    .accessibilityLabel("Open recorded file \(reference.file.path)")
                                                    .accessibilityIdentifier("content-index-open-file-\(hit.id)")
                                                    .help("Open the recorded file selection. A fresh preview must verify its bytes separately.")
                                            }
                                            Text(hit.snippet).font(.system(.callout, design: .monospaced)).lineLimit(3).textSelection(.enabled)
                                        }
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.vertical, 4)
                                        .accessibilityElement(children: .contain)
                                        Divider()
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 8)
                            }
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                            .accessibilityIdentifier("content-index-search-hits")
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
                Text("Query and decoded text retain their Unicode spelling. Index text is derived local data. Reopening does not verify current source bytes.")
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
            if let resolved = resolvedReference, resolved.key == referenceLoadKey {
                let reference = hit.reference.indexReference
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Derived Text Reference").font(.headline)
                        Spacer()
                        Button("Done") { selectedHit = nil }.keyboardShortcut(.cancelAction)
                    }
                    Text(reference.file.path).textSelection(.enabled)
                    Text("\(referenceLabel(reference)) · UTF-16 \(reference.utf16Offset)…\(reference.utf16Offset + reference.utf16Length)")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("\(modeTitle(hit.reference.request.mode)): \(hit.reference.request.query)")
                        .font(.caption).textSelection(.enabled)
                    Text("This is the saved decoder output. It is not a byte range in the source document and does not verify current source bytes.")
                        .font(.caption).foregroundStyle(.orange)
                    ScrollView { Text(referenceExcerpt(resolved.page.text, offset: reference.utf16Offset))
                        .font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    Text("Content SHA-256: \(reference.contentSHA256)\nDerived SHA-256: \(reference.derivedTextSHA256)")
                        .font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                    Button("Open Recorded File") {
                        guard let index = store.snapshot, CaseContentIndexSearch.resolve(reference, in: index) != nil else { return }
                        onOpenReference(reference); selectedHit = nil
                    }
                }.padding(20).frame(minWidth: 620, minHeight: 420)
            } else if isResolvingReference {
                VStack(spacing: 12) {
                    ProgressView("Checking the saved query reference…")
                    Button("Done") { selectedHit = nil }.keyboardShortcut(.cancelAction)
                }.padding(24).frame(minWidth: 400, minHeight: 160)
            } else {
                VStack { Text("This query reference does not resolve in the current index generation."); Button("Done") { selectedHit = nil } }.padding(24)
            }
        }
        .task(id: referenceLoadKey) { await loadSelectedReference() }
    }

    private struct ReferenceLoadKey: Equatable {
        let snapshotID: UUID?
        let reference: ContentIndexQueryReference?
    }

    private struct ResolvedReference {
        let key: ReferenceLoadKey
        let page: DocumentTextPage
    }

    private var referenceLoadKey: ReferenceLoadKey {
        ReferenceLoadKey(snapshotID: store.snapshot?.id, reference: selectedHit?.reference)
    }

    @MainActor
    private func loadSelectedReference() async {
        guard !Task.isCancelled else { return }
        let key = referenceLoadKey
        resolvedReference = nil
        guard let snapshot = store.snapshot, let reference = selectedHit?.reference else {
            isResolvingReference = false; return
        }
        isResolvingReference = true
        defer { if referenceLoadKey == key { isResolvingReference = false } }
        let worker = Task.detached(priority: .userInitiated) {
            CaseContentIndexSearch.resolve(reference, in: snapshot)
        }
        let page = await withTaskCancellationHandler { await worker.value } onCancel: { worker.cancel() }
        guard !Task.isCancelled, referenceLoadKey == key, let page else { return }
        resolvedReference = ResolvedReference(key: key, page: page)
    }

    private var queryPlaceholder: String {
        switch store.searchMode {
        case .literal: "Literal text in decoded content…"
        case .phrase: "Adjacent words in decoded content…"
        case .tokenPrefix: "Beginning of one word…"
        }
    }

    private var modeGuidance: String {
        switch store.searchMode {
        case .literal: "Find the exact substring, including punctuation and 1–2 character terms. Quotes and * are literal text."
        case .phrase: "Find adjacent whole words. Thai-only phrases ignore whitespace between complete Thai tokens, while punctuation and other scripts break that comparison. Enter words without quote or * syntax. Thai token boundaries can vary."
        case .tokenPrefix: "Find this exact prefix at a word start. Enter one recognized word prefix without spaces or * syntax. Thai dictionary boundaries can vary; use Phrase for multiple words."
        }
    }

    private func modeTitle(_ mode: ContentIndexSearchMode) -> String {
        switch mode { case .literal: "Literal"; case .phrase: "Phrase"; case .tokenPrefix: "Token prefix" }
    }

    private func queryIssueDescription(_ issue: ContentIndexQueryIssue) -> String {
        switch issue {
        case .emptyQuery: "Enter a query."
        case .queryTooLong: "Search queries support up to 4,096 UTF-8 bytes."
        case .noWordTokens: "No word tokens were found. Use Literal to search these exact characters."
        case .phraseContainsNonWordText: "Phrase queries accept words and whitespace. Use Literal to search punctuation, quotes or * exactly."
        case .prefixRequiresSingleToken: "Token prefix needs exactly one word prefix. Use Literal for punctuation or spaces."
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
