import ForensicsCore
import SwiftUI

/// A per-file inspector surface. Notes are examiner work; saved AI receipts
/// and exports remain explicitly historical, independently browsable records.
struct CaseWorkView: View {
    @Bindable var store: CaseWorkWorkspaceStore
    @State private var pane: Pane = .notes
    @State private var confirmDiscard = false

    private enum Pane: String, CaseIterable { case notes = "Notes", analyses = "AI History", extractions = "Exports" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !store.hasSelection {
                Text("Select a file to view saved analyses, examiner notes and export history.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                Text(verbatim: store.selectedFilePath)
                    .font(.caption.monospaced()).lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
                Picker("Case work", selection: $pane) {
                    ForEach(Pane.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
                if store.isLoading {
                    HStack { ProgressView().controlSize(.small); Text("Loading historical records…").font(.caption) }
                }
                switch pane {
                case .notes: noteEditor
                case .analyses: history(kind: .analysis, page: store.analysisPage, empty: "No saved AI analyses for this file.")
                case .extractions:
                    history(kind: .extraction, page: store.extractionPage, empty: "No recorded exports for this file.")
                    if let record = store.selectedExtraction { extractionDetail(record) }
                }
                if let error = store.errorMessage {
                    Label { Text(verbatim: error).textSelection(.enabled) } icon: { Image(systemName: "exclamationmark.triangle") }
                        .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
                HStack(alignment: .top) {
                    Text(verbatim: store.statusMessage).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 4)
                    Button(action: store.refresh) { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.borderless).help("Reload historical case records")
                        .accessibilityLabel("Reload historical case records")
                        .disabled(store.isWorking || store.isClosing)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .confirmationDialog("Discard this file’s unsaved note changes and reload its saved revision?", isPresented: $confirmDiscard) {
            Button("Discard Draft and Reload", role: .destructive, action: store.discardDraftAndReload)
            Button("Keep Draft", role: .cancel) {}
        }
        .sheet(item: $store.selectedAnalysis) { record in SavedAnalysisView(record: record) }
        .sheet(item: $store.selectedFinding) { record in SavedFindingRevisionView(record: record) }
    }

    private var noteEditor: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Examiner note", systemImage: "square.and.pencil").font(.headline)
            Text("AI answers are separate advisory receipts. Review status records your assessment; it does not verify evidence bytes.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let record = store.latestFinding {
                Text("Saved revision \(record.revision) · \(record.createdAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary)
                if record.binding.snapshotSHA256 != store.binding?.snapshotSHA256 {
                    Label("This note refers to an earlier filesystem snapshot.", systemImage: "clock.arrow.circlepath")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            TextEditor(text: $store.draft.note)
                .font(.callout).frame(minHeight: 120)
                .padding(4).background(.background.secondary, in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator, lineWidth: 1))
                .accessibilityLabel("Examiner note text")
                .disabled(!store.canEdit)
            Toggle("Bookmark this file", isOn: $store.draft.bookmarked)
                .toggleStyle(.checkbox).disabled(!store.canEdit)
            TextField("Tags, separated by commas", text: $store.draft.tagsText)
                .textFieldStyle(.roundedBorder).disabled(!store.canEdit)
                .accessibilityLabel("Examiner tags, separated by commas")
            Picker("Review status", selection: $store.draft.reviewStatus) {
                Text("Unreviewed").tag(FindingReviewStatus.unreviewed)
                Text("Compared by examiner").tag(FindingReviewStatus.verified)
                Text("Rejected by examiner").tag(FindingReviewStatus.rejected)
            }.disabled(!store.canEdit)
            TextField(store.draft.reviewStatus == .unreviewed ? "Review reason (optional)" : "Review reason (required)", text: $store.draft.reviewReason, axis: .vertical)
                .lineLimit(2...5).textFieldStyle(.roundedBorder).disabled(!store.canEdit)
                .accessibilityLabel("Examiner review reason")
            if let validation = store.draftValidationMessage {
                Text(verbatim: validation).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if store.hasUnsavedChanges {
                Label("Unsaved draft · kept locally in this window when you switch files.", systemImage: "pencil.circle")
                    .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                Text("Drafts are not saved when the window closes. Save explicitly to retain them in the case. Up to 32 other file drafts / 1 MiB are kept in this window; an oversized active draft must be corrected or discarded before leaving it.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button(action: store.saveFinding) {
                    Label(store.isSavingFinding ? "Saving…" : "Save Note Revision", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent).disabled(!store.canSave)
                Spacer(minLength: 4)
                Button("Discard…") { confirmDiscard = true }
                    .disabled(!store.hasUnsavedChanges || store.isSavingFinding || store.isClosing)
            }
            if let page = store.findingPage, !page.items.isEmpty || page.totalDiagnosticCount > 0 {
                DisclosureGroup("Saved note revisions") { history(kind: .finding, page: page, empty: "No saved revisions.") }
                    .font(.caption)
            }
        }
    }

    private func history(kind: CaseWorkKind, page: CaseWorkHistoryPage?, empty: String) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Historical records · source and output bytes have not been reverified by opening this history.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let page {
                if page.items.isEmpty { Text(empty).font(.callout).foregroundStyle(.secondary) }
                ForEach(page.items) { summary in
                    Button { store.open(summary) } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(verbatim: summary.title).lineLimit(2).multilineTextAlignment(.leading)
                            Text(summary.createdAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption).foregroundStyle(.secondary)
                            if let revision = summary.revision { Text("Revision \(revision)").font(.caption2).foregroundStyle(.secondary) }
                            if let retention = summary.retention {
                                Text(retention == .full ? "Exact app request retained" : "Request digest retained")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            if summary.snapshotSHA256 != store.binding?.snapshotSHA256 {
                                Text("Earlier filesystem snapshot").font(.caption2).foregroundStyle(.orange)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
                    }
                    .buttonStyle(.borderless).disabled(store.isLoadingRecord || store.isClosing)
                    Divider()
                }
                if page.totalDiagnosticCount > 0 {
                    Label("\(page.totalDiagnosticCount) unreadable or unsupported records. History coverage is incomplete.", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    ForEach(Array(page.diagnostics.enumerated()), id: \.offset) { _, diagnostic in
                        Text(verbatim: diagnostic.message).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                HStack {
                    Button("Newest") { store.loadNewest(kind: kind) }
                    Spacer(minLength: 4)
                    Text("\(page.items.count) records · max 50/page").font(.caption2).foregroundStyle(.secondary)
                    Button("Older") { store.loadOlder(kind: kind) }.disabled(page.nextCursor == nil)
                }
                .disabled(store.isLoadingHistory || store.isLoading || store.isClosing)
            }
            if store.isLoadingHistory || store.isLoadingRecord { ProgressView().controlSize(.small) }
        }
    }

    private func extractionDetail(_ record: ExtractionRecord) -> some View {
        GroupBox("Historical export receipt") {
            VStack(alignment: .leading, spacing: 8) {
                Text("\(record.outputByteCount.formatted()) extracted bytes").font(.callout)
                Text(verbatim: record.outputHash.scope).font(.caption).foregroundStyle(.secondary)
                Text(verbatim: record.outputHash.sha256).font(.caption.monospaced()).textSelection(.enabled)
                Text(verbatim: record.verificationDescription).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Hide Receipt") { store.selectedExtraction = nil }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct SavedFindingRevisionView: View {
    let record: FindingRecord
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Saved Examiner Note · Revision \(record.revision)").font(.title2.weight(.semibold))
            Text(verbatim: record.binding.selectedEntry.path).font(.callout).textSelection(.enabled)
            Text("Historical record · opening it does not reverify the evidence.").font(.caption).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(verbatim: record.note).textSelection(.enabled)
                    Text(record.bookmarked ? "Bookmarked" : "Not bookmarked").font(.caption)
                    Text(verbatim: record.tags.joined(separator: ", ")).font(.caption).textSelection(.enabled)
                    Text(verbatim: record.reviewStatus.rawValue).font(.caption.weight(.semibold))
                    Text(verbatim: record.reviewReason).font(.callout).textSelection(.enabled)
                    Text("Snapshot SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: record.binding.snapshotSHA256).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Record ID: \(record.id.uuidString)").font(.caption.monospaced()).textSelection(.enabled)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack { Spacer(); Button("Close", action: { dismiss() }).keyboardShortcut(.cancelAction) }
        }.padding(20).frame(width: 640, height: 480)
    }
}
