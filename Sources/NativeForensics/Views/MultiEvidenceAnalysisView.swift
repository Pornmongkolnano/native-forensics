import ForensicsCore
import SwiftUI

/// Local preparation and exact outbound review are separate from provider
/// execution. Model text is rendered literally and cannot launch a tool/URL.
struct MultiEvidenceAnalysisView: View {
    @Bindable var store: MultiEvidenceAnalysisStore
    @State private var tab: Tab = .ranges
    @State private var reviewed = false
    @State private var reviewingSave = false
    private enum Tab: String, CaseIterable { case ranges = "Ranges", payload = "Exact Payload", answer = "Answer", history = "History" }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                Label(store.isHistoryOnly ? "Saved Comparisons" : "Compare with Codex", systemImage: "doc.on.doc")
                    .font(.title2.weight(.semibold))
                Spacer()
                Text(verbatim: store.connectionStatus).font(.caption).foregroundStyle(.secondary)
            }
            if store.isHistoryOnly {
                Text("Browse this case’s saved interpretations locally. Current source bytes remain unverified. Close this history and prepare the matching files to review a new request or freshly open cited content.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Two verified files · UTF-8 ≤32 KiB/file · PDF text ≤16 KiB/file / 32 KiB PDF total · 64 KiB combined")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Reviewed question", text: $store.question, axis: .vertical)
                    .textFieldStyle(.roundedBorder).lineLimit(2...3).disabled(store.isWorking)
            }
            HStack {
                Picker("Comparison panel", selection: $tab) {
                    ForEach(store.isHistoryOnly ? [.history, .answer] : Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented)
                if !store.isHistoryOnly { Button("Reverify Files", action: store.prepareContext).disabled(!store.canPrepareContext) }
            }
            panel.frame(maxHeight: .infinity, alignment: .top)
            Divider()
            if let parent = store.parentRecord {
                HStack {
                    Text("Follow-up parent: \(parent.id.uuidString) · prior answer is untrusted").font(.caption)
                    Button("Clear Parent", action: store.clearParent).disabled(store.isWorking)
                }
            }
            if !store.isHistoryOnly {
                Text("Only this exact reviewed question, disclosure and optional prior answer are sent to OpenAI through Codex. No disk image is sent. Saving is a separate local retention choice.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("I reviewed the exact aggregate payload and agree to send it.", isOn: $reviewed)
                    .toggleStyle(.checkbox).disabled(!store.canAnalyze || tab != .payload)
            }
            if let error = store.errorMessage { Text(verbatim: error).font(.caption).foregroundStyle(.red).lineLimit(3).textSelection(.enabled) }
            HStack {
                if store.isWorking { ProgressView().controlSize(.small); Button("Cancel", action: store.cancel) }
                else if !store.isHistoryOnly {
                    Button("Copy Payload", action: store.copyContextPrompt).disabled(store.outboundPrompt.isEmpty)
                    Button("Save Comparison…") { reviewingSave = true }.disabled(!store.canSaveAnalysis)
                    Button("Reviewed Follow-up", action: store.beginFollowUp).disabled(!store.canBeginFollowUp)
                }
                Spacer()
                Button("Close", action: store.close).keyboardShortcut(.cancelAction).disabled(store.isWorking)
                if !store.isHistoryOnly {
                    Button("Send to Codex") { guard reviewed else { return }; store.analyze(confirmedPrompt: store.outboundPrompt) }
                        .disabled(!reviewed || !store.canAnalyze).keyboardShortcut(.defaultAction)
                }
            }
            Text(verbatim: store.phase).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(18).frame(width: 920, height: 760)
        .sheet(isPresented: $reviewingSave) { SaveAnalysisView(save: store.saveAnalysis) }
        .onChange(of: store.outboundPrompt) { _, _ in reviewed = false }
        .onChange(of: store.isWorking) { _, working in if working { reviewed = false } }
        .onChange(of: store.result != nil) { _, available in if available { tab = .answer } }
        .onChange(of: store.isHistoryOnly, initial: true) { _, historyOnly in
            tab = historyOnly ? .history : .ranges; reviewed = false
        }
    }

    @ViewBuilder private var panel: some View {
        switch tab {
        case .ranges: rangePanel
        case .payload:
            VStack(alignment: .leading, spacing: 6) {
                Text("Exact app-to-CLI UTF-8 request · \(store.outboundPrompt.utf8.count.formatted()) bytes / 192 KiB cap")
                    .font(.caption).foregroundStyle(.secondary)
                AssistantContextPreviewView(prompt: store.outboundPrompt)
            }
        case .answer: answerPanel
        case .history: historyPanel
        }
    }
    private var rangePanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("UTF-8 ranges: start:end in original file bytes. PDF ranges: page:start:end in raw derived UTF-16 text; page numbers start at 1. End is exclusive. Redactions are removed before transmission; PDF ranges never describe original PDF byte offsets.")
                .font(.caption).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 12) {
                rangeEditor(index: 0, ranges: $store.firstRanges, redactions: $store.firstRedactions)
                rangeEditor(index: 1, ranges: $store.secondRanges, redactions: $store.secondRedactions)
            }
            HStack {
                Button("Apply Ranges / Redactions") { store.rebuildDisclosure(); if !store.outboundPrompt.isEmpty { tab = .payload } }
                    .disabled(store.isWorking || store.verifiedFiles.count != 2)
                if let context = store.context {
                    Text("Disclosed: \(context.files.reduce(0) { $0 + $1.disclosedByteCount }.formatted()) bytes · omitted content remains unknown")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
    private func rangeEditor(index: Int, ranges: Binding<String>, redactions: Binding<String>) -> some View {
        let file = store.verifiedFiles.count > index ? store.verifiedFiles[index] : nil
        let isPDF = file?.isPDF == true
        return VStack(alignment: .leading, spacing: 7) {
            Text(store.filePaths.count > index ? store.filePaths[index] : "Selected file \(index + 1)")
                .font(.callout.weight(.semibold)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            TextField(isPDF ? "Selected page:UTF16 ranges (e.g. 1:0:120)" : "Selected ranges (e.g. 0:120)", text: ranges).textFieldStyle(.roundedBorder)
                .accessibilityLabel("File \(index + 1) selected \(isPDF ? "PDF page UTF-16" : "UTF-8 byte") ranges")
            TextField(isPDF ? "Redacted page:UTF16 ranges (e.g. 1:12:24)" : "Redacted ranges (e.g. 12:24)", text: redactions).textFieldStyle(.roundedBorder)
                .accessibilityLabel("File \(index + 1) redacted \(isPDF ? "PDF page UTF-16" : "UTF-8 byte") ranges")
            if let file {
                if let pdf = file.pdf {
                    Text("PDF source: \(file.receipt.byteCount.formatted()) bytes · decoded \(pdf.pageReceipts.count) / \(pdf.analysis.pageCount ?? 0) pages · \(pdf.analysis.textIsComplete ? "reported text complete" : "incomplete text coverage; OCR/omitted pages unknown")")
                        .font(.caption).foregroundStyle(.secondary)
                    DisclosureGroup("Decoder and raw text receipts") {
                        Text(verbatim: pdfReceiptLabel(pdf.provenance))
                            .font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                    }
                }
                Text("Local preview: \(file.previewByteCount.formatted()) \(isPDF ? "derived UTF-8" : "source") bytes. Applied segments below and Exact Payload show the surviving disclosure; nothing is sent automatically.")
                    .font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    Text(verbatim: file.previewText)
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(8).background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                if let disclosure = store.context?.files[index] {
                    Text("Applied disclosure: \(disclosure.disclosedByteCount.formatted()) / \(isPDF ? "16 KiB PDF" : "32 KiB UTF-8") cap · \(disclosure.omittedByteCount.formatted()) \(isPDF ? "raw derived text" : "source") bytes omitted")
                        .font(.caption).foregroundStyle(.secondary)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(disclosure.segments) { segment in
                                Text(verbatim: segmentLabel(segment)).font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: segment.text ?? "Retained text unavailable")
                                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 100)
                }
            } else { ContentUnavailableView("Preparing Locally", systemImage: "doc.text") }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top).disabled(store.isWorking)
    }
    private func segmentLabel(_ segment: MultiEvidenceSegment) -> String {
        if let span = segment.pdfRange {
            return "\(segment.id) · PDF page \(span.pageNumber), raw derived UTF-16 \(span.range.start):\(span.range.end) · \(segment.byteCount) disclosed UTF-8 bytes"
        }
        guard let range = segment.sourceRange else { return segment.id }
        return "\(segment.id) · source UTF-8 bytes \(range.start):\(range.end)"
    }
    private func pdfReceiptLabel(_ provenance: DocumentDecodeProvenance) -> String {
        var lines = ["Decoder \(provenance.decoderVersion) · \(provenance.isolation.rawValue)",
                     "Parser executable SHA-256: \(provenance.decoderExecutableSHA256)"]
        if let hash = provenance.decoderCodeSigningCDHash { lines.append("Parser signing CDHash: \(hash)") }
        if let hash = provenance.brokerExecutableSHA256 { lines.append("Broker executable SHA-256: \(hash)") }
        if let hash = provenance.brokerCodeSigningCDHash { lines.append("Broker signing CDHash: \(hash)") }
        lines.append("Options SHA-256: \(provenance.optionsSHA256)")
        lines.append("Whole raw derived text SHA-256: \(provenance.derivedTextSHA256)")
        return lines.joined(separator: "\n")
    }
    @ViewBuilder private var answerPanel: some View {
        if let result = store.result {
            VStack(alignment: .leading, spacing: 8) {
                if let record = store.savedRecord {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Historical saved interpretation · opening this record did not reverify sources").font(.caption).foregroundStyle(.orange)
                        Text(verbatim: "Saved question: \(record.question)").font(.caption).textSelection(.enabled)
                        Text(verbatim: "Saved files: " + record.context.files.map { $0.binding.selectedEntry.path }.joined(separator: " ↔ "))
                            .font(.caption).lineLimit(2).textSelection(.enabled)
                    }
                }
                AssistantResponseView(summary: result.response.summary, observations: result.response.observations,
                    hypotheses: result.response.hypotheses, limitations: result.response.limitations, nextSteps: result.response.nextSteps)
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        if store.references.isEmpty { Text("No structured citations were provided; verify claims independently.").font(.caption).foregroundStyle(.orange) }
                        ForEach(store.references, id: \.id) { reference in referenceRow(reference) }
                    }
                }.frame(maxHeight: 100)
                if let text = store.openedReferenceText {
                    Text(verbatim: "Freshly verified \(store.openedReferenceLabel ?? "citation")\n\(text)")
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(5)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading).background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                }
            }
        } else { ContentUnavailableView("No Comparison Yet", systemImage: "text.bubble", description: Text("Review both disclosures and the exact payload before Send.")) }
    }
    private func referenceRow(_ reference: MultiEvidenceReference) -> some View {
        HStack {
            Text(verbatim: reference.marker).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Text(verbatim: reference.reason).font(.caption)
                .foregroundStyle(reference.state == .disclosed ? Color.secondary : Color.orange)
            Spacer()
            Button(reference.pdfRange == nil ? "Open Verified Bytes" : "Open Verified PDF Span") { store.openReference(reference) }
                .disabled(!store.canOpenReference(reference))
        }
    }
    private var historyPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(store.historyShowsOlderPage ? "Older historical page · up to 50 receipts" : "Newest historical page · up to 50 receipts").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Newest") { store.loadHistory() }.disabled(store.isWorking)
                Button("Load Older") { store.loadHistory(older: true) }.disabled(!store.canLoadOlderHistory)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if store.history.isEmpty { Text("No saved comparisons in this case.").foregroundStyle(.secondary) }
                    ForEach(store.history) { record in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(verbatim: record.title).lineLimit(2)
                                Text("\(record.createdAt.formatted()) · \(record.retention == .full ? "Exact request retained" : "Request digest only")\(record.parentRecordID == nil ? "" : " · Follow-up")")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Open") { store.loadRecord(id: record.id); tab = .answer }
                                .buttonStyle(.borderless)
                                .disabled(store.isWorking)
                                .accessibilityLabel("Open saved comparison \(record.title)")
                                .accessibilityIdentifier("comparison-history-open-\(record.id.uuidString.lowercased())")
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 8)
                        .accessibilityElement(children: .contain)
                        Divider()
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .accessibilityIdentifier("comparison-history-records")
        }
    }
}
