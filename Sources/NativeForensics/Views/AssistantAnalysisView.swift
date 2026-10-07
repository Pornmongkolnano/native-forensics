import ForensicsCore
import SwiftUI

/// A request-scoped review sheet. Context preparation is local; disclosure is
/// an explicit action after reviewing the exact question and prompt.
struct AssistantAnalysisView: View {
    @Bindable var store: AssistantAnalysisStore
    @State private var selectedTab: Tab = .context
    @State private var allowSending = false
    @State private var isReviewingSave = false

    private enum Tab: String, CaseIterable {
        case context = "Context"
        case answer = "Answer"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            questionComposer
            preparationControls
            Divider()
            Picker("Analysis panel", selection: $selectedTab) {
                ForEach(Tab.allCases, id: \.self) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            analysisPanel
                .frame(maxHeight: .infinity, alignment: .top)
            Divider()
            disclosureControls
            footer
        }
        .padding(18)
        .frame(width: 760, height: 650)
        .onChange(of: store.question) { _, _ in allowSending = false }
        .onChange(of: store.includeText) { _, _ in
            allowSending = false
            selectedTab = .context
        }
        .onChange(of: store.outboundPrompt) { _, _ in
            allowSending = false
            selectedTab = .context
        }
        .onChange(of: store.result != nil) { _, hasResult in
            if hasResult { selectedTab = .answer }
        }
        .onChange(of: store.isWorking) { _, isWorking in
            if isWorking { allowSending = false }
        }
        .sheet(isPresented: $isReviewingSave) {
            SaveAnalysisView(save: store.saveAnalysis)
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "sparkles")
                .font(.title2)
                .foregroundStyle(.tint)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text("Analyze with Codex")
                    .font(.title2.weight(.semibold))
                Text("AI interpretation")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(verbatim: store.selectedFilePath)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(store.selectedFilePath)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 4) {
                Text("Codex CLI")
                    .font(.caption.weight(.semibold))
                Text(verbatim: store.connectionStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.trailing)
            }
            .frame(maxWidth: 180)
        }
    }

    private var questionComposer: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Question").font(.callout.weight(.semibold))
                Spacer()
                preset("Summarize", question: "Summarize this file's metadata and any included text. Cite the exact evidence fields that support each observation.")
                preset("Timeline", question: "Explain the file's recorded timestamps and possible timeline. Separate recorded facts from hypotheses and describe timezone or timestamp limitations.")
                preset("Findings", question: "Identify potentially useful forensic findings in this file's metadata and any included text. Explain the evidence for each finding, limitations, and safe next checks.")
            }
            TextEditor(text: $store.question)
                .font(.callout)
                .frame(height: 56)
                .padding(4)
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator, lineWidth: 1))
                .disabled(store.isWorking)
                .accessibilityLabel("Question for Codex")
        }
    }

    private var preparationControls: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Toggle("Include a UTF-8 text excerpt", isOn: $store.includeText)
                    .toggleStyle(.checkbox)
                    .disabled(store.isWorking)
                Text("Optional · files up to 1 MiB · excerpt up to 32 KiB")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Button(action: store.prepareContext) {
                Label(store.context == nil ? "Prepare Context" : "Rebuild Context", systemImage: "arrow.clockwise")
            }
            .disabled(store.isWorking)
        }
    }

    @ViewBuilder
    private var analysisPanel: some View {
        if selectedTab == .context {
            VStack(alignment: .leading, spacing: 8) {
                if store.contextNeedsPreparation {
                    Label("Prepare or rebuild the context to match the selected content option before sending.", systemImage: "arrow.clockwise")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let context = store.context {
                    contextStatus(context)
                }
                AssistantContextPreviewView(prompt: store.outboundPrompt)
            }
        } else if let result = store.result {
            VStack(alignment: .leading, spacing: 6) {
                if result.startupDiagnosticCount > 0 {
                    Text("An optional Codex startup component was disabled. The completed answer is an AI interpretation of the reviewed context.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                AssistantResponseView(
                    summary: result.response.summary,
                    observations: result.response.observations,
                    hypotheses: result.response.hypotheses,
                    limitations: result.response.limitations,
                    nextSteps: result.response.nextSteps
                )
                Text("Request SHA-256: \(result.requestSHA256)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        } else {
            ContentUnavailableView("No AI Answer Yet", systemImage: "text.bubble", description: Text("Review the local context and question, then send a request to Codex."))
        }
    }

    private func contextStatus(_ context: EvidenceAnalysisContext) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 14) {
                Label(context.textContent == nil ? "Metadata only" : "Metadata and UTF-8 text", systemImage: "doc.text")
                if context.analysis.status == .partial {
                    Label("Partial analysis", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if context.file.isDeleted {
                    Label("Deleted file", systemImage: "trash")
                        .foregroundStyle(.orange)
                }
            }
            .font(.caption)
            if let text = context.textContent {
                Text("Text: \(text.includedByteCount.formatted()) of \(text.completeByteCount.formatted()) bytes included. \(text.isTruncated ? "Excerpt is truncated. " : "")SHA-256 covers the complete extracted file.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text("Container hashes describe selected source-file bytes; logical image and extracted-file hashes have separate scopes shown in the prompt.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if !context.analysis.sourceBytesVerifiedForContent {
                Text("Metadata snapshot · current source bytes have not been reverified for this request.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var disclosureControls: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("The reviewed question and context are sent to OpenAI through Codex and use your account quota. No disk image is sent.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Toggle("I reviewed this question and context and agree to send them.", isOn: $allowSending)
                .toggleStyle(.checkbox)
                .font(.callout)
                .disabled(!store.canAnalyze || store.isWorking)
            if let error = store.errorMessage {
                Label {
                    Text(verbatim: error)
                        .lineLimit(3)
                        .textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                }
                .font(.caption)
                .foregroundStyle(.red)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if store.isWorking {
                ProgressView().controlSize(.small)
                Text(verbatim: store.phase)
                    .font(.caption)
                    .lineLimit(1)
                Button("Cancel", action: store.cancel)
            } else {
                Button("Copy Context", action: store.copyContextPrompt)
                    .disabled(store.outboundPrompt.isEmpty)
                if store.result != nil {
                    Button("Copy Answer", action: store.copyResponse)
                    Button {
                        isReviewingSave = true
                    } label: {
                        Label(store.savedAnalysisID == nil ? "Save Analysis…" : "Saved", systemImage: "tray.and.arrow.down")
                    }
                    .disabled(!store.canSaveAnalysis)
                    .help("Save a local historical AI record with an explicit retention choice")
                }
            }
            Spacer(minLength: 8)
            Button("Close", action: store.close)
                .keyboardShortcut(.cancelAction)
                .disabled(store.isWorking)
            Button {
                guard allowSending, store.canAnalyze, !store.isWorking else { return }
                store.analyze(confirmedPrompt: store.outboundPrompt)
            } label: {
                Label("Send to Codex", systemImage: "paperplane")
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!allowSending || !store.canAnalyze || store.isWorking)
        }
    }

    private func preset(_ title: String, question: String) -> some View {
        Button(title) { store.question = question }
            .buttonStyle(.borderless)
            .font(.caption)
            .disabled(store.isWorking)
    }
}
