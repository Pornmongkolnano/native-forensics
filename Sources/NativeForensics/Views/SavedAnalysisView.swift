import AppKit
import ForensicsCore
import SwiftUI

/// Saved responses and prompts remain selectable literal text. They cannot
/// turn into links, executable actions or verified examiner findings.
struct SavedAnalysisView: View {
    let record: AnalysisRecord
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Saved AI Analysis", systemImage: "sparkles").font(.title2.weight(.semibold))
            Text(verbatim: record.binding.selectedEntry.path).font(.callout).textSelection(.enabled)
            Text("Historical AI interpretation · verify against the evidence. Opening this record does not rehash sources or outputs.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    field("Question", record.question)
                    AssistantResponseView(summary: record.result.response.summary, observations: record.result.response.observations,
                        hypotheses: record.result.response.hypotheses, limitations: record.result.response.limitations,
                        nextSteps: record.result.response.nextSteps)
                        .frame(height: 290)
                    GroupBox("Retention and provenance") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text(record.retention == .full
                                 ? "Full retention: the exact UTF-8 request sent by this app to the CLI is retained. This is not an HTTP payload receipt."
                                 : "Digest-only retention: the question, answer and provenance are retained, but the exact request cannot be reconstructed.")
                                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            field("Saved completion", record.createdAt.formatted(date: .abbreviated, time: .standard))
                            field("Execution adapter", record.result.provider)
                            field("Execution mode", record.result.executionMode)
                            field("CLI version", record.cliVersion ?? "Unknown · not recorded")
                            field("Model version", record.modelVersion ?? "Unknown · not supplied by a validated receipt")
                            field("Prompt template", record.promptTemplateVersion)
                            hash("Exact app request SHA-256", record.requestSHA256)
                            hash("Recorded filesystem snapshot SHA-256", record.binding.snapshotSHA256)
                            field("Evidence ID", record.binding.evidenceID.uuidString)
                            field("Exact file ID", record.binding.selectedEntry.id)
                            hash("File locator SHA-256", record.binding.locatorSHA256)
                            field("Recorded filesystem snapshot", record.binding.snapshotSavedAt.formatted(date: .abbreviated, time: .standard))
                            hash("Selected container SHA-256 · \(record.binding.selectedContainerHash.scope)", record.binding.selectedContainerHash.sha256)
                            if let logical = record.binding.logicalImageHash { hash("Logical image SHA-256 · \(logical.scope)", logical.sha256) }
                            DisclosureGroup("Ordered container hashes · \(record.binding.containerHashes.count)") {
                                LazyVStack(alignment: .leading, spacing: 10) {
                                    ForEach(record.binding.containerHashes, id: \.index) { container in
                                        hash("Container \(container.index + 1) · \(container.scope)", container.sha256)
                                    }
                                }
                            }
                            if let content = record.contentHash {
                                hash("Extracted content SHA-256 · \(content.scope)", content.sha256)
                                field("Disclosed text", "\(record.disclosedContentByteCount) of \(record.completeContentByteCount ?? 0) bytes")
                            }
                            field("Source verification", record.sourceBytesVerifiedForContentAtRequest
                                  ? "Sources verified for content at request time; current bytes are unknown."
                                  : "Historical metadata only; source bytes were not reverified for this request.")
                            field("Recorded engine", record.binding.engineVersion)
                            field("Recorded patch provenance", record.binding.patchDigest)
                            field("Evidence timezone", record.binding.options.timezone)
                            field("Recorded status", record.binding.status.rawValue)
                            field("Record ID", record.id.uuidString)
                            ForEach(Array(record.warnings.enumerated()), id: \.offset) { _, warning in
                                Text(verbatim: warning).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let prompt = record.prompt {
                        DisclosureGroup("Retained exact app request") {
                            AssistantContextPreviewView(prompt: prompt).frame(height: 240)
                            Button("Copy Retained Request") { copy(prompt) }
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Button("Copy Answer") { copy(responseText) }
                Spacer()
                Button("Close", action: { dismiss() }).keyboardShortcut(.cancelAction)
            }
        }.padding(20).frame(width: 720, height: 640)
    }

    private var responseText: String {
        let response = record.result.response
        return (["Summary\n\(response.summary)"] + [
            ("Observations", response.observations), ("Hypotheses", response.hypotheses),
            ("Limitations", response.limitations), ("Next Steps", response.nextSteps)
        ].map { title, items in "\(title)\n" + items.map { "• \($0)" }.joined(separator: "\n") }).joined(separator: "\n\n")
    }

    private func field(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(verbatim: value).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
    private func hash(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(verbatim: value).font(.caption.monospaced()).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
    private func copy(_ value: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string)
    }
}
