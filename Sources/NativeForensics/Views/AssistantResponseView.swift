import SwiftUI

/// Model output is displayed as selectable literal text. It cannot become a
/// clickable URL, execute markup or trigger a workbench action.
struct AssistantResponseView: View {
    let summary: String
    let observations: [String]
    let hypotheses: [String]
    let limitations: [String]
    let nextSteps: [String]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Label("AI interpretation · verify against the evidence", systemImage: "sparkles")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                responseSection("Summary", text: summary)
                responseSection("Observations", items: observations)
                responseSection("Hypotheses", items: hypotheses)
                responseSection("Limitations", items: limitations)
                responseSection("Next Steps", items: nextSteps)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
    }

    private func responseSection(_ title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout.weight(.semibold))
            Text(verbatim: text)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func responseSection(_ title: String, items: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout.weight(.semibold))
            if items.isEmpty {
                Text("None provided.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("•").foregroundStyle(.secondary)
                        Text(verbatim: item)
                            .font(.callout)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
}
