import SwiftUI

/// Keeps every character of the outbound prompt available for review without
/// asking the text renderer to lay out one unbounded evidence blob.
struct AssistantContextPreviewView: View {
    let prompt: String
    @State private var page = 0

    private static let pageLength = 20_000

    private var pages: [String] {
        guard !prompt.isEmpty else { return [] }
        var result: [String] = []
        var start = prompt.startIndex
        while start < prompt.endIndex {
            let end = prompt.index(start, offsetBy: Self.pageLength, limitedBy: prompt.endIndex) ?? prompt.endIndex
            result.append(String(prompt[start..<end]))
            start = end
        }
        return result
    }

    var body: some View {
        let chunks = pages
        let selectedPage = min(page, max(0, chunks.count - 1))
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Exact outbound prompt", systemImage: "doc.text.magnifyingglass")
                    .font(.caption.weight(.semibold))
                Spacer()
                if chunks.count > 1 {
                    Button {
                        page = max(0, selectedPage - 1)
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .disabled(selectedPage == 0)
                    .accessibilityLabel("Previous context page")
                    Text("\(selectedPage + 1) of \(chunks.count)")
                        .font(.caption.monospacedDigit())
                    Button {
                        page = min(chunks.count - 1, selectedPage + 1)
                    } label: {
                        Image(systemName: "chevron.right")
                    }
                    .disabled(selectedPage == chunks.count - 1)
                    .accessibilityLabel("Next context page")
                }
            }
            if chunks.isEmpty {
                ContentUnavailableView("Prepare a Context", systemImage: "doc.text", description: Text("Prepare the selected file's context before reviewing or sending it."))
            } else {
                ScrollView(.vertical) {
                    Text(verbatim: chunks[selectedPage])
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(10)
                }
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                .accessibilityLabel("Outbound prompt, page \(selectedPage + 1) of \(chunks.count)")
            }
        }
        .onChange(of: prompt) { _, _ in page = 0 }
    }
}
