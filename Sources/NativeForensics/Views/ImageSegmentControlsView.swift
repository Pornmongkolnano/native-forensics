import SwiftUI

struct ImageSegmentControlsView: View {
    @Bindable var workspace: WorkspaceStore
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Image segments: \(workspace.selectedEvidence == nil ? 0 : workspace.additionalImageSegments.count + 1)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Add Segments…", action: workspace.chooseAdditionalImageSegments)
                    .controlSize(.small)
                    .disabled(workspace.selectedEvidence == nil || workspace.isBusy || workspace.isLoadingFilesystem)
            }
            if let evidence = workspace.selectedEvidence {
                DisclosureGroup("Review read order", isExpanded: $isExpanded) {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("1.").monospacedDigit()
                                Label(URL(fileURLWithPath: evidence.sourcePath).lastPathComponent, systemImage: "lock")
                                    .lineLimit(1)
                                    .help(evidence.sourcePath)
                                Spacer()
                                Text("Recorded first file")
                                    .foregroundStyle(.secondary)
                            }
                            ForEach(Array(workspace.additionalImageSegments.enumerated()), id: \.element.path) { index, url in
                                HStack(spacing: 8) {
                                    Text("\(index + 2).").monospacedDigit()
                                    Text(url.lastPathComponent)
                                        .lineLimit(1)
                                        .help(url.path)
                                    Spacer()
                                    Button {
                                        workspace.moveImageSegment(at: index, by: -1)
                                    } label: { Image(systemName: "arrow.up") }
                                        .disabled(index == 0 || workspace.isBusy || workspace.isLoadingFilesystem)
                                        .help("Move segment earlier")
                                    Button {
                                        workspace.moveImageSegment(at: index, by: 1)
                                    } label: { Image(systemName: "arrow.down") }
                                        .disabled(index == workspace.additionalImageSegments.count - 1 || workspace.isBusy || workspace.isLoadingFilesystem)
                                        .help("Move segment later")
                                    Button {
                                        workspace.removeImageSegment(at: index)
                                    } label: { Image(systemName: "minus.circle") }
                                        .disabled(workspace.isBusy || workspace.isLoadingFilesystem)
                                        .help("Remove segment from this analysis")
                                }
                            }
                        }
                        .buttonStyle(.borderless)
                        .padding(.vertical, 6)
                    }
                    .frame(height: min(140, CGFloat(workspace.additionalImageSegments.count + 1) * 28))
                    Text("New selections initially use natural filename order. Review the order above; it is sent exactly as shown. Additional segments are hashed separately. Extraction uses the ordered inputs saved with the listing.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .font(.caption)
            }
        }
        .onChange(of: workspace.additionalImageSegments.count) { _, count in
            if count > 0 { isExpanded = true }
        }
        .onAppear { isExpanded = !workspace.additionalImageSegments.isEmpty }
    }
}
