import SwiftUI

struct OpticalStatusView: View {
    let store: OpticalWorkspaceStore
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(store.statusMessage).lineLimit(1).help(store.statusMessage)
                Spacer()
                Button("Cancel", action: store.cancel)
            }
            if let progress = store.progress {
                Text("\(progress.stage) · \(progress.completedBytes.formatted()) / \(progress.totalBytes.formatted()) bytes · \(progress.files.formatted()) files")
                    .foregroundStyle(.secondary).monospacedDigit()
            }
        }
    }
}
