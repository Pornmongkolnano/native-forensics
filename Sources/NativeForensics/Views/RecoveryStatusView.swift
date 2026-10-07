import ForensicsCore
import SwiftUI

struct RecoveryStatusView: View {
    let store: RecoveryWorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(store.statusMessage).lineLimit(1).help(store.statusMessage)
                Spacer()
                Button("Cancel", action: store.cancel).help("Cancel owned recovery or preview work (⌘.)")
            }
            if let progress = store.progress {
                Text("\(progress.stage) · \(progress.completed.formatted())\(progress.total.map { " of \($0.formatted())" } ?? "") \(progress.unit)")
                    .foregroundStyle(.secondary).monospacedDigit()
                Text("Progress is reported by stage; no exact completion estimate is inferred.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
