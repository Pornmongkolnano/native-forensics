import ForensicsCore
import SwiftUI

struct CaseHeaderView: View {
    let forensicCase: ForensicCase

    var body: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 4) {
                Text(forensicCase.manifest.name)
                    .font(.title2.weight(.semibold))
                    .textSelection(.enabled)
                Text("Created \(forensicCase.manifest.createdAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label("File inspection", systemImage: "checkmark.shield")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
    }
}
