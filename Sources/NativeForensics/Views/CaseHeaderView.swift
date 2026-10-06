import ForensicsCore
import SwiftUI

struct CaseHeaderView: View {
    let forensicCase: ForensicCase

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(forensicCase.manifest.name)
                    .font(.headline)
                    .lineLimit(1)
                    .help(forensicCase.manifest.name)
                    .textSelection(.enabled)
                Text("Created \(forensicCase.manifest.createdAt.formatted(date: .abbreviated, time: .omitted))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            Text("\(forensicCase.manifest.evidence.count.formatted()) evidence \(forensicCase.manifest.evidence.count == 1 ? "record" : "records")")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
    }
}
