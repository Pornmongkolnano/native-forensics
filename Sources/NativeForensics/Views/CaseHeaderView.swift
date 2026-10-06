import ForensicsCore
import SwiftUI

struct CaseHeaderView: View {
    let workspace: WorkspaceStore

    private var title: String {
        workspace.section == .filesystem ? workspace.filesystemCategory.title
            : workspace.section == .caseDetails ? "Case Details" : "Data Sources"
    }

    private var symbol: String {
        workspace.section == .filesystem ? workspace.filesystemCategory.symbol
            : workspace.section == .caseDetails ? "folder.badge.gearshape" : "externaldrive.fill"
    }

    private var sourceCount: String {
        let count = workspace.currentCase?.manifest.evidence.count ?? 0
        return "\(count.formatted()) \(count == 1 ? "source" : "sources")"
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                HStack(spacing: 5) {
                    Text(workspace.currentCase?.manifest.name ?? "Case")
                    if workspace.section == .filesystem, let source = workspace.selectedEvidence {
                        Image(systemName: "chevron.right").font(.system(size: 8, weight: .semibold))
                        Text(URL(fileURLWithPath: source.sourcePath).lastPathComponent)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            }
            Spacer(minLength: 12)
            Label(sourceCount, systemImage: "externaldrive")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
    }
}
