import SwiftUI

struct SidebarView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        List(selection: $workspace.section) {
            Section("Workbench") {
                ForEach(WorkspaceSection.allCases) { section in
                    Label(section.title, systemImage: section.symbol)
                        .tag(section)
                }
            }

            if let forensicCase = workspace.currentCase {
                Section("Current Case") {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(forensicCase.manifest.name)
                            .fontWeight(.medium)
                            .lineLimit(1)
                        Text("\(forensicCase.manifest.evidence.count) evidence records")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .selectionDisabled()
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 6) {
                Image(systemName: "shield.lefthalf.filled")
                Text("Evidence is read only")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
