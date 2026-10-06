import SwiftUI

struct SidebarView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        List(selection: $workspace.section) {
            Section("Workbench") {
                ForEach(WorkspaceSection.allCases) { section in
                    HStack(spacing: 9) {
                        Image(systemName: section.symbol)
                            .foregroundStyle(.secondary)
                            .frame(width: 16)
                        Text(section.title)
                    }
                    .tag(section)
                }
            }

            if let forensicCase = workspace.currentCase {
                Section("Current Case") {
                    HStack(alignment: .top, spacing: 9) {
                        Image(systemName: "folder")
                            .foregroundStyle(.secondary)
                            .frame(width: 16)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(forensicCase.manifest.name)
                                .fontWeight(.medium)
                                .lineLimit(1)
                                .help(forensicCase.manifest.name)
                            Text("\(forensicCase.manifest.evidence.count.formatted()) evidence \(forensicCase.manifest.evidence.count == 1 ? "record" : "records")")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .selectionDisabled()
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 6) {
                Image(systemName: "lock.shield")
                Text("Read-only evidence")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
