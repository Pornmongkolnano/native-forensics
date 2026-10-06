import SwiftUI

struct WelcomeView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 14) {
                Image(systemName: "externaldrive.badge.checkmark")
                    .font(.system(size: 42, weight: .light))
                    .foregroundStyle(Color.accentColor)
                    .padding(20)
                    .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 22))
                    .accessibilityHidden(true)
                Text("Native Forensics")
                    .font(.largeTitle.weight(.semibold))
                Text("A workspace for your evidence")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                Text("Record image hashes, explore filesystems and verify extracted files in a saved case.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: 12) {
                Button("Create Case…", action: workspace.createCase)
                    .buttonStyle(.borderedProminent)
                    .help("Create a new case (⌘N)")
                Button("Open Case…", action: workspace.chooseCase)
                    .help("Open a saved case (⌘O)")
            }
            .controlSize(.large)
            .disabled(workspace.isBusy)
            HStack(alignment: .top, spacing: 28) {
                step("Create a case", detail: "Keep your work together", symbol: "folder.badge.plus")
                step("Inspect an image", detail: "Record size and SHA-256", symbol: "externaldrive")
                step("Explore files", detail: "Analyze and extract", symbol: "doc.text.magnifyingglass")
            }
            .padding(.top, 12)
            Label("Evidence sources stay read only", systemImage: "lock.shield")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func step(_ title: String, detail: String, symbol: String) -> some View {
        VStack(spacing: 7) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(.secondary)
            Text(title).font(.callout.weight(.medium))
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
        .multilineTextAlignment(.center)
    }
}
