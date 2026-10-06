import SwiftUI

struct WelcomeView: View {
    let workspace: WorkspaceStore

    var body: some View {
        ContentUnavailableView {
            Label("Native Forensics", systemImage: "externaldrive")
        } description: {
            Text("Create a case to inspect a disk image. Record the selected file's size and SHA-256 while keeping the evidence unchanged.")
                .frame(maxWidth: 450)
        } actions: {
            HStack {
                Button("Create Case…", action: workspace.createCase)
                    .buttonStyle(.borderedProminent)
                Button("Open Case…", action: workspace.chooseCase)
            }
            .disabled(workspace.isBusy)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
