import SwiftUI

struct ContentView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        NavigationSplitView {
            SidebarView(workspace: workspace)
                .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 280)
        } detail: {
            VStack(spacing: 0) {
                if let forensicCase = workspace.currentCase {
                    CaseHeaderView(forensicCase: forensicCase)
                    Divider()
                    if workspace.section == .caseDetails {
                        CaseDetailsView(forensicCase: forensicCase)
                    } else if workspace.section == .filesystem {
                        FilesystemView(workspace: workspace)
                    } else {
                        EvidenceTableView(workspace: workspace)
                    }
                } else {
                    WelcomeView(workspace: workspace)
                }
                Divider()
                InspectionStatusView(workspace: workspace)
            }
            .inspector(isPresented: $workspace.showInspector) {
                Group {
                    if workspace.section == .filesystem {
                        FilesystemInspectorView(workspace: workspace)
                    } else {
                        EvidenceInspectorView(workspace: workspace)
                    }
                }
                .inspectorColumnWidth(min: 270, ideal: 310, max: 420)
            }
        }
        .navigationTitle(workspace.currentCase?.manifest.name ?? "Native Forensics")
        .frame(minWidth: 900, minHeight: 580)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: workspace.createCase) {
                    Label("New Case", systemImage: "folder.badge.plus")
                }
                .help("Create a new forensic case (⌘N)")
                .disabled(workspace.isBusy)

                Button(action: workspace.chooseCase) {
                    Label("Open Case", systemImage: "folder")
                }
                .help("Open a saved case (⌘O)")
                .disabled(workspace.isBusy)

                Button(action: workspace.chooseImage) {
                    Label("Inspect Image", systemImage: "externaldrive.badge.plus")
                }
                .help("Inspect a disk image and record its SHA-256 (⇧⌘I)")
                .disabled(!workspace.canInspectImage)

                Button(action: workspace.analyzeSelectedImage) {
                    Label("Analyze Filesystem", systemImage: "list.bullet.rectangle")
                }
                .help("Analyze the selected evidence image (⇧⌘A)")
                .disabled(!workspace.canAnalyzeFilesystem)
            }

            ToolbarItem(placement: .automatic) {
                Button { workspace.showInspector.toggle() } label: {
                    Label("Evidence Inspector", systemImage: "sidebar.right")
                }
                .help("Toggle evidence inspector (⌥⌘I)")
            }
        }
        .alert("Unable to Complete Action", isPresented: Binding(
            get: { workspace.errorMessage != nil },
            set: { if !$0 { workspace.errorMessage = nil } }
        )) {
            Button("OK") { workspace.errorMessage = nil }
        } message: {
            Text(workspace.errorMessage ?? "")
        }
    }
}
