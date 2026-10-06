import SwiftUI

struct ContentView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        NavigationSplitView {
            SidebarView(workspace: workspace)
                .navigationSplitViewColumnWidth(min: 210, ideal: 245, max: 320)
        } detail: {
            VStack(spacing: 0) {
                if let forensicCase = workspace.currentCase {
                    CaseHeaderView(workspace: workspace)
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
            .inspector(isPresented: Binding(
                get: { workspace.showInspector && workspace.currentCase != nil },
                set: { workspace.showInspector = $0 }
            )) {
                Group {
                    if workspace.section == .filesystem {
                        FilesystemInspectorView(workspace: workspace)
                    } else {
                        EvidenceInspectorView(workspace: workspace)
                    }
                }
                .inspectorColumnWidth(min: 280, ideal: 320, max: 420)
            }
        }
        .navigationTitle(workspace.currentCase?.manifest.name ?? "Native Forensics")
        .frame(minWidth: 1040, minHeight: 660)
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
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
            }

            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: workspace.chooseImage) {
                    Label("Add Data Source", systemImage: "externaldrive.badge.plus")
                }
                .help("Inspect a disk image and record its SHA-256 (⇧⌘I)")
                .disabled(!workspace.canInspectImage)

                Button(action: workspace.analyzeSelectedImage) {
                    Label("Analyze Filesystem", systemImage: "play.circle")
                }
                .help("Analyze the selected evidence image (⇧⌘A)")
                .disabled(!workspace.canAnalyzeFilesystem)

                Button(action: workspace.chooseExtractionDestination) {
                    Label("Extract Selected File", systemImage: "square.and.arrow.up")
                }
                .help("Extract the selected file to a new destination (⇧⌘E)")
                .disabled(!workspace.canExtractFilesystemFile)
            }

            ToolbarItem(placement: .automatic) {
                Button { workspace.showInspector.toggle() } label: {
                    Label("Evidence Inspector", systemImage: "sidebar.right")
                }
                .help("Toggle evidence inspector (⌥⌘I)")
                .disabled(workspace.currentCase == nil)
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
