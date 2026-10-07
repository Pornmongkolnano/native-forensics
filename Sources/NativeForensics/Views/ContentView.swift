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
                    // Native tables can contribute their unbounded content height
                    // to NavigationSplitView's minimum size. Give the work area
                    // a window-sized viewport so long tables cannot push every
                    // split column, including the sidebar, outside the window.
                    GeometryReader { _ in
                        Group {
                            if workspace.section == .caseDetails {
                                CaseDetailsView(forensicCase: forensicCase)
                            } else if workspace.section == .optical {
                                OpticalWorkspaceView(workspace: workspace)
                            } else if workspace.section == .recovery {
                                RecoveryWorkspaceView(workspace: workspace)
                            } else if workspace.section == .filesystem {
                                FilesystemView(workspace: workspace)
                            } else {
                                EvidenceTableView(workspace: workspace)
                            }
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
                    if workspace.section == .optical {
                        OpticalInspectorView(workspace: workspace)
                    } else if workspace.section == .recovery {
                        RecoveryInspectorView(workspace: workspace)
                    } else if workspace.section == .filesystem {
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

                Button(action: workspace.inspectSelectedOpticalHistory) {
                    Label("Inspect UDF History", systemImage: "opticaldisc")
                }
                .help("Inspect bounded UDF optical namespace and VAT history (⌥⌘U)")
                .disabled(!workspace.canInspectOpticalHistory)

                Button(action: workspace.recoverSelectedEvidence) {
                    Label("Recover Files", systemImage: "arrow.uturn.backward.circle")
                }
                .help("Recover file signatures from the whole selected RAW image (⇧⌘R)")
                .disabled(!workspace.canRecoverFiles)

                Button(action: workspace.chooseExtractionDestination) {
                    Label("Extract Selected File", systemImage: "square.and.arrow.up")
                }
                .help("Extract the selected file to a new destination (⇧⌘E)")
                .disabled(!workspace.canExtractFilesystemFile)

                Button(action: workspace.openAssistant) {
                    Label("Analyze with Codex", systemImage: "sparkles")
                }
                .help("Review selected file context and ask Codex (⌥⌘A)")
                .disabled(!workspace.canOpenAssistant)
            }

            ToolbarItem(placement: .automatic) {
                Button { workspace.showInspector.toggle() } label: {
                    Label("Evidence Inspector", systemImage: "sidebar.right")
                }
                .help("Toggle evidence inspector (⌥⌘I)")
                .disabled(workspace.currentCase == nil)
            }
        }
        .sheet(isPresented: Binding(
            get: { workspace.assistant.isPresented },
            set: { if !$0 { workspace.assistant.close() } }
        )) {
            AssistantAnalysisView(store: workspace.assistant)
                .interactiveDismissDisabled(workspace.assistant.isWorking)
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
