import Foundation

/// Owns workspaces while their windows are visible and retains closed ones
/// until cancellation, atomic publication and helper cleanup have finished.
@MainActor
final class WorkspaceLifecycle {
    static let shared = WorkspaceLifecycle()
    private var workspaces: [ObjectIdentifier: WorkspaceStore] = [:]

    var count: Int { workspaces.count }
    var hasActiveWork: Bool { workspaces.values.contains(where: \.hasActiveWork) }
    var unsavedNoteCount: Int { workspaces.values.reduce(0) { $0 + $1.caseWork.retainedDraftCount } }

    func discardUnsavedNotes() {
        for workspace in workspaces.values { workspace.caseWork.discardAllDrafts() }
    }

    func register(_ workspace: WorkspaceStore) {
        workspaces[ObjectIdentifier(workspace)] = workspace
    }

    func close(_ workspace: WorkspaceStore) {
        register(workspace)
        workspace.prepareForClosing()
        Task {
            await workspace.shutdown()
            workspaces[ObjectIdentifier(workspace)] = nil
        }
    }

    func prepareForTermination() {
        for workspace in workspaces.values { workspace.prepareForClosing() }
    }

    func shutdownAll() async {
        let pending = Array(workspaces.values)
        // Start cancellation on every window before awaiting any one worker.
        let jobs = pending.flatMap { $0.beginShutdown() }
        for job in jobs { await job.value }
        for workspace in pending { workspaces[ObjectIdentifier(workspace)] = nil }
    }
}
