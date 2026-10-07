import Foundation

extension WorkspaceStore {
    var canRecoverFiles: Bool {
        currentCase != nil && selectedEvidence != nil && !isBusy && !isLoadingFilesystem
            && caseWork.canChangeSelection && recovery.canChangeSelection && recovery.canRecover
    }

    func showRecoveredFiles() {
        guard !isBusy, currentCase != nil, selectedEvidence != nil, caseWork.canChangeSelection, recovery.canChangeSelection else { return }
        section = .recovery
        showInspector = true
        recovery.configure(evidence: selectedEvidence, in: currentCase)
    }

    func recoverSelectedEvidence() {
        guard canRecoverFiles else { return }
        section = .recovery
        showInspector = true
        recovery.beginRecovery()
    }
}
