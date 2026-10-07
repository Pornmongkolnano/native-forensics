import Foundation

extension WorkspaceStore {
    var canInspectOpticalHistory: Bool {
        currentCase != nil && selectedEvidence != nil && !isBusy && !isLoadingFilesystem
            && caseWork.canChangeSelection && recovery.canChangeSelection && optical.canInspect
    }
    func showOpticalHistory() {
        guard !isBusy, currentCase != nil, selectedEvidence != nil,
              caseWork.canChangeSelection, recovery.canChangeSelection else { return }
        section = .optical
        showInspector = true
        optical.configure(evidence: selectedEvidence, in: currentCase)
    }
    func inspectSelectedOpticalHistory() {
        guard canInspectOpticalHistory else { return }
        section = .optical
        showInspector = true
        optical.inspect()
    }
}
