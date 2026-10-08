import Foundation
import ForensicsCore

extension WorkspaceStore {
    func showAPFSFiles() {
        guard !isBusy, !isClosing, currentCase != nil, selectedEvidence != nil else { return }
        section = .apfs
        apfs.configure(evidence: selectedEvidence, in: currentCase)
    }
}
