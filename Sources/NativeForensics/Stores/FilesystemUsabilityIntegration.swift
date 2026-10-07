import Foundation
import ForensicsCore

extension WorkspaceStore {
    var matchingExportableFiles: [FilesystemEntry] {
        FilesystemBatchExportStore.eligibleFiles(in: filesystemRows)
    }
    var canExtractAllMatched: Bool {
        let count = matchingExportableFiles.count
        return currentCase != nil && selectedEvidence != nil && selectedFilesystemResult != nil && (1...1_000).contains(count)
            && !isBusy && !isFilteringFilesystem && !isLoadingFilesystem && caseWork.canChangeSelection && recovery.canChangeSelection
    }
    func exportMatchingFilesystemFiles() {
        guard canExtractAllMatched, let forensicCase = currentCase, let evidence = selectedEvidence,
              let result = selectedFilesystemResult else { return }
        let files = matchingExportableFiles
        isPresentingPanel = true
        filesystemBatchPanelTask = Task { [weak self] in
            guard let self else { return }
            defer { self.isPresentingPanel = false; self.filesystemBatchPanelTask = nil }
            guard !self.isClosing, !Task.isCancelled else { return }
            guard let destination = await CasePanelService.newFilesystemBatchDestination(), !self.isClosing, !Task.isCancelled else { return }
            guard self.currentCase?.manifest.id == forensicCase.manifest.id,
                  self.currentCase?.bundleURL == forensicCase.bundleURL,
                  self.selectedEvidence == evidence, self.selectedFilesystemResult == result else {
                self.errorMessage = "The selected source or saved filesystem changed while choosing an export destination. Start again with the current selection."
                return
            }
            self.filesystemBatchExport.start(analysis: result, files: files, destination: destination, caseURL: forensicCase.bundleURL)
        }
    }
}
