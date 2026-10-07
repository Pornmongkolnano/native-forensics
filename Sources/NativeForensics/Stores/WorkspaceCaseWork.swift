import ForensicsCore

extension WorkspaceStore {
    /// A file ID can be reused by another snapshot/stream. Refresh using the
    /// exact selected entry after evidence changes and after index rebuilds.
    func refreshSelectedFileWork() {
        guard !isClosing else { return }
        guard let forensicCase = currentCase, let evidence = selectedEvidence,
              let result = selectedFilesystemResult, let file = selectedFilesystemFile,
              result.files.first(where: { $0.id == file.id }) == file else {
            filesystemDocumentPreview.reset()
            contentPreview.reset()
            _ = caseWork.reset()
            return
        }
        guard caseWork.configure(forensicCase: forensicCase, evidence: evidence, result: result, file: file) else {
            errorMessage = caseWork.errorMessage ?? "Save or discard the note draft before changing files."
            return
        }
        filesystemDocumentPreview.configure(evidence: evidence, result: result, file: file)
        contentPreview.configure(evidence: evidence, result: result, file: file, helperURL: engineHelperURL)
    }
}
