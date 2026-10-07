import ForensicsCore

extension WorkspaceStore {
    var canOpenAssistant: Bool {
        !isBusy && !isLoadingFilesystem && !isFilteringFilesystem
            && currentCase != nil && selectedEvidence != nil
            && selectedFilesystemResult != nil
            && selectedFilesystemFile.map({ !$0.isDirectory }) == true
    }

    func openAssistant() {
        guard canOpenAssistant, let evidence = selectedEvidence,
              let result = selectedFilesystemResult,
              let file = selectedFilesystemFile else { return }
        assistant.cliPath = CodexCLIAvailability.configuredPath
        assistant.configure(evidence: evidence, result: result, file: file, helperURL: engineHelperURL,
                            forensicCase: currentCase)
    }
}
