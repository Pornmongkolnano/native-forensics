import Foundation
import ForensicsCore

extension WorkspaceStore {
    var canDecryptSelectedEFSFile: Bool {
        !isBusy && selectedEFSContext != nil
    }

    private var selectedEFSContext: EFSKeySelectionContext? {
        guard let forensicCase = currentCase, let evidence = selectedEvidence,
              let result = selectedFilesystemResult, let file = selectedFilesystemFile,
              let generation = filesystemListingGenerations[evidence.id] else { return nil }
        return try? EFSKeySelectionContext(caseID: forensicCase.manifest.id, evidence: evidence,
            listingGenerationID: generation, result: result, file: file)
    }

    func efsSelectionIsCurrent(_ context: EFSKeySelectionContext) -> Bool {
        !isClosing && selectedEFSContext == context
    }

    func showEFSKeyInput() {
        guard canDecryptSelectedEFSFile, let context = selectedEFSContext,
              let forensicCase = currentCase, let result = selectedFilesystemResult else { return }
        let client = EngineClient(helperURL: engineHelperURL)
        let store = EFSKeyInputStore(scheduler: workScheduler,
            validateSelection: { [weak self] in self?.efsSelectionIsCurrent($0) == true },
            operation: { context, material, destination in
                var options = context.options; options.hashLogicalImage = false
                return try await client.extractDecrypted(imagePaths: context.sourcePaths.map { URL(fileURLWithPath: $0) },
                    file: context.file, outputURL: destination, keyMaterial: material,
                    options: options, expectedSourceHashes: context.sourceHashes)
            }, onPublished: { [weak self] publication in
                guard let self else { return }
                if self.efsSelectionIsCurrent(publication.context) {
                    self.extractionReceipt = publication.receipt
                    self.extractionReceiptIsVerified = true
                    self.statusMessage = "Source and decrypted output hashes verified. EFS CBC does not authenticate historical plaintext."
                }
                if !self.isClosing { self.caseWork.refresh() }
            }, recordPublication: { publication in
                await ExtractionHistoryPublication.publish(receipt: publication.receipt,
                    caseID: forensicCase.manifest.id, evidence: context.evidence, result: result,
                    file: context.file, in: forensicCase.bundleURL, id: publication.id)
            })
        store.configure(context: context)
        efsKeyInput = store
    }

    /// Both sheet dismissal and Quit retain the owner until key/helper drainage.
    func closeEFSKeyInput() {
        guard efsClosingTask == nil, let store = efsKeyInput else { return }
        store.cancel()
        efsClosingTask = Task { [weak self] in
            await store.close()
            guard let self else { return }
            if self.efsKeyInput === store { self.efsKeyInput = nil }
            self.efsClosingTask = nil
        }
    }
}
