import Foundation
import ForensicsCore

extension WorkspaceStore {
    var canOpenComparison: Bool {
        !isBusy && !isLoadingFilesystem && comparisonSelection.canCompare
            && currentCase != nil && selectedEvidence != nil && selectedFilesystemResult != nil
            && caseWork.canChangeSelection && recovery.canChangeSelection
    }
    var canOpenComparisonHistory: Bool { !isBusy && currentCase != nil }

    func openComparisonHistory() {
        guard canOpenComparisonHistory, let forensicCase = currentCase else { return }
        comparisonAssistant.configureHistory(forensicCase: forensicCase)
    }

    func showContentSearch() {
        guard !isBusy, let forensicCase = currentCase else { return }
        section = .contentSearch
        contentIndex.configure(forensicCase: forensicCase, results: filesystemResults)
    }

    func showComparison() {
        guard !isBusy, currentCase != nil, selectedEvidence != nil else { return }
        comparisonSelection.configure(result: selectedFilesystemResult)
        section = .comparison
    }

    func openComparison() {
        guard canOpenComparison, let forensicCase = currentCase, let evidence = selectedEvidence,
              let result = selectedFilesystemResult, let first = comparisonSelection.firstFile,
              let second = comparisonSelection.secondFile,
              result.files.contains(first), result.files.contains(second) else { return }
        comparisonAssistant.cliPath = CodexCLIAvailability.configuredPath
        comparisonAssistant.configure(evidence: evidence, result: result, files: [first, second],
                                      helperURL: engineHelperURL, forensicCase: forensicCase)
    }

    func showTimeline() {
        guard !isBusy, currentCase != nil, selectedEvidence != nil else { return }
        section = .timeline
        configureTimeline()
    }

    func showCaseIntegrity() {
        guard !isBusy, let forensicCase = currentCase else { return }
        section = .integrity
        caseIntegrity.configure(forensicCase: forensicCase)
    }

    func refreshDerivedWorkspaces() {
        guard !isClosing, let forensicCase = currentCase else { return }
        if section == .contentSearch {
            contentIndex.configure(forensicCase: forensicCase, results: filesystemResults)
        }
        if section == .timeline { configureTimeline() }
    }

    private func configureTimeline() {
        guard let forensicCase = currentCase, let evidence = selectedEvidence,
              let result = selectedFilesystemResult else { timeline.reset(); return }
        timeline.configure(caseID: forensicCase.manifest.id, evidence: evidence,
                           result: result, historical: true, caseURL: forensicCase.bundleURL)
    }

    func openContentIndexReference(_ reference: ContentIndexReference) {
        guard let snapshot = contentIndex.snapshot,
              snapshot.caseID == currentCase?.manifest.id,
              CaseContentIndexSearch.resolve(reference, in: snapshot) != nil,
              let source = snapshot.sources.first(where: { $0.evidenceID == reference.evidenceID }) else {
            errorMessage = "This content reference does not resolve in the current derived index."
            return
        }
        openRecordedFile(evidenceID: reference.evidenceID, fileID: reference.file.id) { evidence, result in
            guard result.files.contains(reference.file),
                  try ContentIndexSource.make(ContentIndexInput(evidence: evidence, result: result)) == source else {
                throw ForensicsError.sourceChanged
            }
        }
    }

    func openTimelineFile(_ binding: TimelineSourceBinding, _ fileID: String) {
        guard timeline.report?.binding == binding, binding.caseID == currentCase?.manifest.id else {
            errorMessage = "This timeline reference belongs to a different report."
            return
        }
        openRecordedFile(evidenceID: binding.evidenceID, fileID: fileID) { evidence, result in
            guard try TimelineSourceBinding.make(caseID: binding.caseID, evidence: evidence,
                                                  result: result, historical: binding.historical) == binding else {
                throw ForensicsError.sourceChanged
            }
        }
    }

    /// Resolving a saved reference opens recorded metadata only. Explicit preview
    /// or extraction then freshly checks source bytes through the existing service.
    private func openRecordedFile(evidenceID: UUID, fileID: String,
        validate: @escaping @Sendable (EvidenceRecord, EnumerationResult) throws -> Void) {
        guard !isBusy, !isClosing, caseWork.canChangeSelection, recovery.canChangeSelection,
              let forensicCase = currentCase,
              let evidence = forensicCase.manifest.evidence.first(where: { $0.id == evidenceID }) else { return }
        let existing = filesystemResults[evidenceID], id = UUID()
        derivedNavigationID = id
        derivedNavigationTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.derivedNavigationID == id {
                    self.derivedNavigationID = nil; self.derivedNavigationTask = nil
                }
            }
            do {
                let (result, cost) = try await self.workScheduler.run(.historyRead) { _ in
                    guard let result = try existing ?? EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL),
                          result.files.contains(where: { $0.id == fileID }),
                          result.sourcePaths.first == evidence.sourcePath,
                          result.sourceFileHashes[evidence.sourcePath] == evidence.sha256 else {
                        throw ForensicsError.sourceChanged
                    }
                    try validate(evidence, result)
                    return (result, try FilesystemListingStringCost.measure(result))
                }
                try Task.checkCancellation()
                guard self.derivedNavigationID == id, !self.isClosing,
                      self.currentCase?.manifest.id == forensicCase.manifest.id,
                      self.currentCase?.bundleURL == forensicCase.bundleURL else { return }
                guard self.retainFilesystemResult(result, evidenceID: evidenceID, cost: cost) else {
                    throw EngineError.limitExceeded("The recorded listing exceeds the in-memory retention budget. Its disk artifact was preserved.")
                }
                self.selectedEvidenceID = evidenceID
                self.refreshFilesystemSelection()
                self.filesystemCategory = .all; self.filesystemSearchText = ""
                self.selectedFileID = fileID; self.section = .filesystem; self.showInspector = true
                self.statusMessage = "Opened the exact recorded file reference. Preview or extract to verify current source bytes."
            } catch is CancellationError {
            } catch {
                guard self.derivedNavigationID == id else { return }
                self.errorMessage = "The recorded file reference is stale or unavailable: \(error.localizedDescription)"
            }
        }
    }
}
