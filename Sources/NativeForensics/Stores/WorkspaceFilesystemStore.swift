import Foundation
import ForensicsCore

extension WorkspaceStore {
    var navigationSelection: WorkspaceNavigationSelection? {
        switch section {
        case .evidence: return .overview
        case .caseDetails: return .caseDetails
        case .recovery: return .recovery
        case .optical: return .optical
        case .apfs: return .apfs
        case .contentSearch: return .contentSearch
        case .comparison: return .comparison
        case .timeline: return .timeline
        case .integrity: return .integrity
        case .filesystem:
            if !filesystemNavigationShowsCategory, let selectedEvidenceID {
                return .dataSource(selectedEvidenceID)
            }
            return .fileView(filesystemCategory)
        case nil: return nil
        }
    }

    func navigate(to selection: WorkspaceNavigationSelection) {
        guard !isBusy else { return }
        switch selection {
        case .overview: section = .evidence
        case .caseDetails: section = .caseDetails
        case .recovery: showRecoveredFiles()
        case .optical: showOpticalHistory()
        case .apfs: showAPFSFiles()
        case .contentSearch: showContentSearch()
        case .comparison: showComparison()
        case .timeline: showTimeline()
        case .integrity: showCaseIntegrity()
        case .dataSource(let evidenceID): chooseDataSource(evidenceID)
        case .fileView(let category): chooseFileView(category)
        }
    }

    func chooseDataSource(_ evidenceID: UUID) {
        guard !isBusy, currentCase?.manifest.evidence.contains(where: { $0.id == evidenceID }) == true else { return }
        selectedEvidenceID = evidenceID
        filesystemSearchText = ""
        filesystemCategory = .all
        filesystemNavigationShowsCategory = false
        section = .filesystem
    }

    func chooseFileView(_ category: FilesystemCategory) {
        guard !isBusy, currentCase != nil, selectedEvidence != nil else { return }
        filesystemCategory = category
        filesystemNavigationShowsCategory = true
        section = .filesystem
    }

    var selectedFilesystemResult: EnumerationResult? {
        guard let selectedEvidenceID else { return nil }
        return filesystemResults[selectedEvidenceID]
    }

    var selectedFilesystemFile: FilesystemEntry? {
        guard let selectedFileID else { return nil }
        return filesystemFilesByID[selectedFileID]
    }

    var canAnalyzeFilesystem: Bool {
        selectedEvidence != nil && currentCase != nil && !isBusy && !isLoadingFilesystem && caseWork.canChangeSelection
            && TimeZone(identifier: evidenceTimezone) != nil
            && validatedEngineMaxFiles != nil
    }

    var validatedEngineMaxFiles: Int? {
        let text = engineMaxFilesText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }),
              let value = Int(text), (1...50_000).contains(value) else { return nil }
        return value
    }

    var engineMaxFilesValidationMessage: String? {
        validatedEngineMaxFiles == nil ? "Enter a whole number from 1 to 50,000 for the listing limit." : nil
    }

    var canExtractFilesystemFile: Bool {
        guard let file = selectedFilesystemFile else { return false }
        return !isBusy && !isFilteringFilesystem && !file.isDirectory && selectedEvidence != nil
    }

    var engineOptions: EngineOptions {
        EngineOptions(imageType: engineImageType, sectorSize: engineSectorSize,
                      timezone: evidenceTimezone, maxFiles: engineMaxFiles)
    }

    /// Debounce typing and keep Foundation's Unicode matching off the UI actor.
    /// Generation + source-selection guards prevent an old query being published.
    @discardableResult
    func refreshFilesystemRows() -> UInt64? {
        cancelFilesystemSearch(outcome: .superseded)
        guard !isClosing else { return nil }
        let timing = filesystemUITiming
        let trialID = timing.begin()
        let index = filesystemSearchIndex
        let query = filesystemSearchText
        let category = filesystemCategory
        let searchRows = filesystemRowSearch
        guard !query.isEmpty || category != .all else {
            filesystemRows = (try? index.rows(matching: "")) ?? []
            clearInvisibleFilesystemSelection(in: filesystemRows)
            timing.record(.rowsPublished, trialID: trialID)
            timing.finish(.published, trialID: trialID)
            return trialID
        }
        let searchID = UUID()
        let evidenceID = selectedEvidenceID
        let caseID = currentCase?.manifest.id
        let caseURL = currentCase?.bundleURL
        filesystemSearchID = searchID
        isFilteringFilesystem = true
        let priorOwners = Array(filesystemSearchJobs.values)
        timing.record(.scheduled, trialID: trialID)
        filesystemSearchTask = Task { [weak self] in
            var outcome = UIInteractionOutcome.cancelled
            defer {
                if let cancellation = self?.filesystemSearchCancellationOutcomes.removeValue(forKey: searchID) {
                    outcome = cancellation
                }
                timing.finish(outcome, trialID: trialID)
                self?.filesystemSearchJobs.removeValue(forKey: searchID)
                if let self, self.filesystemSearchID == searchID {
                    self.isFilteringFilesystem = false
                    self.filesystemSearchID = nil
                    self.filesystemSearchTask = nil
                }
            }
            do {
                for owner in priorOwners { await owner.value }
                try Task.checkCancellation()
                try await Task.sleep(for: .milliseconds(120))
                try Task.checkCancellation()
                let worker = Task.detached(priority: .userInitiated) {
                    timing.record(.workerStarted, trialID: trialID)
                    let rows = try searchRows(index, query, category)
                    timing.record(.workerFinished, trialID: trialID)
                    return rows
                }
                let rows = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
                try Task.checkCancellation()
                guard let self, self.filesystemSearchID == searchID,
                      self.selectedEvidenceID == evidenceID,
                      self.currentCase?.manifest.id == caseID,
                      self.currentCase?.bundleURL == caseURL,
                      self.filesystemSearchText == query,
                      self.filesystemCategory == category else { outcome = .superseded; return }
                self.filesystemRows = rows
                self.clearInvisibleFilesystemSelection(in: rows)
                timing.record(.rowsPublished, trialID: trialID)
                outcome = .published
            } catch is CancellationError {
                outcome = .cancelled
            } catch {
                outcome = .failed
                // Superseded queries are cancelled; the matching generation's
                // defer releases its activity state without publishing old rows.
            }
        }
        if let task = filesystemSearchTask { filesystemSearchJobs[searchID] = task }
        return trialID
    }

    func cancelFilesystemSearch(outcome: UIInteractionOutcome = .cancelled) {
        if let id = filesystemSearchID { filesystemSearchCancellationOutcomes[id] = outcome }
        filesystemSearchID = nil
        filesystemSearchTask?.cancel()
        for task in filesystemSearchJobs.values { task.cancel() }
        filesystemSearchTask = nil
        isFilteringFilesystem = false
    }

    private func clearInvisibleFilesystemSelection(in rows: [FilesystemEntry]) {
        if let selected = selectedFileID, !rows.contains(where: { $0.id == selected }) {
            selectedFileID = nil
        }
    }

    func refreshFilesystemSelection() {
        guard !isClosing else { return }
        let selectedCaseID = currentCase?.manifest.id
        guard filesystemSelectionID != selectedEvidenceID || filesystemSelectionCaseID != selectedCaseID else { return }
        // A completed export is historical output for the previous source.
        // Clear its presentation without touching its published folder.
        filesystemBatchExport.reset()
        filesystemSelectionID = selectedEvidenceID
        filesystemSelectionCaseID = selectedCaseID
        cancelFilesystemLoad()
        cancelFilesystemSearch()
        filesystemSearchIndex = FilesystemSearchIndex(files: [])
        selectedFileID = nil
        extractionReceipt = nil
        extractionReceiptIsVerified = false
        filesystemSearchText = ""
        filesystemCategory = .all
        filesystemNavigationShowsCategory = false
        additionalImageSegments = []
        filesystemRows = []
        filesystemFilesByID = [:]
        if let cached = selectedFilesystemResult {
            if let id = selectedEvidenceID { filesystemListingRetention.touch(id) }
            applyFilesystemOptions(cached)
            rebuildFilesystemIndex()
            refreshFilesystemRows()
            return
        }
        guard let evidence = selectedEvidence, let forensicCase = currentCase else { return }
        let loadID = UUID()
        let evidenceID = evidence.id
        let caseID = forensicCase.manifest.id
        let caseURL = forensicCase.bundleURL
        let sourcePath = evidence.sourcePath
        filesystemLoadID = loadID
        isLoadingFilesystem = true
        let priorOwners = Array(filesystemLoadJobs.values)
        filesystemLoadTask = Task { [weak self] in
            guard let self else { return }
            defer {
                self.filesystemLoadJobs.removeValue(forKey: loadID)
                if self.filesystemLoadID == loadID {
                    self.isLoadingFilesystem = false
                    self.filesystemLoadID = nil
                    self.filesystemLoadTask = nil
                }
            }
            do {
                for owner in priorOwners { await owner.value }
                try Task.checkCancellation()
                let (cached, cost) = try await self.workScheduler.run(.historyRead) { _ in
                    let cached = try EngineResultStore.load(evidenceID: evidenceID, in: caseURL)
                    return (cached, try cached.map { try FilesystemListingStringCost.measure($0) })
                }
                try Task.checkCancellation()
                guard self.filesystemLoadID == loadID,
                      self.currentCase?.manifest.id == caseID,
                      self.currentCase?.bundleURL == caseURL,
                      self.selectedEvidenceID == evidenceID else { return }
                if let cached {
                    guard cached.sourcePaths.first == sourcePath else {
                        self.errorMessage = "The saved read order does not start with this evidence record. Reanalyze with the recorded image first."
                        return
                    }
                    guard let cost, self.retainFilesystemResult(cached, evidenceID: evidenceID, cost: cost) else {
                        throw EngineError.limitExceeded("The saved listing exceeds the in-memory retention budget. Its disk artifact was preserved.")
                    }
                    self.applyFilesystemOptions(cached)
                    self.rebuildFilesystemIndex()
                    self.refreshFilesystemRows()
                }
            } catch is CancellationError {
                // Selection changes discard this read without altering the new selection.
            } catch {
                guard self.filesystemLoadID == loadID,
                      self.currentCase?.manifest.id == caseID,
                      self.selectedEvidenceID == evidenceID else { return }
                self.errorMessage = "The saved filesystem result could not be read: \(error.localizedDescription) The cache was preserved. Reanalyze the source to create a validated replacement."
            }
        }
        if let task = filesystemLoadTask { filesystemLoadJobs[loadID] = task }
    }

    func analyzeSelectedImage() {
        guard canAnalyzeFilesystem,
              let evidence = selectedEvidence,
              let forensicCase = currentCase else { return }
        guard ensureEngineAvailable() else { return }
        let jobID = beginEngineJob(label: "Verifying source before analysis…")
        let startedAt = Date()
        let options = engineOptions
        let sources = [URL(fileURLWithPath: evidence.sourcePath)] + additionalImageSegments
        section = .filesystem
        engineTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finishEngineJob(jobID) }
            var cacheWasSaved = false
            var permit: ForensicWorkPermit?
            do {
                self.engineOperationLabel = "Waiting for the application workflow slot…"
                let admitted = try await self.workScheduler.acquire(.filesystemAnalysis)
                permit = admitted
                try Task.checkCancellation()
                let helperURL = self.engineHelperURL
                let helperSHA: String?
                if forensicCase.manifest.schemaVersion == 2 {
                    helperSHA = try await admitted.run { try await ImageInspector.inspect(url: helperURL, progress: { _ in }).sha256 }
                } else { helperSHA = nil }
                try await admitted.run { try await self.verifySource(evidence, jobID: jobID) }
                self.engineOperationLabel = "Reading filesystem…"
                let client = self.engineClient, callback = self.engineProgressCallback(jobID)
                let result = try await admitted.run {
                    try await client.enumerate(imagePaths: sources, options: options, progress: callback)
                }
                try Task.checkCancellation()
                self.engineOperationLabel = "Verifying source after analysis…"
                try await admitted.run { try await self.verifySource(evidence, jobID: jobID) }
                try Task.checkCancellation()
                self.engineOperationLabel = "Saving filesystem result…"
                self.engineProgress = nil
                self.verificationProgress = nil
                let evidenceID = evidence.id
                let caseURL = forensicCase.bundleURL
                if let helperSHA {
                    guard try await admitted.run({ try await ImageInspector.inspect(url: helperURL, progress: { _ in }).sha256 }) == helperSHA else {
                        throw ForensicsError.sourceChanged
                    }
                }
                let cost = try await admitted.run { try FilesystemListingStringCost.measure(result) }
                let updatedCase = try await admitted.runToCompletion {
                    if forensicCase.manifest.schemaVersion == 2 {
                        return try EngineResultStore.saveWithJobProvenance(result: result, evidenceID: evidenceID,
                            in: caseURL, jobID: jobID, startedAt: startedAt, executableSHA256: helperSHA).forensicCase
                    }
                    try EngineResultStore.save(result: result, evidenceID: evidenceID, in: caseURL)
                    return forensicCase
                }
                cacheWasSaved = true
                if self.currentCase?.manifest == forensicCase.manifest,
                   self.currentCase?.bundleURL == updatedCase.bundleURL {
                    self.currentCase = updatedCase
                    self.caseIntegrity.configure(forensicCase: updatedCase)
                }
                guard self.retainFilesystemResult(result, evidenceID: evidence.id, cost: cost) else {
                    throw EngineError.limitExceeded("The analysis was saved but exceeds the in-memory retention budget. Its disk artifact was preserved.")
                }
                self.selectedFileID = nil
                self.rebuildFilesystemIndex()
                self.refreshFilesystemRows()
                self.showInspector = true
                try Task.checkCancellation()
                switch result.status {
                case .completed:
                    self.statusMessage = "Filesystem analysis saved: \(result.files.count) entries. Source SHA-256 matches the evidence record."
                case .partial:
                    self.statusMessage = "Partial filesystem result saved: \(result.files.count) entries. Review the warnings before using these results."
                case .failed:
                    self.statusMessage = "Filesystem analysis failed. Review the result warnings."
                case .cancelled:
                    self.statusMessage = "Filesystem analysis cancelled."
                }
            } catch is CancellationError {
                self.statusMessage = cacheWasSaved
                    ? "The analysis result was saved before cancellation completed."
                    : "Filesystem analysis cancelled. No new result was saved."
            } catch {
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Filesystem analysis failed. Reopen the case to check its saved results before retrying."
            }
            if let permit { await permit.release() }
        }
    }

    func selectAndAnalyzeEvidence(_ evidenceID: UUID) {
        guard !isBusy, let caseID = currentCase?.manifest.id else { return }
        selectedEvidenceID = evidenceID
        refreshFilesystemSelection()
        let loading = filesystemLoadTask
        Task { [weak self] in
            await loading?.value
            guard let self, self.selectedEvidenceID == evidenceID,
                  self.currentCase?.manifest.id == caseID else { return }
            self.analyzeSelectedImage()
        }
    }

    func chooseExtractionDestination() {
        if canDecryptSelectedEFSFile { showEFSKeyInput(); return }
        guard canExtractFilesystemFile,
              let evidence = selectedEvidence,
              let file = selectedFilesystemFile,
              let forensicCase = currentCase else { return }
        guard ensureEngineAvailable() else { return }
        var options = selectedFilesystemResult?.options ?? engineOptions
        // Exact hashes of every cached input protect extraction integrity. Avoid
        // recomputing the decompressed logical-image hash for each file export.
        options.hashLogicalImage = false
        let sourceHashes = selectedFilesystemResult?.sourceFileHashes ?? [:]
        let sourcePaths = selectedFilesystemResult?.sourcePaths.map { URL(fileURLWithPath: $0) }
            ?? [URL(fileURLWithPath: evidence.sourcePath)]
        isPresentingPanel = true
        Task { [weak self] in
            guard let self else { return }
            guard !self.isClosing else {
                self.isPresentingPanel = false
                return
            }
            let destination = await CasePanelService.newExtractedFile(named: file.name)
            self.isPresentingPanel = false
            guard let destination, !self.isClosing else { return }
            guard self.currentCase?.manifest.id == forensicCase.manifest.id,
                  self.currentCase?.bundleURL == forensicCase.bundleURL,
                  self.selectedEvidenceID == evidence.id,
                  self.selectedFileID == file.id else {
                self.errorMessage = "The case or file selection changed while choosing an output path. Select the file again before extraction."
                return
            }
            // Use the options that produced this file, including its evidence timezone.
            self.extract(file: file, evidence: evidence, to: destination, options: options, sourcePaths: sourcePaths, sourceHashes: sourceHashes)
        }
    }

    func cancelEngineJob() {
        guard isEngineRunning else { return }
        engineOperationLabel = "Cancelling native engine job…"
        engineTask?.cancel()
    }

    func chooseAdditionalImageSegments() {
        guard !isBusy, !isLoadingFilesystem, let evidence = selectedEvidence,
              let forensicCase = currentCase else { return }
        isPresentingPanel = true
        Task { [weak self] in
            guard let self else { return }
            defer { self.isPresentingPanel = false }
            guard !self.isClosing else { return }
            guard let selected = await CasePanelService.additionalImageSegments(),
                  !self.isClosing,
                  self.selectedEvidenceID == evidence.id,
                  self.currentCase?.manifest.id == forensicCase.manifest.id,
                  self.currentCase?.bundleURL == forensicCase.bundleURL else { return }
            let existing = Set(([URL(fileURLWithPath: evidence.sourcePath)] + self.additionalImageSegments)
                .map { $0.standardizedFileURL.resolvingSymlinksInPath().path })
            var addedPaths = existing
            let ordered = selected.sorted {
                let comparison = $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent)
                return comparison == .orderedSame ? $0.path < $1.path : comparison == .orderedAscending
            }
            var additions: [URL] = []
            for url in ordered {
                let canonical = url.standardizedFileURL.resolvingSymlinksInPath()
                if addedPaths.insert(canonical.path).inserted {
                    additions.append(canonical)
                }
            }
            guard addedPaths.count <= 1024 else {
                self.errorMessage = "An image can contain at most 1,024 explicitly selected files, including its recorded first file."
                return
            }
            self.additionalImageSegments.append(contentsOf: additions)
        }
    }

    func moveImageSegment(at index: Int, by delta: Int) {
        guard !isBusy,
              additionalImageSegments.indices.contains(index),
              additionalImageSegments.indices.contains(index + delta) else { return }
        additionalImageSegments.swapAt(index, index + delta)
    }

    func removeImageSegment(at index: Int) {
        guard !isBusy, additionalImageSegments.indices.contains(index) else { return }
        additionalImageSegments.remove(at: index)
    }

    func cancelCurrentJob() {
        efsKeyInput?.cancel()
        filesystemDocumentPreview.cancel()
        filesystemBatchExport.cancel()
        filesystemBatchPanelTask?.cancel()
        optical.cancel()
        apfs.cancel()
        recovery.cancel()
        assistant.cancel()
        contentPreview.cancel()
        caseWork.cancelPendingWork()
        comparisonSelection.cancel()
        comparisonAssistant.cancel()
        contentIndex.cancel()
        timeline.cancel()
        caseIntegrity.cancelPendingWork()
        derivedNavigationTask?.cancel()
        if isFilteringFilesystem {
            filesystemSearchText = ""
            filesystemCategory = .all
        } else {
            cancelFilesystemSearch()
        }
        cancelFilesystemLoad()
        if isEngineRunning { cancelEngineJob() }
        else { cancelInspection() }
    }

    private func cancelFilesystemLoad() {
        filesystemLoadTask?.cancel()
        for task in filesystemLoadJobs.values { task.cancel() }
        filesystemLoadTask = nil
        filesystemLoadID = nil
        isLoadingFilesystem = false
    }

    private func applyFilesystemOptions(_ result: EnumerationResult) {
        engineImageType = result.options.imageType
        engineSectorSize = result.options.sectorSize
        engineMaxFiles = result.options.maxFiles
        engineMaxFilesText = String(result.options.maxFiles)
        evidenceTimezone = result.options.timezone
        additionalImageSegments = result.sourcePaths.dropFirst().map { URL(fileURLWithPath: $0) }
    }

    private var engineClient: EngineClient {
        EngineClient(helperURL: engineHelperURL)
    }

    private func ensureEngineAvailable() -> Bool {
        guard let issue = EngineAvailability.issue(for: engineHelperURL) else { return true }
        errorMessage = issue
        statusMessage = "Native engine unavailable. The evidence and saved results were preserved."
        return false
    }

    private func rebuildFilesystemIndex() {
        cancelFilesystemSearch()
        let files = selectedFilesystemResult?.files ?? []
        filesystemSearchIndex = FilesystemSearchIndex(files: files)
        var byID: [String: FilesystemEntry] = [:]
        byID.reserveCapacity(files.count)
        for file in files where byID[file.id] == nil {
            byID[file.id] = file
        }
        filesystemFilesByID = byID
        refreshSelectedFileWork()
        comparisonSelection.configure(result: selectedFilesystemResult)
        refreshDerivedWorkspaces()
    }

    private func extract(file: FilesystemEntry, evidence: EvidenceRecord, to destination: URL, options: EngineOptions, sourcePaths: [URL], sourceHashes: [String: String]) {
        guard !isBusy, let forensicCase = currentCase, let recordedAnalysis = selectedFilesystemResult,
              recordedAnalysis.files.first(where: { $0.id == file.id }) == file else { return }
        let jobID = beginEngineJob(label: "Verifying source before extraction…")
        engineTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finishEngineJob(jobID) }
            var permit: ForensicWorkPermit?
            do {
                self.engineOperationLabel = "Waiting for the application workflow slot…"
                let admitted = try await self.workScheduler.acquire(.extraction)
                permit = admitted
                try await admitted.run { try await self.verifySource(evidence, jobID: jobID) }
                self.engineOperationLabel = "Extracting \(file.name)…"
                let client = self.engineClient, callback = self.engineProgressCallback(jobID)
                let receipt = try await admitted.run {
                    try await client.extract(imagePaths: sourcePaths, file: file, outputURL: destination,
                        options: options, expectedSourceHashes: sourceHashes, progress: callback)
                }
                self.extractionReceipt = receipt
                self.engineOperationLabel = "Verifying source after extraction…"
                try await admitted.run { try await self.verifySource(evidence, jobID: jobID) }
                try Task.checkCancellation()
                self.extractionReceiptIsVerified = true
                self.caseWork.recordExtraction(receipt: receipt, forensicCase: forensicCase,
                    evidence: evidence, result: recordedAnalysis, file: file)
                self.statusMessage = "Extracted \(EvidenceFormatting.bytes(receipt.byteCount)) to a new file. Source SHA-256 matches the evidence record."
            } catch is CancellationError {
                self.statusMessage = self.extractionReceipt == nil
                    ? "Extraction cancelled."
                    : "Post-extraction source verification cancelled. The output receipt remains unverified."
            } catch {
                self.errorMessage = error.localizedDescription
                self.statusMessage = self.extractionReceipt == nil
                    ? "Extraction failed."
                    : "Post-extraction source verification failed. The output receipt remains unverified."
            }
            if let permit { await permit.release() }
        }
    }

    private func beginEngineJob(label: String) -> UUID {
        let jobID = UUID()
        engineJobID = jobID
        isEngineRunning = true
        engineOperationLabel = label
        engineProgress = nil
        verificationProgress = nil
        extractionReceipt = nil
        extractionReceiptIsVerified = false
        return jobID
    }

    private func finishEngineJob(_ jobID: UUID) {
        guard engineJobID == jobID else { return }
        isEngineRunning = false
        engineProgress = nil
        verificationProgress = nil
        engineTask = nil
        engineJobID = nil
    }

    private func verifySource(_ evidence: EvidenceRecord, jobID: UUID) async throws {
        engineProgress = nil
        verificationProgress = nil
        let inspected = try await ImageInspector.inspect(url: URL(fileURLWithPath: evidence.sourcePath)) { [weak self] update in
            Task { @MainActor [weak self] in
                guard let self, self.engineJobID == jobID, self.isEngineRunning else { return }
                self.verificationProgress = update
            }
        }
        verificationProgress = nil
        guard inspected.sha256 == evidence.sha256, inspected.byteCount == evidence.byteCount else {
            throw ForensicsError.sourceChanged
        }
    }

    private func engineProgressCallback(_ jobID: UUID) -> @Sendable (EngineProgress) -> Void {
        { [weak self] update in
            Task { @MainActor [weak self] in
                guard let self, self.engineJobID == jobID, self.isEngineRunning else { return }
                self.engineProgress = update
            }
        }
    }
}
