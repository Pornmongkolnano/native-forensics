import Foundation
import ForensicsCore

extension WorkspaceStore {
    var selectedFilesystemResult: EnumerationResult? {
        guard let selectedEvidenceID else { return nil }
        return filesystemResults[selectedEvidenceID]
    }

    var selectedFilesystemFile: FilesystemEntry? {
        guard let selectedFileID else { return nil }
        return filesystemFilesByID[selectedFileID]
    }

    var canAnalyzeFilesystem: Bool {
        selectedEvidence != nil && currentCase != nil && !isBusy && !isLoadingFilesystem
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
    func refreshFilesystemRows() {
        cancelFilesystemSearch()
        let index = filesystemSearchIndex
        let query = filesystemSearchText
        guard !query.isEmpty else {
            filesystemRows = (try? index.rows(matching: "")) ?? []
            return
        }
        let searchID = UUID()
        let evidenceID = selectedEvidenceID
        let caseID = currentCase?.manifest.id
        let caseURL = currentCase?.bundleURL
        filesystemSearchID = searchID
        isFilteringFilesystem = true
        filesystemSearchTask = Task { [weak self] in
            defer {
                if let self, self.filesystemSearchID == searchID {
                    self.isFilteringFilesystem = false
                    self.filesystemSearchID = nil
                    self.filesystemSearchTask = nil
                }
            }
            do {
                try await Task.sleep(for: .milliseconds(120))
                try Task.checkCancellation()
                let worker = Task.detached(priority: .userInitiated) {
                    try index.rows(matching: query)
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
                      self.filesystemSearchText == query else { return }
                self.filesystemRows = rows
                if let selected = self.selectedFileID, !rows.contains(where: { $0.id == selected }) {
                    self.selectedFileID = nil
                }
            } catch {
                // Superseded queries are cancelled; the matching generation's
                // defer releases its activity state without publishing old rows.
            }
        }
    }

    func cancelFilesystemSearch() {
        filesystemSearchID = nil
        filesystemSearchTask?.cancel()
        filesystemSearchTask = nil
        isFilteringFilesystem = false
    }

    func refreshFilesystemSelection() {
        let selectedCaseID = currentCase?.manifest.id
        guard filesystemSelectionID != selectedEvidenceID || filesystemSelectionCaseID != selectedCaseID else { return }
        filesystemSelectionID = selectedEvidenceID
        filesystemSelectionCaseID = selectedCaseID
        cancelFilesystemLoad()
        cancelFilesystemSearch()
        filesystemSearchIndex = FilesystemSearchIndex(files: [])
        selectedFileID = nil
        extractionReceipt = nil
        extractionReceiptIsVerified = false
        filesystemSearchText = ""
        additionalImageSegments = []
        filesystemRows = []
        filesystemFilesByID = [:]
        if let cached = selectedFilesystemResult {
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
        filesystemLoadTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.filesystemLoadID == loadID {
                    self.isLoadingFilesystem = false
                    self.filesystemLoadID = nil
                    self.filesystemLoadTask = nil
                }
            }
            do {
                let cached = try await Task.detached(priority: .utility) {
                    try EngineResultStore.load(evidenceID: evidenceID, in: caseURL)
                }.value
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
                    self.filesystemResults[evidenceID] = cached
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
                self.errorMessage = "The saved filesystem result could not be read: \(error.localizedDescription)"
            }
        }
    }

    func analyzeSelectedImage() {
        guard canAnalyzeFilesystem,
              let evidence = selectedEvidence,
              let forensicCase = currentCase else { return }
        let jobID = beginEngineJob(label: "Verifying source before analysis…")
        let options = engineOptions
        let sources = [URL(fileURLWithPath: evidence.sourcePath)] + additionalImageSegments
        section = .filesystem
        engineTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finishEngineJob(jobID) }
            var cacheWasSaved = false
            do {
                try await self.verifySource(evidence, jobID: jobID)
                self.engineOperationLabel = "Reading filesystem…"
                let result = try await self.engineClient.enumerate(
                    imagePaths: sources,
                    options: options,
                    progress: self.engineProgressCallback(jobID)
                )
                try Task.checkCancellation()
                self.engineOperationLabel = "Verifying source after analysis…"
                try await self.verifySource(evidence, jobID: jobID)
                try Task.checkCancellation()
                self.engineOperationLabel = "Saving filesystem result…"
                self.engineProgress = nil
                self.verificationProgress = nil
                let evidenceID = evidence.id
                let caseURL = forensicCase.bundleURL
                try await Task.detached(priority: .utility) {
                    try EngineResultStore.save(result: result, evidenceID: evidenceID, in: caseURL)
                }.value
                cacheWasSaved = true
                self.filesystemResults[evidence.id] = result
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
                self.statusMessage = "Filesystem analysis failed. No new result was saved."
            }
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
        guard canExtractFilesystemFile,
              let evidence = selectedEvidence,
              let file = selectedFilesystemFile,
              let forensicCase = currentCase else { return }
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
            let destination = await CasePanelService.newExtractedFile(named: file.name)
            self.isPresentingPanel = false
            guard let destination else { return }
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
            guard let selected = await CasePanelService.additionalImageSegments(),
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
        if isFilteringFilesystem {
            filesystemSearchText = ""
        } else {
            cancelFilesystemSearch()
        }
        cancelFilesystemLoad()
        if isEngineRunning { cancelEngineJob() }
        else { cancelInspection() }
    }

    private func cancelFilesystemLoad() {
        filesystemLoadTask?.cancel()
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
        EngineClient(helperURL: Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/NFTSKEngine"))
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
    }

    private func extract(file: FilesystemEntry, evidence: EvidenceRecord, to destination: URL, options: EngineOptions, sourcePaths: [URL], sourceHashes: [String: String]) {
        guard !isBusy else { return }
        let jobID = beginEngineJob(label: "Verifying source before extraction…")
        engineTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finishEngineJob(jobID) }
            do {
                try await self.verifySource(evidence, jobID: jobID)
                self.engineOperationLabel = "Extracting \(file.name)…"
                let receipt = try await self.engineClient.extract(
                    imagePaths: sourcePaths,
                    file: file,
                    outputURL: destination,
                    options: options,
                    expectedSourceHashes: sourceHashes,
                    progress: self.engineProgressCallback(jobID)
                )
                self.extractionReceipt = receipt
                self.engineOperationLabel = "Verifying source after extraction…"
                try await self.verifySource(evidence, jobID: jobID)
                try Task.checkCancellation()
                self.extractionReceiptIsVerified = true
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
