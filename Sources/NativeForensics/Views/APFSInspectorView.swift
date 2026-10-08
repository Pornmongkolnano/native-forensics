import ForensicsCore
import SwiftUI

struct APFSInspectorView: View {
    let store: APFSWorkspaceStore
    @State private var pane: Pane = .properties
    @State private var usesContainerCredential = false
    @State private var usesVolumeCredential = false
    @State private var containerCredential = ""
    @State private var volumeCredential = ""
    @State private var exportPanelTask: Task<Void, Never>?
    @State private var exportPanelID: UUID?
    @State private var admissionTask: Task<Void, Never>?
    @State private var admissionID: UUID?
    @State private var admissionMessage: String?

    private enum AdmittedFileAction {
        case preview
        case export(URL)
    }

    private enum Pane: String, CaseIterable {
        case properties = "Properties"
        case preview = "Preview"
        case provenance = "Provenance"
    }

    private var matchingAnalysis: DocumentAnalysis? {
        guard let entry = store.selectedEntry, let hash = entry.sha256,
              let analysis = store.analysis, analysis.sourceSHA256 == hash,
              analysis.sourceByteCount == entry.byteCount else { return nil }
        return analysis
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: store.selectedEntry.map { APFSViewFormatting.icon($0.kind) } ?? "externaldrive")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.selectedEntry.map(APFSViewFormatting.filename) ?? "APFS Inspector")
                            .font(.headline)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Text("Experimental allocated file view")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Picker("APFS inspector information", selection: $pane) {
                    ForEach(Pane.allCases, id: \.self) { pane in
                        Text(pane.rawValue).tag(pane)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityLabel("APFS inspector information")
            }
            .padding(16)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    if let warning = store.cleanupWarning {
                        Label(warning, systemImage: "externaldrive.badge.exclamationmark")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Reload Saved Result", action: store.refresh)
                            .disabled(!store.hasSource || store.hasActiveWork || admissionID != nil || exportPanelID != nil)
                    }
                    if pane == .provenance {
                        if let result = store.result {
                            APFSProvenanceView(result: result, isHistorical: store.isHistorical)
                        } else {
                            Text("APFS inspection receipts record the allocated view, source hash and volume identity of a supported disk image.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    } else if let entry = store.selectedEntry {
                        if pane == .properties {
                            APFSEntryPropertiesView(entry: entry, snapshot: store.result?.selectedSnapshot,
                                copyHash: store.copySelectedHash)
                        } else {
                            preview
                        }
                        if entry.kind == .regular {
                            fileActions
                        } else {
                            Text("Directories and links are recorded as metadata. File preview and export require a completely verified regular-file entry.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } else {
                        Text("Select an APFS entry to inspect its path, recorded metadata and supported file content.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onDisappear {
            cancelExportPanel()
            cancelAdmission()
            clearCredentials()
        }
        .onChange(of: store.selectedEntryPath) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
            pane = .properties
        }
        .onChange(of: store.selectedSourceFilename) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
        }
        .onChange(of: store.selectedEvidenceID) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
        }
        .onChange(of: store.selectedCaseID) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
        }
        .onChange(of: store.result?.evidenceID) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
            pane = .properties
        }
        .onChange(of: store.jobBindingID) { _, _ in
            cancelExportPanel()
            cancelAdmission()
            admissionMessage = nil
            clearCredentials()
        }
        .onChange(of: store.state) { _, state in
            if state != .idle {
                cancelExportPanel()
                cancelAdmission()
                admissionMessage = nil
                clearCredentials()
            }
        }
        .onChange(of: store.errorMessage) { _, error in
            if error != nil { clearCredentials() }
        }
        .onChange(of: store.cleanupWarning) { _, warning in
            if warning != nil {
                cancelExportPanel()
                cancelAdmission()
                admissionMessage = nil
                clearCredentials()
            }
        }
        .onChange(of: store.analysis?.sourceSHA256) { _, hash in
            if hash != nil, matchingAnalysis != nil { pane = .preview }
        }
    }

    private var preview: some View {
        @Bindable var store = store
        return VStack(alignment: .leading, spacing: 12) {
            Label("Verified Local Preview", systemImage: "doc.text.viewfinder")
                .font(.headline)
            Text("Main data-fork bytes from the recorded current or selected snapshot view are checked against the APFS file hash before the local preview decoder reads them. Content decoding is a separate check from the allocated-view metadata.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let analysis = matchingAnalysis {
                DecodedDocumentContentView(analysis: analysis, contentQuery: $store.contentQuery,
                    searchOutcome: store.searchOutcome)
            } else if store.state != .previewing {
                Text("Verify and Preview supports bounded PDF, image, Office, ZIP and text content. A filename extension remains a hint until the file's bytes are inspected.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var fileActions: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            APFSJobCredentialsView(usesContainerCredential: $usesContainerCredential,
                usesVolumeCredential: $usesVolumeCredential, containerCredential: $containerCredential,
                volumeCredential: $volumeCredential)
                .disabled(store.hasActiveWork || store.cleanupUncertain || exportPanelID != nil || admissionID != nil)
            if let message = admissionMessage {
                Label(message, systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button(action: previewSelected) {
                Label(matchingAnalysis == nil ? "Verify and Preview" : "Verify and Reload", systemImage: "doc.text.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .disabled(!store.canPreview || exportPanelID != nil || admissionID != nil)
            Button(action: exportSelected) {
                Label("Export to New File…", systemImage: "square.and.arrow.up")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!store.canExport || exportPanelID != nil || admissionID != nil)
            if let reason = store.documentUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if store.hasActiveWork || exportPanelID != nil || admissionID != nil {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(exportPanelID != nil ? "Choose a new export file."
                        : admissionID != nil ? "Checking the available forensic workflow slot…" : store.statusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                    Button("Cancel") {
                        cancelExportPanel()
                        cancelAdmission()
                        admissionMessage = nil
                        clearCredentials()
                        store.cancel()
                    }
                    .disabled(store.state == .cancelling)
                }
            }
            if let error = store.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let receipt = store.lastExport, receipt.relativePath == store.selectedEntry?.relativePath,
               receipt.volumeUUID == store.result?.volumeUUID,
               receipt.selectedSnapshot == store.result?.selectedSnapshot {
                GroupBox("Verified Export Receipt") {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(store.lastExportDestination?.lastPathComponent ?? receipt.relativePath)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Text("\(EvidenceFormatting.bytes(receipt.byteCount)) · logical APFS main data-fork bytes")
                            .foregroundStyle(.secondary)
                        Text(APFSViewFormatting.selectedView(receipt.selectedSnapshot))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(verbatim: receipt.sha256)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        Text("Fresh source and output hashes matched. The file was created without replacing an existing output.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .controlSize(.small)
    }

    private func previewSelected() {
        guard store.canPreview, admissionID == nil, exportPanelID == nil,
              let entry = store.selectedEntry, let result = store.result else {
            clearCredentials()
            return
        }
        beginAdmission(.preview, bindingID: store.jobBindingID, maximumEntries: store.maximumEntries,
            volumeUUID: store.selectedVolumeUUID, snapshotUUID: store.selectedSnapshotUUID,
            result: result, entry: entry)
    }

    private func exportSelected() {
        guard store.canExport, let entry = store.selectedEntry, let result = store.result,
              let evidenceID = store.selectedEvidenceID, let caseID = store.selectedCaseID,
              exportPanelID == nil, admissionID == nil else {
            clearCredentials()
            return
        }
        let panelID = UUID(), bindingID = store.jobBindingID, maximumEntries = store.maximumEntries
        let volumeUUID = store.selectedVolumeUUID, snapshotUUID = store.selectedSnapshotUUID
        exportPanelID = panelID; admissionMessage = nil
        exportPanelTask = Task { @MainActor in
            defer {
                if exportPanelID == panelID {
                    exportPanelID = nil
                    exportPanelTask = nil
                }
            }
            let chosenDestination = await CasePanelService.newExtractedFile(named: APFSViewFormatting.filename(entry))
            guard exportPanelID == panelID else { return }
            guard let destination = chosenDestination, !Task.isCancelled,
                  store.selectedEntryPath == entry.relativePath,
                  store.selectedEntry == entry,
                  store.jobBindingID == bindingID, store.maximumEntries == maximumEntries,
                  store.selectedVolumeUUID == volumeUUID,
                  store.selectedSnapshotUUID == snapshotUUID,
                  store.selectedEvidenceID == evidenceID, store.selectedCaseID == caseID,
                  store.result?.evidenceID == result.evidenceID,
                  store.result?.containerSHA256 == result.containerSHA256,
                  store.result?.volumeUUID == result.volumeUUID,
                  store.result?.selectedSnapshot == result.selectedSnapshot,
                  store.canExport else {
                clearCredentials()
                return
            }
            beginAdmission(.export(destination), bindingID: bindingID, maximumEntries: maximumEntries,
                volumeUUID: volumeUUID, snapshotUUID: snapshotUUID, result: result, entry: entry)
        }
    }

    private func beginAdmission(_ action: AdmittedFileAction, bindingID: UUID, maximumEntries: Int,
                                volumeUUID: UUID?, snapshotUUID: UUID?, result: APFSInspectionResult, entry: APFSFileEntry) {
        guard admissionID == nil else { return }
        let id = UUID()
        admissionID = id; admissionMessage = nil
        admissionTask = Task { @MainActor in
            defer {
                if admissionID == id { admissionID = nil; admissionTask = nil }
            }
            var permit: ForensicWorkPermit?
            do {
                let admitted = try await store.acquireImmediateAdmission()
                permit = admitted
                try Task.checkCancellation()
                guard admissionID == id, store.jobBindingID == bindingID,
                      store.maximumEntries == maximumEntries, store.result == result,
                      store.selectedVolumeUUID == volumeUUID,
                      store.selectedSnapshotUUID == snapshotUUID,
                      store.selectedEntry == entry, canStart(action) else { throw CancellationError() }
                do {
                    let credentials = try APFSViewCredentialCapture.capture(container: &containerCredential, volume: &volumeCredential,
                        containerEnabled: usesContainerCredential, volumeEnabled: usesVolumeCredential)
                    let started: Bool
                    switch action {
                    case .preview:
                        started = store.previewSelected(passphrase: credentials.container,
                            volumePassphrase: credentials.volume, permit: admitted)
                    case .export(let destination):
                        started = store.exportSelected(to: destination, passphrase: credentials.container,
                            volumePassphrase: credentials.volume, permit: admitted)
                    }
                    if started { permit = nil }
                } catch {
                    store.rejectCredentialCapture()
                }
            } catch is CancellationError {
                // A canceled or superseded action does not capture credentials.
            } catch {
                if admissionID == id, store.jobBindingID == bindingID {
                    admissionMessage = APFSViewAdmissionFormatting.message(error)
                }
            }
            if let permit { await permit.release() }
        }
    }

    private func canStart(_ action: AdmittedFileAction) -> Bool {
        switch action {
        case .preview: store.canPreview
        case .export: store.canExport
        }
    }

    private func cancelAdmission() {
        admissionTask?.cancel()
        admissionTask = nil
        admissionID = nil
    }

    private func cancelExportPanel() {
        exportPanelTask?.cancel()
        exportPanelTask = nil
        exportPanelID = nil
    }

    private func clearCredentials() {
        containerCredential = ""
        volumeCredential = ""
    }
}

private struct APFSEntryPropertiesView: View {
    let entry: APFSFileEntry
    let snapshot: APFSSnapshotInventoryEntry?
    let copyHash: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            APFSInspectorField(label: "Recorded View", value: APFSViewFormatting.selectedView(snapshot))
            APFSInspectorField(label: "Recorded Relative Path", value: entry.relativePath)
            APFSInspectorField(label: "Kind", value: APFSViewFormatting.kind(entry.kind))
            APFSInspectorField(label: "Recorded Size", value: "\(entry.byteCount.formatted()) bytes")
            APFSInspectorField(label: "Inode", value: entry.inode.formatted())
            Text("The path and inode identify an entry in the recorded system view. They do not identify byte offsets in the disk-image container.")
                .font(.caption)
                .foregroundStyle(.secondary)
            APFSInspectorField(label: "Modified · UTC", value: APFSViewFormatting.modified(entry))
            APFSInspectorField(label: "Exact Modification Time", value: "\(entry.modifiedSeconds) seconds + \(entry.modifiedNanoseconds) nanoseconds since the Unix epoch", monospaced: true)
            HStack {
                Text("File SHA-256").font(.headline)
                Spacer(minLength: 8)
                Button(action: copyHash) { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .disabled(entry.sha256 == nil)
                    .help("Copy the verified plaintext file SHA-256")
                    .accessibilityLabel("Copy APFS plaintext file SHA-256")
            }
            APFSInspectorField(label: "Scope · complete plaintext main data-fork bytes",
                value: entry.sha256 ?? "No complete bounded file-byte hash was recorded.", monospaced: entry.sha256 != nil)
            if entry.kind == .regular {
                APFSInspectorField(label: "Filename Extension Hint", value: extensionHint)
                Text("The extension is a filename hint. Preview checks MIME and readable content separately from the file-byte hash.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var extensionHint: String {
        let suffix = (entry.relativePath as NSString).pathExtension
        return suffix.isEmpty ? "Unknown" : suffix.uppercased()
    }
}

private struct APFSProvenanceView: View {
    let result: APFSInspectionResult
    let isHistorical: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            APFSInspectorField(label: "Recorded Profile", value: "Experimental read-only system APFS allocated view")
            APFSInspectorField(label: "Inspection Receipt", value: isHistorical ? "Saved result" : "Completed inspection result")
            APFSInspectorField(label: "Coverage", value: result.coverage == .completeAllocatedView ? "Complete allocated view within the configured limits" : "Partial allocated view; review the warnings")
            APFSInspectorField(label: "Encryption Layers", value: APFSViewFormatting.encryption(result))
            APFSInspectorField(label: "Volume UUID", value: result.volumeUUID.uuidString.lowercased(), monospaced: true)
            if let snapshot = result.selectedSnapshot {
                APFSInspectorField(label: "Selected Snapshot Name", value: snapshot.name)
                APFSInspectorField(label: "Selected Snapshot UUID", value: snapshot.uuid.uuidString.lowercased(), monospaced: true)
                APFSInspectorField(label: "Selected Snapshot Transaction ID", value: snapshot.transactionID.formatted())
            } else {
                APFSInspectorField(label: "Recorded View", value: "Current Volume")
            }
            APFSInspectorField(label: "Source Size", value: "\(result.containerByteCount.formatted()) bytes")
            APFSInspectorField(label: "Source SHA-256 · selected container file bytes", value: result.containerSHA256, monospaced: true)
            Text("The source hash describes the stored disk-image container. Entry hashes describe complete plaintext regular-file main data forks read from the chosen current or snapshot view. These are separate hash scopes; snapshot presence does not establish deleted-file recovery.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("Snapshot Inventory · \(result.snapshots.count.formatted())") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(result.snapshotInventoryAvailable
                        ? result.snapshots.isEmpty
                            ? "This receipt's inventory recorded no snapshots; it does not establish the absence of snapshots at another inspection time."
                            : result.selectedSnapshot == nil
                                ? "Names and identifiers are inventory metadata. This receipt's file hashes cover the current volume; snapshot content was not read."
                                : "Names and identifiers are inventory metadata. This receipt's file hashes cover only the explicit selected snapshot shown above."
                        : "Snapshot inventory was unavailable. An empty list does not establish the absence of snapshots.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(Array(result.snapshots.prefix(100).enumerated()), id: \.offset) { _, snapshot in
                        VStack(alignment: .leading, spacing: 5) {
                            APFSInspectorField(label: "Recorded Name", value: snapshot.name)
                            APFSInspectorField(label: "Snapshot UUID", value: snapshot.uuid.uuidString.lowercased(), monospaced: true)
                            APFSInspectorField(label: "Transaction ID", value: snapshot.transactionID.formatted())
                        }
                    }
                    if result.snapshots.count > 100 {
                        Text("Showing the first 100 snapshot inventory records from this receipt.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 8)
            }
            .font(.caption)
            DisclosureGroup("Inspection Limits") {
                VStack(alignment: .leading, spacing: 8) {
                    APFSInspectorField(label: "Maximum Entries", value: result.options.maximumEntries.formatted())
                    APFSInspectorField(label: "Maximum File Bytes", value: EvidenceFormatting.bytes(result.options.maximumFileBytes))
                    APFSInspectorField(label: "Maximum Total File Bytes", value: EvidenceFormatting.bytes(result.options.maximumAggregateFileBytes))
                    APFSInspectorField(label: "Maximum Depth", value: result.options.maximumDepth.formatted())
                }
                .padding(.top, 8)
            }
            .font(.caption)
            ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct APFSInspectorField: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(verbatim: value)
                .font(monospaced ? .system(.caption2, design: .monospaced) : .callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
