import AppKit
import Foundation
import ForensicsCore

/// The native workbench delegates UDF parsing and atomic export to the same
/// bounded adapter used by the portable Autopsy bundle. It never changes the
/// selected case or substitutes host dates for recorded UDF metadata.
enum OpticalAutopsyExportService {
    static let metadataNotice = "Autopsy imports these derived files as Logical Files. Original UDF timestamps and deletion flags remain in Reports; leave Autopsy's host timestamp options off. Keep the export folder in the same location after import."

    @MainActor
    static func chooseDestination() async -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Export UDF Files for Autopsy"
        panel.prompt = "Choose Export Parent"
        panel.message = "Choose a parent folder outside the evidence source and case. A new unique folder will contain all current and historical files, verified hashes, and Reports. \(metadataNotice)"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        NSApp.activate(ignoringOtherApps: true)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let completion: (NSApplication.ModalResponse) -> Void = { response in
                    let parent = response == .OK ? panel.url : nil
                    continuation.resume(returning: parent.map {
                        $0.appendingPathComponent("UDF-for-Autopsy-\(UUID().uuidString.lowercased())", isDirectory: true)
                    })
                }
                let window = NSApp.orderedWindows.first {
                    $0.isVisible && !$0.isMiniaturized && !($0 is NSPanel)
                        && $0.sheetParent == nil && $0.attachedSheet == nil
                }
                if let window { panel.beginSheetModal(for: window, completionHandler: completion) }
                else { panel.begin(completionHandler: completion) }
            }
        } onCancel: {
            // Cancel this operation's panel only. Its completion drains the
            // workspace owner during a source change or application shutdown.
            Task { @MainActor in panel.cancel(nil) }
        }
    }

    static func export(evidence: EvidenceRecord, result: UDFInspectionResult,
        in forensicCase: ForensicCase, to destination: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void) async throws -> UDFLogicalFilesExport {
        try validateDestination(destination, evidence: evidence, forensicCase: forensicCase)
        guard forensicCase.manifest.evidence.contains(evidence), result.caseID == forensicCase.manifest.id,
              result.sourceEvidenceID == evidence.id, result.sourceSHA256 == evidence.sha256,
              result.sourceByteCount == evidence.byteCount,
              try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result else {
            throw UDFError.invalidResult("The selected UDF receipt is no longer the latest job for this case and source. Reload it before exporting.")
        }
        let receipt = try await UDFLogicalFilesExporter.export(evidence: evidence, to: destination, progress: progress)
        try validateReceipt(receipt, result: result, destination: destination)
        return receipt
    }

    static func validateDestination(_ destination: URL, evidence: EvidenceRecord, forensicCase: ForensicCase) throws {
        guard destination.isFileURL, destination.host == nil || destination.host == "" || destination.host == "localhost",
              !destination.path.utf8.contains(0), !destination.lastPathComponent.isEmpty,
              destination.path != "/" else { throw ForensicsError.invalidFileURL }
        let target = destination.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath()
            .appendingPathComponent(destination.lastPathComponent, isDirectory: true)
        let source = URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL.resolvingSymlinksInPath()
        let caseURL = forensicCase.bundleURL.standardizedFileURL.resolvingSymlinksInPath()
        guard target.path != source.path, !source.path.hasPrefix(target.path + "/"),
              target.path != caseURL.path, !target.path.hasPrefix(caseURL.path + "/"),
              !target.deletingLastPathComponent().pathComponents.contains(where: { $0.lowercased().hasSuffix(".nativecase") }) else {
            throw UDFError.invalidResult("Choose a new export folder outside the evidence source and every forensic case.")
        }
        guard !FileManager.default.fileExists(atPath: target.path),
              (try? FileManager.default.destinationOfSymbolicLink(atPath: target.path)) == nil else {
            throw UDFError.invalidResult("This output path already exists. Choose a new folder; previous exports cannot be replaced.")
        }
    }

    static func validateReceipt(_ receipt: UDFLogicalFilesExport, result: UDFInspectionResult, destination: URL) throws {
        let target = destination.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath()
            .appendingPathComponent(destination.lastPathComponent).path
        guard receipt.schemaVersion == 1, receipt.status == "completed", receipt.destinationPath == target,
              receipt.sourceSHA256 == result.sourceSHA256, receipt.sourceByteCount == result.sourceByteCount,
              receipt.parserVersion == result.parserVersion, receipt.profile == result.profile,
              receipt.entries.count == result.entries.count,
              Set(result.entries.map(\.id)).count == result.entries.count,
              Set(receipt.entries.map(\.entryID)).count == receipt.entries.count,
              Set(receipt.entries.map(\.outputRelativePath)).count == receipt.entries.count else {
            throw UDFError.invalidResult("The completed Autopsy export does not match the selected source and full UDF inventory.")
        }
        let expected = Dictionary(uniqueKeysWithValues: result.entries.map { ($0.id, $0) })
        for record in receipt.entries {
            let path = record.outputRelativePath
            guard let entry = expected[record.entryID], record.originalPath == entry.originalPath,
                  record.state == entry.state, record.byteCount == entry.byteCount, record.sha256 == entry.sha256,
                  Set(record.snapshotIDs) == Set(entry.snapshotIDs), path.hasPrefix("LogicalFiles/"),
                  !path.hasPrefix("/"), !path.utf8.contains(0),
                  !path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
                throw UDFError.invalidResult("An exported payload path, byte hash or historical state differs from the selected UDF inventory.")
            }
        }
        // The adapter has its own report case/job IDs. They deliberately do not
        // replace the workbench's original case and inspection identities.
    }
}
